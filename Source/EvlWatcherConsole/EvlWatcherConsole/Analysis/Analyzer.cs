using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>
    /// Reads each needed log once (in full for logs a rule watches, by event ID otherwise) and runs the three check
    /// groups. Pure apart from the <see cref="IEventSource"/>.
    /// </summary>
    public sealed class Analyzer
    {
        #region private members

        private const string SecurityLog = "Security";
        private const string SystemLog = "System";
        private const string ApplicationLog = "Application";
        private const string RdpCoreLog = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

        private readonly IEventSource _source;

        #endregion

        #region constructor

        public Analyzer(IEventSource source)
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
        }

        #endregion

        #region public operations

        public AnalysisResult Analyze(AnalyzerInput input, IProgress<string> progress, CancellationToken ct)
        {
            Stopwatch watch = Stopwatch.StartNew();
            var result = new AnalysisResult();
            var eventsByLog = new Dictionary<string, IList<AnalyzedEvent>>(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, HashSet<int>> plan in BuildLogPlan(input))
            {
                ct.ThrowIfCancellationRequested();
                string log = plan.Key;

                if (!_source.LogExists(log))
                {
                    result.LogsMissing.Add(log);
                    continue;
                }

                progress?.Report($"Reading {ShortName(log)} log…");
                try
                {
                    var events = new List<AnalyzedEvent>();
                    foreach (AnalyzedEvent ev in _source.Read(log, plan.Value?.ToList(), input.FromUtc, ct))
                    {
                        events.Add(ev);
                        if (events.Count % 5000 == 0)
                            progress?.Report($"Reading {ShortName(log)} log… {events.Count:N0} events");
                    }
                    eventsByLog[log] = events;
                    result.LogsChecked.Add(log);
                    result.EventsRead += events.Count;
                }
                catch (UnauthorizedAccessException)
                {
                    result.LogsUnreadable.Add(log);
                }
                catch (EventLogException)
                {
                    result.LogsUnreadable.Add(log);
                }
            }

            ct.ThrowIfCancellationRequested();
            progress?.Report("Checking for risks…");

            var findings = new List<Finding>();
            if (input.Rules == null)
                result.Notice = "The EvlWatcher service isn't responding, so attacks couldn't be checked against your rules.";
            findings.AddRange(AttackChecks.Run(eventsByLog, input));
            findings.AddRange(SecurityChecks.Run(eventsByLog, input));
            findings.AddRange(HealthChecks.Run(eventsByLog, input));

            result.Findings = findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.LastSeenUtc).ToList();
            result.BanAllAction = AttackChecks.BuildBanAll(result.Findings);
            result.Duration = watch.Elapsed;
            return result;
        }

        #endregion

        #region private operations

        /// <summary>Log name → event IDs to read; null means "all events" (a rule watches that log).</summary>
        private static List<KeyValuePair<string, HashSet<int>>> BuildLogPlan(AnalyzerInput input)
        {
            var plan = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
            var order = new List<string>();

            void Want(string log, IEnumerable<int> ids)
            {
                log = log.Trim();
                if (log.Length == 0)
                    return;
                if (!plan.TryGetValue(log, out HashSet<int> existing))
                {
                    plan[log] = ids == null ? null : new HashSet<int>(ids);
                    order.Add(log);
                }
                else if (existing != null)
                {
                    if (ids == null)
                        plan[log] = null;
                    else
                        existing.UnionWith(ids);
                }
            }

            if (input.Rules != null)
            {
                foreach (GenericIPBlockingTaskDTO rule in input.Rules.Where(r => r.Active))
                    foreach (string log in rule.EventPath ?? new List<string>())
                        Want(log, null);
            }

            Want(SecurityLog, SecurityChecks.SecurityEventIds.Concat(HealthChecks.SecurityEventIds));
            Want(SystemLog, SecurityChecks.SystemEventIds.Concat(HealthChecks.SystemEventIds));
            Want(ApplicationLog, HealthChecks.ApplicationEventIds);
            Want(RdpCoreLog, new[] { 131 });

            return order.Select(log => new KeyValuePair<string, HashSet<int>>(log, plan[log])).ToList();
        }

        private static string ShortName(string log)
        {
            int slash = log.LastIndexOf('/');
            string name = slash > 0 ? log.Substring(0, slash) : log;
            return name.StartsWith("Microsoft-Windows-", StringComparison.Ordinal) ? name.Substring("Microsoft-Windows-".Length) : name;
        }

        #endregion
    }
}
