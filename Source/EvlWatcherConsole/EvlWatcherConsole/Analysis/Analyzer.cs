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
            var hits = new List<RuleHit>();
            List<RuleMatcher> matchers = (input.Rules ?? new List<GenericIPBlockingTaskDTO>()).Where(r => r.Active).Select(r => new RuleMatcher(r)).ToList();
            input.SecurityLogRead = false;
            input.SecurityOldestUtc = null;

            foreach (KeyValuePair<string, HashSet<int>> plan in BuildLogPlan(input))
            {
                ct.ThrowIfCancellationRequested();
                string log = plan.Key;

                if (!_source.LogExists(log))
                {
                    result.LogsMissing.Add(log);
                    continue;
                }

                // A rule's log is read in full, but only rule hits and the IDs the other checks need stay in memory.
                List<RuleMatcher> logMatchers = matchers.Where(m => AttackChecks.Logs(m.Rule).Contains(log, StringComparer.OrdinalIgnoreCase)).ToList();
                HashSet<int> keepIds = FixedIds(log);
                bool isSecurity = string.Equals(log, SecurityLog, StringComparison.OrdinalIgnoreCase);

                progress?.Report($"Reading {ShortName(log)} log…");
                try
                {
                    var events = new List<AnalyzedEvent>();
                    int read = 0;
                    DateTime? oldest = null;
                    foreach (AnalyzedEvent ev in _source.Read(log, plan.Value?.ToList(), input.FromUtc, ct))
                    {
                        read++;
                        if (isSecurity && (!oldest.HasValue || ev.TimeUtc < oldest.Value))
                            oldest = ev.TimeUtc;
                        foreach (RuleMatcher matcher in logMatchers)
                        {
                            System.Net.IPAddress ip = matcher.Match(ev.Xml);
                            if (ip != null)
                                hits.Add(new RuleHit(matcher.Rule.TaskName, ip, ev.TimeUtc));
                        }
                        if (keepIds.Contains(ev.EventId))
                        {
                            ev.DropXml();
                            events.Add(ev);
                        }
                        if (read % 5000 == 0)
                            progress?.Report($"Reading {ShortName(log)} log… {read:N0} events");
                    }
                    eventsByLog[log] = events;
                    result.LogsChecked.Add(log);
                    result.EventsRead += read;
                    result.EventsKept += events.Count;
                    if (isSecurity)
                    {
                        input.SecurityLogRead = true;
                        input.SecurityOldestUtc = oldest;
                    }
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
            findings.AddRange(AttackChecks.Run(hits, eventsByLog, input, ct));
            findings.AddRange(SecurityChecks.Run(eventsByLog, input, ct));
            findings.AddRange(HealthChecks.Run(eventsByLog, input, ct));
            ct.ThrowIfCancellationRequested();

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

        /// <summary>The event IDs the security and health checks need from a log (the rest of a rule log is not kept).</summary>
        private static HashSet<int> FixedIds(string log)
        {
            if (string.Equals(log, SecurityLog, StringComparison.OrdinalIgnoreCase))
                return new HashSet<int>(SecurityChecks.SecurityEventIds.Concat(HealthChecks.SecurityEventIds));
            if (string.Equals(log, SystemLog, StringComparison.OrdinalIgnoreCase))
                return new HashSet<int>(SecurityChecks.SystemEventIds.Concat(HealthChecks.SystemEventIds));
            if (string.Equals(log, ApplicationLog, StringComparison.OrdinalIgnoreCase))
                return new HashSet<int>(HealthChecks.ApplicationEventIds);
            if (string.Equals(log, RdpCoreLog, StringComparison.OrdinalIgnoreCase))
                return new HashSet<int> { 131 };
            return new HashSet<int>();
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
