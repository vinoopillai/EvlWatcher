using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>
    /// Group 1: attacks by IP. Events are matched to rules the way the service does it (RuleBuilder.Match), so the
    /// analyzer sees exactly the attempts a rule counts.
    /// </summary>
    public static class AttackChecks
    {
        #region private members

        private const string RdpCoreProvider = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";
        private const string SecurityAuditing = "Microsoft-Windows-Security-Auditing";

        #endregion

        #region public operations

        public static IList<Finding> Run(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input)
        {
            var findings = new List<Finding>();
            if (input.Rules != null)
            {
                foreach (GenericIPBlockingTaskDTO rule in input.Rules.Where(r => r.Active && r.TriggerCount > 0))
                    findings.AddRange(CheckRule(rule, eventsByLog, input));
            }
            findings.AddRange(CheckRdpFlood(eventsByLog, input));
            return findings;
        }

        /// <summary>One action banning every address of the Warning attack findings; null when there is none.</summary>
        public static FindingAction BuildBanAll(IEnumerable<Finding> findings)
        {
            List<string> addresses = findings
                .Where(f => f.Category == FindingCategory.Attack && f.Severity >= FindingSeverity.Warning)
                .SelectMany(f => f.Actions.Where(a => a.Kind == FindingActionKind.BanPermanently).SelectMany(a => a.Addresses))
                .Distinct()
                .ToList();
            if (addresses.Count == 0)
                return null;

            return new FindingAction
            {
                Kind = FindingActionKind.BanAll,
                Addresses = addresses,
                Label = $"Ban all {addresses.Count} unbanned attackers",
                ConfirmationText = $"Add these {addresses.Count} addresses to the permanent ban list?\n\n" + string.Join("\n", addresses) +
                                   "\n\nPermanent bans are never lifted automatically. You can remove them on the Bans & Whitelist tab."
            };
        }

        #endregion

        #region rule checks

        private static IEnumerable<Finding> CheckRule(GenericIPBlockingTaskDTO rule, IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input)
        {
            var attempts = new Dictionary<string, List<DateTime>>();
            foreach (string log in (rule.EventPath ?? new List<string>()).Select(p => p.Trim()).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!TryGetLog(eventsByLog, log, out IList<AnalyzedEvent> events))
                    continue;
                foreach (AnalyzedEvent ev in events)
                {
                    IPAddress ip = RuleBuilder.Match(rule, ev.Xml);
                    if (ip == null || !IsBannable(ip, input))
                        continue;
                    string key = ip.ToString();
                    if (!attempts.TryGetValue(key, out List<DateTime> times))
                        attempts[key] = times = new List<DateTime>();
                    times.Add(ev.TimeUtc);
                }
            }

            int window = Math.Max(1, rule.EventAge);
            var evading = new List<(string ip, List<DateTime> times, TimeSpan needed)>();
            var heavy = new List<(string ip, List<DateTime> times)>();

            foreach (KeyValuePair<string, List<DateTime>> kvp in attempts)
            {
                if (IsBanned(kvp.Key, input))
                    continue;
                List<DateTime> times = kvp.Value.OrderBy(t => t).ToList();
                if (times.Count >= rule.TriggerCount && MaxInWindow(times, TimeSpan.FromSeconds(window)) < rule.TriggerCount)
                    evading.Add((kvp.Key, times, NeededSpan(times, rule.TriggerCount)));
                else if (times.Count >= AnalyzerThresholds.HeavyAttackerAttempts)
                    heavy.Add((kvp.Key, times));
            }

            FindingAction widen = BuildWiden(rule, evading.Select(e => e.needed).ToList());

            foreach (var e in evading)
            {
                TimeSpan span = e.times[e.times.Count - 1] - e.times[0];
                TimeSpan every = TimeSpan.FromTicks(span.Ticks / Math.Max(1, e.times.Count - 1));
                var finding = new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.Attack,
                    Address = e.ip,
                    RuleName = rule.TaskName,
                    LastSeenUtc = e.times[e.times.Count - 1],
                    Title = $"{e.ip} tried {e.times.Count} times in {Duration(span)} (every ~{Duration(every)}) — too slow for rule {rule.TaskName} ({rule.TriggerCount} within {Duration(TimeSpan.FromSeconds(window))})",
                    Details = $"First attempt {Local(e.times[0])}, last {Local(e.times[e.times.Count - 1])}. It never made {rule.TriggerCount} attempts within {Duration(TimeSpan.FromSeconds(window))}, so the rule didn't ban it.",
                    Advice = "Ban it permanently. To catch slow attackers like this automatically, widen the rule's window."
                };
                finding.Actions.Add(Ban(e.ip));
                if (widen != null)
                    finding.Actions.Add(widen);
                yield return finding;
            }

            foreach (var h in heavy)
            {
                var finding = new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.Attack,
                    Address = h.ip,
                    RuleName = rule.TaskName,
                    LastSeenUtc = h.times[h.times.Count - 1],
                    Title = $"{h.ip} tried {h.times.Count} times and isn't banned",
                    Details = $"Rule {rule.TaskName}. First attempt {Local(h.times[0])}, last {Local(h.times[h.times.Count - 1])}. Its temporary ban has run out or it was removed.",
                    Advice = "Ban it permanently."
                };
                finding.Actions.Add(Ban(h.ip));
                yield return finding;
            }
        }

        private static FindingAction BuildWiden(GenericIPBlockingTaskDTO rule, List<TimeSpan> needed)
        {
            if (needed.Count == 0)
                return null;

            double largest = needed.Max(n => n.TotalSeconds);
            int step = AnalyzerThresholds.WidenWindowSteps.FirstOrDefault(s => s >= largest);
            if (step == 0)
            {
                int max = AnalyzerThresholds.WidenWindowSteps.Max();
                if (!needed.Any(n => n.TotalSeconds <= max))
                    return null;
                step = max;
            }
            if (step <= rule.EventAge)
                return null;

            int newLock = Math.Max(rule.LockTime, step);
            string hours = Duration(TimeSpan.FromSeconds(step));
            return new FindingAction
            {
                Kind = FindingActionKind.WidenRuleWindow,
                RuleName = rule.TaskName,
                NewEventAgeSeconds = step,
                NewLockTimeSeconds = newLock,
                Label = $"Widen rule window to {hours}",
                ConfirmationText =
                    $"Rule {rule.TaskName}: window {rule.EventAge / 60} → {step / 60} minutes, ban length {rule.LockTime / 60} → {newLock / 60} minutes.\n\n" +
                    $"Any address with {rule.TriggerCount} failed logons within {hours} will be banned for {Duration(TimeSpan.FromSeconds(newLock))}. " +
                    "The ban length must be at least the window, otherwise the same address is banned again as soon as its ban lifts.\n\n" +
                    "Make sure your own addresses are whitelisted."
            };
        }

        #endregion

        #region RDP flood

        private static IEnumerable<Finding> CheckRdpFlood(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input)
        {
            var connections = new Dictionary<string, List<DateTime>>();
            foreach (KeyValuePair<string, IList<AnalyzedEvent>> log in eventsByLog)
            {
                foreach (AnalyzedEvent ev in log.Value.Where(e => e.EventId == 131 && Is(e.Provider, RdpCoreProvider)))
                {
                    if (!AddressClassifier.TryParse(ev.Get("ClientIP"), out IPAddress ip) || !IsBannable(ip, input))
                        continue;
                    string key = ip.ToString();
                    if (!connections.TryGetValue(key, out List<DateTime> times))
                        connections[key] = times = new List<DateTime>();
                    times.Add(ev.TimeUtc);
                }
            }

            var loggedOn = new HashSet<string>(eventsByLog.Values.SelectMany(v => v)
                .Where(e => e.EventId == 4624 && Is(e.Provider, SecurityAuditing))
                .Select(e => AddressClassifier.TryParse(e.Get("IpAddress"), out IPAddress ip) ? ip.ToString() : null)
                .Where(s => s != null));

            foreach (KeyValuePair<string, List<DateTime>> kvp in connections)
            {
                if (kvp.Value.Count < AnalyzerThresholds.RdpFloodConnections || loggedOn.Contains(kvp.Key) || IsBanned(kvp.Key, input))
                    continue;
                List<DateTime> times = kvp.Value.OrderBy(t => t).ToList();
                var finding = new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.Attack,
                    Address = kvp.Key,
                    LastSeenUtc = times[times.Count - 1],
                    Title = $"{kvp.Key} opened {times.Count} Remote Desktop connections without logging on",
                    Details = $"First {Local(times[0])}, last {Local(times[times.Count - 1])}. Connection floods use server resources even without a password attempt.",
                    Advice = "Ban it permanently."
                };
                finding.Actions.Add(Ban(kvp.Key));
                yield return finding;
            }
        }

        #endregion

        #region helpers

        internal static FindingAction Ban(string ip) => new FindingAction
        {
            Kind = FindingActionKind.BanPermanently,
            Addresses = new[] { ip },
            Label = "Ban permanently",
            ConfirmationText = $"Add {ip} to the permanent ban list?\n\nPermanent bans are never lifted automatically. You can remove it on the Bans & Whitelist tab."
        };

        internal static bool IsBannable(IPAddress ip, AnalyzerInput input) =>
            !AddressClassifier.IsLocal(ip, input.LocalAddresses)
            && !AddressClassifier.IsPrivate(ip)
            && !AddressClassifier.IsWhitelisted(ip.ToString(), input.WhitelistPatterns);

        private static bool IsBanned(string ip, AnalyzerInput input) =>
            (input.TemporarilyBanned != null && input.TemporarilyBanned.Contains(ip))
            || (input.PermanentlyBanned != null && input.PermanentlyBanned.Contains(ip));

        private static int MaxInWindow(List<DateTime> sorted, TimeSpan window)
        {
            int best = 0, start = 0;
            for (int end = 0; end < sorted.Count; end++)
            {
                while (sorted[end] - sorted[start] >= window)
                    start++;
                best = Math.Max(best, end - start + 1);
            }
            return best;
        }

        /// <summary>The shortest time any <paramref name="count"/> consecutive attempts took, plus one second.</summary>
        private static TimeSpan NeededSpan(List<DateTime> sorted, int count)
        {
            TimeSpan best = TimeSpan.MaxValue;
            for (int i = 0; i + count - 1 < sorted.Count; i++)
            {
                TimeSpan span = sorted[i + count - 1] - sorted[i];
                if (span < best)
                    best = span;
            }
            return best + TimeSpan.FromSeconds(1);
        }

        internal static bool TryGetLog(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, string log, out IList<AnalyzedEvent> events)
        {
            foreach (KeyValuePair<string, IList<AnalyzedEvent>> kvp in eventsByLog)
            {
                if (string.Equals(kvp.Key, log, StringComparison.OrdinalIgnoreCase))
                {
                    events = kvp.Value;
                    return true;
                }
            }
            events = null;
            return false;
        }

        internal static bool Is(string provider, string expected) => string.Equals(provider, expected, StringComparison.OrdinalIgnoreCase);

        internal static string Local(DateTime utc) => utc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);

        internal static string Duration(TimeSpan span)
        {
            if (span.TotalMinutes < 1)
                return $"{Math.Max(1, (int)Math.Round(span.TotalSeconds))} s";
            if (span.TotalMinutes < 120)
                return $"{(int)Math.Round(span.TotalMinutes)} min";
            if (span.TotalHours < 48)
                return $"{(int)Math.Round(span.TotalHours)} hours";
            return $"{(int)Math.Round(span.TotalDays)} days";
        }

        #endregion
    }
}
