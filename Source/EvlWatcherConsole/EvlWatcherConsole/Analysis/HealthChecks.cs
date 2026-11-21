using System;
using System.Collections.Generic;
using System.Linq;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>Group 3: events that point at problems which slow down, degrade or break the server. Advice only.</summary>
    public static class HealthChecks
    {
        #region public properties

        public static readonly int[] SystemEventIds = { 7, 11, 51, 153, 55, 98, 1001, 41, 6008, 2004, 2013, 7031, 7034, 20 };

        public static readonly int[] ApplicationEventIds = { 1000, 1002, 833, 701 };

        public static readonly int[] SecurityEventIds = { 1104 };

        #endregion

        #region private members

        private sealed class Check
        {
            public Func<string, bool> Provider;
            public int[] Ids;
            public Func<AnalyzedEvent, string> GroupBy = e => "";
            public Func<int, FindingSeverity> Severity;
            public Func<string, int, string> Title;
            public string Advice;
        }

        private static readonly Check[] Checks =
        {
            new Check
            {
                Provider = p => Is(p, "disk"), Ids = new[] { 7, 11, 51, 153 },
                Severity = n => FindingSeverity.Critical,
                Title = (g, n) => $"Disk errors ({n})",
                Advice = "Back up now and check the disk; these errors often come before a disk fails."
            },
            new Check
            {
                Provider = p => Is(p, "Ntfs") || Is(p, "Microsoft-Windows-Ntfs"), Ids = new[] { 55, 98 },
                Severity = n => FindingSeverity.Critical,
                Title = (g, n) => $"File system errors ({n})",
                Advice = "Run chkdsk on the volume during a maintenance window."
            },
            new Check
            {
                Provider = p => Is(p, "Microsoft-Windows-WER-SystemErrorReporting") || Is(p, "BugCheck"), Ids = new[] { 1001 },
                Severity = n => FindingSeverity.Critical,
                Title = (g, n) => $"The server crashed with a blue screen ({n})",
                Advice = "The server crashed (blue screen). Check drivers and recent updates."
            },
            new Check
            {
                Provider = p => Is(p, "Microsoft-Windows-Kernel-Power") || Is(p, "EventLog"), Ids = new[] { 41, 6008 },
                Severity = n => FindingSeverity.Warning,
                Title = (g, n) => $"Unexpected restarts ({n})",
                Advice = "Find out why the server restarted: power, crash or someone holding the power button."
            },
            new Check
            {
                Provider = p => Is(p, "Microsoft-Windows-Resource-Exhaustion-Detector"), Ids = new[] { 2004 },
                Severity = n => FindingSeverity.Warning,
                Title = (g, n) => $"Memory ran low ({n})",
                Advice = "Memory ran low. Check which programs use most memory, or add RAM."
            },
            new Check
            {
                Provider = p => Is(p, "srv"), Ids = new[] { 2013 },
                Severity = n => FindingSeverity.Warning,
                Title = (g, n) => $"Disk almost full ({n})",
                Advice = "A disk is almost full. Free space or extend the volume."
            },
            new Check
            {
                Provider = p => Is(p, "Microsoft-Windows-Eventlog"), Ids = new[] { 1104 },
                Severity = n => FindingSeverity.Critical,
                Title = (g, n) => "The Security log is full and stopped recording",
                Advice = "The Security log is full and has stopped recording, so EvlWatcher can't see attacks. Set it to overwrite old events or archive it."
            },
            new Check
            {
                Provider = p => Is(p, "Service Control Manager"), Ids = new[] { 7031, 7034 },
                GroupBy = e => e.Get("param1") ?? "(unknown service)",
                Severity = n => n >= AnalyzerThresholds.ServiceCrashWarningCount ? FindingSeverity.Warning : FindingSeverity.Info,
                Title = (g, n) => $"Service \"{g}\" stopped unexpectedly {Times(n)}",
                Advice = "Check the service's own logs. A service that keeps crashing can slow the server or leave it without that function."
            },
            new Check
            {
                Provider = p => Is(p, "Application Error") || Is(p, "Application Hang"), Ids = new[] { 1000, 1002 },
                GroupBy = e => e.Get("AppName") ?? e.Get("#1") ?? "(unknown program)",
                Severity = n => n >= AnalyzerThresholds.AppCrashWarningCount ? FindingSeverity.Warning : FindingSeverity.Info,
                Title = (g, n) => $"Program \"{g}\" crashed or hung {Times(n)}",
                Advice = "Update or repair the program. Repeated crashes can point at a bad update, low memory or disk problems."
            },
            new Check
            {
                Provider = p => Is(p, "MSSQLSERVER") || (p ?? "").StartsWith("MSSQL$", StringComparison.OrdinalIgnoreCase), Ids = new[] { 833, 701 },
                GroupBy = e => e.Provider,
                Severity = n => FindingSeverity.Warning,
                Title = (g, n) => $"SQL Server ({g}) reports slow disk I/O or memory pressure ({n})",
                Advice = "Check disk latency and SQL Server's memory settings; these slow every database on the server."
            },
            new Check
            {
                Provider = p => Is(p, "Microsoft-Windows-WindowsUpdateClient"), Ids = new[] { 20 },
                Severity = n => FindingSeverity.Info,
                Title = (g, n) => $"Windows Update failed to install updates ({n})",
                Advice = "Open Windows Update and retry; missing security updates leave the server exposed."
            }
        };

        #endregion

        #region public operations

        public static IList<Finding> Run(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input)
        {
            // Information (4) and Verbose (5) events are routine: e.g. Ntfs 98 "Volume C: is healthy" shares its ID with real problems.
            List<AnalyzedEvent> all = eventsByLog.Values.SelectMany(v => v).Where(e => e.Level < 4).ToList();
            var findings = new List<Finding>();

            foreach (Check check in Checks)
            {
                foreach (IGrouping<string, AnalyzedEvent> group in all.Where(e => check.Ids.Contains(e.EventId) && check.Provider(e.Provider))
                                                                      .GroupBy(check.GroupBy, StringComparer.OrdinalIgnoreCase))
                {
                    int count = group.Count();
                    DateTime first = group.Min(e => e.TimeUtc), last = group.Max(e => e.TimeUtc);
                    findings.Add(new Finding
                    {
                        Severity = check.Severity(count),
                        Category = FindingCategory.ServerHealth,
                        LastSeenUtc = last,
                        Title = check.Title(group.Key, count),
                        Details = count == 1
                            ? $"At {AttackChecks.Local(last)} ({group.First().Provider}, event {group.First().EventId})."
                            : $"{count} times between {AttackChecks.Local(first)} and {AttackChecks.Local(last)} ({group.First().Provider}, events {string.Join(", ", group.Select(e => e.EventId).Distinct())}).",
                        Advice = check.Advice
                    });
                }
            }
            return findings;
        }

        #endregion

        #region helpers

        private static bool Is(string provider, string expected) => AttackChecks.Is(provider, expected);

        private static string Times(int n) => n == 1 ? "once" : n + " times";

        #endregion
    }
}
