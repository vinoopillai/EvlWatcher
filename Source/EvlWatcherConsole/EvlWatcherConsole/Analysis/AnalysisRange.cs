using System;
using System.Collections.Generic;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.Analysis
{
    public enum AnalysisRange
    {
        Last24Hours,
        Last7Days,
        Last30Days
    }

    public static class AnalysisRanges
    {
        public static TimeSpan ToTimeSpan(this AnalysisRange range)
        {
            switch (range)
            {
                case AnalysisRange.Last7Days: return TimeSpan.FromDays(7);
                case AnalysisRange.Last30Days: return TimeSpan.FromDays(30);
                default: return TimeSpan.FromHours(24);
            }
        }

        public static string Label(this AnalysisRange range)
        {
            switch (range)
            {
                case AnalysisRange.Last7Days: return "Last 7 days";
                case AnalysisRange.Last30Days: return "Last 30 days";
                default: return "Last 24 hours";
            }
        }
    }

    /// <summary>Everything the analyzer needs besides the events.</summary>
    public sealed class AnalyzerInput
    {
        public DateTime NowUtc { get; set; }

        public AnalysisRange Range { get; set; }

        /// <summary>All rules from the service; null when the service didn't answer.</summary>
        public IList<GenericIPBlockingTaskDTO> Rules { get; set; }

        public IList<string> WhitelistPatterns { get; set; } = new List<string>();

        public ISet<string> TemporarilyBanned { get; set; } = new HashSet<string>();

        public ISet<string> PermanentlyBanned { get; set; } = new HashSet<string>();

        public ISet<string> LocalAddresses { get; set; } = new HashSet<string>();

        /// <summary>The service's scan interval; the effective window of rules with OnlyNewEvents.</summary>
        public int CheckIntervalSeconds { get; set; } = 30;

        /// <summary>Set by the analyzer: whether the Security log could be read this scan.</summary>
        public bool SecurityLogRead { get; set; }

        /// <summary>Set by the analyzer: the oldest Security event read (older events in other logs can't be cross-checked).</summary>
        public DateTime? SecurityOldestUtc { get; set; }

        public DateTime FromUtc => NowUtc - Range.ToTimeSpan();
    }

    public sealed class AnalysisResult
    {
        public IList<Finding> Findings { get; set; } = new List<Finding>();

        public IList<string> LogsChecked { get; set; } = new List<string>();

        public IList<string> LogsMissing { get; set; } = new List<string>();

        public IList<string> LogsUnreadable { get; set; } = new List<string>();

        public int EventsRead { get; set; }

        /// <summary>Events held in memory for the checks (the rest of a rule's log is reduced to rule hits while reading).</summary>
        public int EventsKept { get; set; }

        public TimeSpan Duration { get; set; }

        /// <summary>Shown above the findings, e.g. when attack checks had to be skipped.</summary>
        public string Notice { get; set; }

        /// <summary>One action that bans every unbanned attacker found; null when there is none.</summary>
        public FindingAction BanAllAction { get; set; }
    }

    /// <summary>Tunable limits of the checks, in one place.</summary>
    public static class AnalyzerThresholds
    {
        public const int HeavyAttackerAttempts = 20;
        public const int RdpFloodConnections = 50;
        public const int FailuresBeforeLogon = 3;

        /// <summary>Failures count towards a "possible break-in" only within this time before the logon.</summary>
        public static readonly TimeSpan FailuresBeforeLogonWindow = TimeSpan.FromHours(1);
        public const int LockoutWarningCount = 3;
        public const int ServiceCrashWarningCount = 2;
        public const int AppCrashWarningCount = 3;

        /// <summary>Windows "Widen rule window" may offer, in seconds: 1 h, 6 h, 24 h.</summary>
        public static readonly int[] WidenWindowSteps = { 3600, 21600, 86400 };
    }
}
