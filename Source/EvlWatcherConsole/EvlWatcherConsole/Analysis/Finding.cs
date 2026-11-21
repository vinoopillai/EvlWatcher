using System;
using System.Collections.Generic;

namespace EvlWatcherConsole.Analysis
{
    public enum FindingSeverity
    {
        Info = 0,
        Warning = 1,
        Critical = 2
    }

    public enum FindingCategory
    {
        Attack,
        SecurityChange,
        ServerHealth
    }

    public enum FindingActionKind
    {
        BanPermanently,
        BanAll,
        WidenRuleWindow
    }

    /// <summary>A fix the admin can apply with one click, after confirming <see cref="ConfirmationText"/>.</summary>
    public sealed class FindingAction
    {
        public FindingActionKind Kind { get; set; }

        public IReadOnlyList<string> Addresses { get; set; } = new string[0];

        public string RuleName { get; set; }

        public int NewEventAgeSeconds { get; set; }

        public int NewLockTimeSeconds { get; set; }

        public string Label { get; set; }

        public string ConfirmationText { get; set; }
    }

    /// <summary>One risk the analyzer found, in plain language.</summary>
    public sealed class Finding
    {
        public FindingSeverity Severity { get; set; }

        public FindingCategory Category { get; set; }

        public string Title { get; set; }

        public string Details { get; set; }

        public string Advice { get; set; }

        /// <summary>The IP address the finding is about, if any.</summary>
        public string Address { get; set; }

        /// <summary>The rule the finding is about, if any.</summary>
        public string RuleName { get; set; }

        public DateTime LastSeenUtc { get; set; }

        public IList<FindingAction> Actions { get; set; } = new List<FindingAction>();
    }
}
