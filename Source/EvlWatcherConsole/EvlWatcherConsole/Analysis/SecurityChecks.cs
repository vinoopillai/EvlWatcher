using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>Group 2: signs that someone got in or changed something. Alerts with advice; bans only for public IPs.</summary>
    public static class SecurityChecks
    {
        #region public properties

        public static readonly int[] SecurityEventIds = { 4624, 4625, 4740, 1102, 4720, 4728, 4732, 4756, 4698 };

        public static readonly int[] SystemEventIds = { 7045 };

        #endregion

        #region private members

        private const string Auditing = "Microsoft-Windows-Security-Auditing";
        private const string EventlogProvider = "Microsoft-Windows-Eventlog";
        private const string Scm = "Service Control Manager";

        private static readonly HashSet<string> PrivilegedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Administrators", "Remote Desktop Users", "Domain Admins", "Enterprise Admins"
        };

        #endregion

        #region public operations

        public static IList<Finding> Run(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input)
        {
            List<AnalyzedEvent> all = eventsByLog.Values.SelectMany(v => v).ToList();
            var findings = new List<Finding>();
            findings.AddRange(LogonsAfterFailures(all, input));
            findings.AddRange(LogCleared(all));
            findings.AddRange(ServicesInstalled(all));
            findings.AddRange(GroupChanges(all));
            findings.AddRange(UsersCreated(all));
            findings.AddRange(Lockouts(all));
            findings.AddRange(TasksCreated(all));
            return findings;
        }

        #endregion

        #region checks

        private static IEnumerable<Finding> LogonsAfterFailures(List<AnalyzedEvent> all, AnalyzerInput input)
        {
            var failures = all.Where(e => e.EventId == 4625 && AttackChecks.Is(e.Provider, Auditing))
                .Select(e => new { Ip = Ip(e), User = e.Get("TargetUserName") ?? "", e.TimeUtc })
                .Where(f => f.Ip != null)
                .ToList();

            var logons = all.Where(e => e.EventId == 4624 && AttackChecks.Is(e.Provider, Auditing)
                                        && (e.Get("LogonType") == "3" || e.Get("LogonType") == "10"))
                .Select(e => new { Ip = Ip(e), User = e.Get("TargetUserName") ?? "", e.TimeUtc, Type = e.Get("LogonType") })
                .Where(l => l.Ip != null)
                .ToList();

            foreach (var group in logons.GroupBy(l => new { l.Ip, User = l.User.ToUpperInvariant() }))
            {
                var logon = group.OrderBy(l => l.TimeUtc).Last();
                IPAddress ip = IPAddress.Parse(logon.Ip);
                if (AddressClassifier.IsLocal(ip, input.LocalAddresses))
                    continue;

                var before = failures.Where(f => f.Ip == logon.Ip && f.TimeUtc < logon.TimeUtc).ToList();
                if (before.Count < AnalyzerThresholds.FailuresBeforeLogon)
                    continue;

                bool sameAccount = before.Any(f => string.Equals(f.User, logon.User, StringComparison.OrdinalIgnoreCase));
                bool isPublic = !AddressClassifier.IsPrivate(ip) && !AddressClassifier.IsWhitelisted(logon.Ip, input.WhitelistPatterns);

                var finding = new Finding
                {
                    Severity = isPublic && sameAccount ? FindingSeverity.Critical : FindingSeverity.Warning,
                    Category = FindingCategory.SecurityChange,
                    Address = logon.Ip,
                    LastSeenUtc = logon.TimeUtc,
                    Title = $"Possible break-in: {logon.Ip} logged on as \"{logon.User}\" after {before.Count} failed attempts",
                    Details = $"Logon type {logon.Type} ({(logon.Type == "10" ? "Remote Desktop" : "network")}) at {AttackChecks.Local(logon.TimeUtc)}. " +
                              $"Failed accounts from this address: {string.Join(", ", before.Select(f => f.User).Distinct(StringComparer.OrdinalIgnoreCase).Take(5))}.",
                    Advice = "If you don't recognise this logon: change the account's password, check what it did, and ban the address."
                };
                if (isPublic)
                {
                    FindingAction ban = AttackChecks.Ban(logon.Ip);
                    ban.ConfirmationText += "\n\nThis may be a real user who mistyped their password before logging on.";
                    finding.Actions.Add(ban);
                }
                yield return finding;
            }
        }

        private static IEnumerable<Finding> LogCleared(List<AnalyzedEvent> all) =>
            all.Where(e => e.EventId == 1102 && AttackChecks.Is(e.Provider, EventlogProvider)).Select(e => new Finding
            {
                Severity = FindingSeverity.Critical,
                Category = FindingCategory.SecurityChange,
                LastSeenUtc = e.TimeUtc,
                Title = "The Security log was cleared",
                Details = $"Cleared by {e.Get("SubjectDomainName")}\\{e.Get("SubjectUserName")} at {AttackChecks.Local(e.TimeUtc)}.",
                Advice = "Attackers clear the log to hide their tracks. Find out who did it and why."
            });

        private static IEnumerable<Finding> ServicesInstalled(List<AnalyzedEvent> all) =>
            all.Where(e => e.EventId == 7045 && AttackChecks.Is(e.Provider, Scm)).Select(e => new Finding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.SecurityChange,
                LastSeenUtc = e.TimeUtc,
                Title = $"New service installed: {e.Get("ServiceName")}",
                Details = $"Program: {e.Get("ImagePath")}. Runs as {e.Get("AccountName")}, start type {e.Get("StartType")}, installed {AttackChecks.Local(e.TimeUtc)}.",
                Advice = "Check that you expected this service and that its program path is legitimate."
            });

        private static IEnumerable<Finding> GroupChanges(List<AnalyzedEvent> all) =>
            all.Where(e => (e.EventId == 4732 || e.EventId == 4728 || e.EventId == 4756) && AttackChecks.Is(e.Provider, Auditing)
                           && PrivilegedGroups.Contains(e.Get("TargetUserName") ?? ""))
                .Select(e => new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.SecurityChange,
                    LastSeenUtc = e.TimeUtc,
                    Title = $"Account added to {e.Get("TargetUserName")}",
                    Details = $"Member {e.Get("MemberName")} ({e.Get("MemberSid")}), added by {e.Get("SubjectUserName")} at {AttackChecks.Local(e.TimeUtc)}.",
                    Advice = "Check that this change was intended."
                });

        private static IEnumerable<Finding> UsersCreated(List<AnalyzedEvent> all) =>
            all.Where(e => e.EventId == 4720 && AttackChecks.Is(e.Provider, Auditing)).Select(e => new Finding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.SecurityChange,
                LastSeenUtc = e.TimeUtc,
                Title = $"New user account: {e.Get("TargetUserName")}",
                Details = $"Created by {e.Get("SubjectUserName")} at {AttackChecks.Local(e.TimeUtc)}.",
                Advice = "Check that this account was intended."
            });

        private static IEnumerable<Finding> Lockouts(List<AnalyzedEvent> all)
        {
            var failures = all.Where(e => e.EventId == 4625 && AttackChecks.Is(e.Provider, Auditing)).ToList();

            foreach (var group in all.Where(e => e.EventId == 4740 && AttackChecks.Is(e.Provider, Auditing))
                                     .GroupBy(e => (e.Get("TargetUserName") ?? "").ToUpperInvariant()))
            {
                string account = group.First().Get("TargetUserName");
                List<string> ips = failures
                    .Where(f => string.Equals(f.Get("TargetUserName"), account, StringComparison.OrdinalIgnoreCase))
                    .Select(Ip).Where(ip => ip != null).Distinct().Take(10).ToList();
                int count = group.Count();

                yield return new Finding
                {
                    Severity = count >= AnalyzerThresholds.LockoutWarningCount ? FindingSeverity.Warning : FindingSeverity.Info,
                    Category = FindingCategory.SecurityChange,
                    LastSeenUtc = group.Max(e => e.TimeUtc),
                    Title = $"Account \"{account}\" was locked out {count} time{(count == 1 ? "" : "s")}",
                    Details = ips.Count == 0
                        ? "No failed logons with a source address were found for this account."
                        : "Failed logons for this account came from: " + string.Join(", ", ips) + ".",
                    Advice = "If these addresses aren't yours, ban them. Consider renaming the built-in Administrator account."
                };
            }
        }

        private static IEnumerable<Finding> TasksCreated(List<AnalyzedEvent> all) =>
            all.Where(e => e.EventId == 4698 && AttackChecks.Is(e.Provider, Auditing)).Select(e => new Finding
            {
                Severity = FindingSeverity.Info,
                Category = FindingCategory.SecurityChange,
                LastSeenUtc = e.TimeUtc,
                Title = $"Scheduled task created: {e.Get("TaskName")}",
                Details = $"Created by {e.Get("SubjectUserName")} at {AttackChecks.Local(e.TimeUtc)}.",
                Advice = "Check that you expected this task."
            });

        #endregion

        #region helpers

        private static string Ip(AnalyzedEvent e) =>
            AddressClassifier.TryParse(e.Get("IpAddress"), out IPAddress ip) ? ip.ToString() : null;

        #endregion
    }
}
