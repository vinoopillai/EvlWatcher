using System;
using System.Collections.Generic;
using System.Linq;
using EvlWatcherConsole.Analysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests.Analysis
{
    [TestClass]
    public class SecurityChecksTests
    {
        private static readonly DateTime T0 = EventSamples.Utc("2026-11-20T20:00:00Z");

        private static AnalyzerInput Input() => new AnalyzerInput
        {
            NowUtc = EventSamples.Utc("2026-11-21T00:30:00Z"),
            Range = AnalysisRange.Last24Hours,
            WhitelistPatterns = new List<string> { "10.0.0.*" },
            LocalAddresses = new HashSet<string> { "127.0.0.1" }
        };

        private static IList<Finding> Run(params AnalyzedEvent[] events) =>
            SecurityChecks.Run(events.GroupBy(e => e.LogName).ToDictionary(g => g.Key, g => (IList<AnalyzedEvent>)g.ToList()), Input());

        private static IEnumerable<AnalyzedEvent> Failures(string ip, int count, string user = "administrator") =>
            Enumerable.Range(0, count).Select(i => EventSamples.Failed4625(ip, T0.AddMinutes(i), user));

        [TestMethod]
        public void LogonAfterFailuresFromPublicIpSameAccountIsCritical()
        {
            IList<Finding> findings = Run(Failures("5.175.140.23", 5)
                .Concat(new[] { EventSamples.Logon4624("5.175.140.23", T0.AddMinutes(10), "Administrator", 3) }).ToArray());

            Finding f = findings.Single();
            Assert.AreEqual(FindingSeverity.Critical, f.Severity);
            Assert.AreEqual(FindingCategory.SecurityChange, f.Category);
            Assert.AreEqual("5.175.140.23", f.Address);
            FindingAction ban = f.Actions.Single();
            Assert.AreEqual(FindingActionKind.BanPermanently, ban.Kind);
            StringAssert.Contains(ban.ConfirmationText, "real user");
        }

        [TestMethod]
        public void LogonAfterFailuresDifferentAccountIsWarning()
        {
            Finding f = Run(Failures("5.175.140.23", 5)
                .Concat(new[] { EventSamples.Logon4624("5.175.140.23", T0.AddMinutes(10), "alice", 10) }).ToArray()).Single();
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
        }

        [TestMethod]
        public void LogonAfterFailuresFromPrivateIpIsWarningWithoutBan()
        {
            Finding f = Run(Failures("192.168.1.20", 5)
                .Concat(new[] { EventSamples.Logon4624("192.168.1.20", T0.AddMinutes(10), "administrator", 3) }).ToArray()).Single();
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
            Assert.AreEqual(0, f.Actions.Count);
        }

        [TestMethod]
        public void TwoFailuresThenLogonIsNotReported()
        {
            Assert.AreEqual(0, Run(Failures("5.175.140.23", 2)
                .Concat(new[] { EventSamples.Logon4624("5.175.140.23", T0.AddMinutes(10), "administrator", 3) }).ToArray()).Count);
        }

        [TestMethod]
        public void FailuresAfterLogonDoNotCount()
        {
            Assert.AreEqual(0, Run(new[] { EventSamples.Logon4624("5.175.140.23", T0.AddMinutes(-1), "administrator", 3) }
                .Concat(Failures("5.175.140.23", 5)).ToArray()).Count);
        }

        [TestMethod]
        public void InteractiveLogonTypeIsIgnored()
        {
            Assert.AreEqual(0, Run(Failures("5.175.140.23", 5)
                .Concat(new[] { EventSamples.Logon4624("5.175.140.23", T0.AddMinutes(10), "administrator", 2) }).ToArray()).Count);
        }

        [TestMethod]
        public void LogClearedIsCritical()
        {
            Finding f = Run(EventSamples.LogCleared1102(T0, "admin2")).Single();
            Assert.AreEqual(FindingSeverity.Critical, f.Severity);
            StringAssert.Contains(f.Details, "admin2");
        }

        [TestMethod]
        public void ServiceInstalledIsWarning()
        {
            Finding f = Run(EventSamples.ServiceInstalled7045("Updater", @"C:\Users\Public\upd.exe", T0)).Single();
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
            StringAssert.Contains(f.Details, @"C:\Users\Public\upd.exe");
        }

        [TestMethod]
        public void AdminGroupAddIsWarningOtherGroupIgnored()
        {
            IList<Finding> findings = Run(EventSamples.GroupAdd4732("Administrators", "CN=bob", T0),
                                          EventSamples.GroupAdd4732("Backup Operators", "CN=bob", T0));
            Assert.AreEqual(FindingSeverity.Warning, findings.Single().Severity);
            StringAssert.Contains(findings.Single().Title, "Administrators");
        }

        [TestMethod]
        public void UserCreatedIsWarningTaskCreatedIsInfo()
        {
            IList<Finding> findings = Run(EventSamples.UserCreated4720("support2", T0), EventSamples.TaskCreated4698(@"\Updater", T0));
            Assert.AreEqual(FindingSeverity.Warning, findings.Single(f => f.Title.Contains("support2")).Severity);
            Assert.AreEqual(FindingSeverity.Info, findings.Single(f => f.Title.Contains("Updater")).Severity);
        }

        [TestMethod]
        public void LockoutsGroupedAndListCallerIps()
        {
            IList<Finding> findings = Run(new[]
            {
                EventSamples.Lockout4740("administrator", T0), EventSamples.Lockout4740("administrator", T0.AddHours(1)),
                EventSamples.Lockout4740("administrator", T0.AddHours(2))
            }.Concat(Failures("5.175.140.23", 2)).Concat(Failures("94.203.133.74", 2)).ToArray());

            Finding f = findings.Single();
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
            StringAssert.Contains(f.Details, "5.175.140.23");
            StringAssert.Contains(f.Details, "94.203.133.74");
            Assert.AreEqual(0, f.Actions.Count);
        }

        [TestMethod]
        public void SingleLockoutIsInfo()
        {
            Assert.AreEqual(FindingSeverity.Info, Run(EventSamples.Lockout4740("bob", T0)).Single().Severity);
        }
    }
}
