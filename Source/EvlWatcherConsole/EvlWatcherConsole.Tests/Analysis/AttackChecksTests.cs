using System;
using System.Collections.Generic;
using System.Linq;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Analysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests.Analysis
{
    [TestClass]
    public class AttackChecksTests
    {
        // The slow attacker from the maintainer's log of 2026-11-20/21 (UTC): one try every ~24 minutes.
        private static readonly string[] SlowAttackerTimes =
        {
            "2026-11-20T18:36:28Z", "2026-11-20T19:00:47Z", "2026-11-20T19:25:03Z", "2026-11-20T19:49:16Z",
            "2026-11-20T20:13:36Z", "2026-11-20T20:37:53Z", "2026-11-20T21:04:53Z", "2026-11-20T21:31:15Z",
            "2026-11-20T21:56:51Z", "2026-11-20T22:21:43Z", "2026-11-20T22:46:24Z", "2026-11-20T23:11:02Z",
            "2026-11-20T23:35:24Z", "2026-11-20T23:59:48Z", "2026-11-21T00:24:20Z"
        };

        private static GenericIPBlockingTaskDTO Rule(int lockTime = 3600, bool active = true) => new GenericIPBlockingTaskDTO
        {
            TaskName = "BlockRDPBrutersBySecurity4625",
            Active = active,
            TriggerCount = 5,
            EventAge = 3600,
            LockTime = lockTime,
            PermaBanCount = 3,
            EventPath = new List<string> { "Security" },
            RegexBoosters = new List<string> { "4625", "IpAddress" },
            Regex = @"<Data Name=.IpAddress.>(\d*.\d*.\d*.\d*)"
        };

        private static AnalyzerInput Input(GenericIPBlockingTaskDTO rule, params string[] whitelist) => new AnalyzerInput
        {
            NowUtc = EventSamples.Utc("2026-11-21T00:30:00Z"),
            Range = AnalysisRange.Last24Hours,
            Rules = new List<GenericIPBlockingTaskDTO> { rule },
            WhitelistPatterns = whitelist.ToList(),
            LocalAddresses = new HashSet<string> { "127.0.0.1", "::1" },
            SecurityLogRead = true
        };

        // ---- review fixes ----

        [TestMethod]
        public void LegitUserWithSuccessfulLogonIsNotFlagged()
        {
            // 15 typos over the day, but the same address also logs on successfully: a real user, not an attacker
            var events = SlowAttacker().Concat(new[] { EventSamples.Logon4624("5.175.140.23", EventSamples.Utc("2026-11-20T23:00:00Z"), "alice", 10) }).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), Input(Rule())).Count);
        }

        [TestMethod]
        public void FloodSkippedWhenSecurityUnread()
        {
            DateTime t = EventSamples.Utc("2026-11-20T10:00:00Z");
            AnalyzerInput input = Input(Rule());
            input.SecurityLogRead = false;
            var events = Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddSeconds(i * 10))).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), input).Count);
        }

        [TestMethod]
        public void SparseConnectionsAreNotAFlood()
        {
            // a daily RDP user: 60 connections spread over the range, never 50 within an hour
            DateTime t = EventSamples.Utc("2026-11-20T00:31:00Z");
            var events = Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddMinutes(i * 23))).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), Input(Rule())).Count);
        }

        [TestMethod]
        public void FloodIgnoresConnectionsOlderThanTheSecurityLog()
        {
            DateTime t = EventSamples.Utc("2026-11-20T10:00:00Z");
            AnalyzerInput input = Input(Rule());
            input.SecurityOldestUtc = t.AddHours(1);
            var events = Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddSeconds(i * 10))).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), input).Count);
        }

        [TestMethod]
        public void FloodSkippedWhenServiceDown()
        {
            DateTime t = EventSamples.Utc("2026-11-20T10:00:00Z");
            AnalyzerInput input = Input(Rule());
            input.Rules = null;
            var events = Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddSeconds(i * 10))).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), input).Count);
        }

        [TestMethod]
        public void OnlyNewRuleUsesCheckIntervalAndGetsNoWiden()
        {
            // OnlyNew rules count only the events of one check interval: 5 tries within 90 s evade a 30 s interval
            GenericIPBlockingTaskDTO rule = Rule();
            rule.OnlyNewEvents = true;
            AnalyzerInput input = Input(rule);
            input.CheckIntervalSeconds = 30;

            Finding f = AttackChecks.Run(Logs(Burst("5.175.140.23", "2026-11-20T10:00:00Z", 5, 20).ToArray()), input).Single();
            Assert.IsFalse(f.Actions.Any(a => a.Kind == FindingActionKind.WidenRuleWindow));
            Assert.IsTrue(f.Actions.Any(a => a.Kind == FindingActionKind.BanPermanently));
        }

        [TestMethod]
        public void BanAllConfirmationIsShortForManyAddresses()
        {
            var findings = Enumerable.Range(1, 120).Select(i => new Finding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.Attack,
                Actions = { AttackChecks.Ban("203.0." + (i / 250) + "." + (i % 250)) }
            }).ToList();

            FindingAction all = AttackChecks.BuildBanAll(findings);
            Assert.AreEqual(120, all.Addresses.Count);
            Assert.IsTrue(all.ConfirmationText.Split('\n').Length < 30, "dialog must fit on screen");
            StringAssert.Contains(all.ConfirmationText, "and 100 more");
        }

        [TestMethod]
        public void ChecksHonourCancellation()
        {
            using (var cts = new System.Threading.CancellationTokenSource())
            {
                cts.Cancel();
                bool cancelled = false;
                try
                {
                    AttackChecks.Run(Logs(SlowAttacker()), Input(Rule()), cts.Token);
                }
                catch (OperationCanceledException)
                {
                    cancelled = true;
                }
                Assert.IsTrue(cancelled);
            }
        }

        [TestMethod]
        public void RuleMatcherAgreesWithRuleBuilder()
        {
            GenericIPBlockingTaskDTO rule = Rule();
            var matcher = new RuleMatcher(rule);
            foreach (AnalyzedEvent e in SlowAttacker().Concat(Burst("-", "2026-11-20T10:00:00Z", 2, 1)).Concat(new[] { EventSamples.Disk7(DateTime.UtcNow) }))
                Assert.AreEqual(Rules.RuleBuilder.Match(rule, e.Xml)?.ToString(), matcher.Match(e.Xml)?.ToString());
        }

        private static Dictionary<string, IList<AnalyzedEvent>> Logs(params AnalyzedEvent[] events) =>
            events.GroupBy(e => e.LogName).ToDictionary(g => g.Key, g => (IList<AnalyzedEvent>)g.ToList());

        private static IEnumerable<AnalyzedEvent> Burst(string ip, string startUtc, int count, int secondsApart)
        {
            DateTime t = EventSamples.Utc(startUtc);
            for (int i = 0; i < count; i++)
                yield return EventSamples.Failed4625(ip, t.AddSeconds(i * secondsApart));
        }

        private static AnalyzedEvent[] SlowAttacker() =>
            SlowAttackerTimes.Select(t => EventSamples.Failed4625("5.175.140.23", EventSamples.Utc(t))).ToArray();

        [TestMethod]
        public void SlowAttackerIsEvadingAndGetsSixHourWiden()
        {
            IList<Finding> findings = AttackChecks.Run(Logs(SlowAttacker()), Input(Rule()));

            Finding f = findings.Single();
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
            Assert.AreEqual(FindingCategory.Attack, f.Category);
            Assert.AreEqual("5.175.140.23", f.Address);
            StringAssert.Contains(f.Title, "15");

            FindingAction widen = f.Actions.Single(a => a.Kind == FindingActionKind.WidenRuleWindow);
            Assert.AreEqual(21600, widen.NewEventAgeSeconds);
            Assert.AreEqual(21600, widen.NewLockTimeSeconds);
            Assert.AreEqual("BlockRDPBrutersBySecurity4625", widen.RuleName);
            StringAssert.Contains(widen.ConfirmationText, "60");
            StringAssert.Contains(widen.ConfirmationText, "360");
            StringAssert.Contains(widen.ConfirmationText, "whitelisted");

            FindingAction ban = f.Actions.Single(a => a.Kind == FindingActionKind.BanPermanently);
            CollectionAssert.AreEqual(new[] { "5.175.140.23" }, ban.Addresses.ToArray());
        }

        [TestMethod]
        public void WidenKeepsLongerLockTime()
        {
            Finding f = AttackChecks.Run(Logs(SlowAttacker()), Input(Rule(lockTime: 86400))).Single();
            Assert.AreEqual(86400, f.Actions.Single(a => a.Kind == FindingActionKind.WidenRuleWindow).NewLockTimeSeconds);
        }

        [TestMethod]
        public void BannedBurstAttackerHasNoFinding()
        {
            AnalyzerInput input = Input(Rule());
            input.TemporarilyBanned.Add("37.98.153.123");
            Assert.AreEqual(0, AttackChecks.Run(Logs(Burst("37.98.153.123", "2026-11-20T18:44:33Z", 5, 40).ToArray()), input).Count);
        }

        [TestMethod]
        public void HeavyUnbannedAttackerIsWarning()
        {
            Finding f = AttackChecks.Run(Logs(Burst("88.214.25.121", "2026-11-21T00:04:06Z", 25, 2).ToArray()), Input(Rule())).Single();
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
            Assert.AreEqual("88.214.25.121", f.Address);
            Assert.AreEqual(FindingActionKind.BanPermanently, f.Actions.Single().Kind);
        }

        [TestMethod]
        public void CaughtBurstUnderHeavyLimitHasNoFinding()
        {
            // reached the trigger inside the window (the service would have banned it), ban since expired, < 20 tries
            Assert.AreEqual(0, AttackChecks.Run(Logs(Burst("88.214.25.124", "2026-11-20T04:22:01Z", 15, 2).ToArray()), Input(Rule())).Count);
        }

        [TestMethod]
        public void WhitelistedAndPrivateGetNothing()
        {
            var events = Burst("192.168.1.50", "2026-11-20T10:00:00Z", 30, 60).Concat(Burst("10.1.1.1", "2026-11-20T10:00:00Z", 30, 60)).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), Input(Rule(), "192.168.*")).Count);
        }

        [TestMethod]
        public void IgnoresMissingAndLocalAddresses()
        {
            var events = Burst("-", "2026-11-20T10:00:00Z", 30, 60)
                .Concat(Burst("::1", "2026-11-20T10:00:00Z", 30, 60))
                .Concat(Burst("127.0.0.1", "2026-11-20T10:00:00Z", 30, 60)).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), Input(Rule())).Count);
        }

        [TestMethod]
        public void ParsesClientIpWithPort()
        {
            DateTime t = EventSamples.Utc("2026-11-20T10:00:00Z");
            var events = Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddSeconds(i * 10))).ToArray();

            Finding f = AttackChecks.Run(Logs(events), Input(Rule())).Single();
            Assert.AreEqual("203.0.113.9", f.Address);
            Assert.AreEqual(FindingSeverity.Warning, f.Severity);
            Assert.AreEqual(FindingActionKind.BanPermanently, f.Actions.Single().Kind);
        }

        [TestMethod]
        public void RdpFloodWithSuccessfulLogonIsNotReported()
        {
            DateTime t = EventSamples.Utc("2026-11-20T10:00:00Z");
            var events = Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddSeconds(i * 10)))
                .Concat(new[] { EventSamples.Logon4624("203.0.113.9", t, "alice", 10) }).ToArray();
            Assert.AreEqual(0, AttackChecks.Run(Logs(events), Input(Rule())).Count);
        }

        [TestMethod]
        public void BanAllListsDistinctAddresses()
        {
            var events = SlowAttacker()
                .Concat(SlowAttackerTimes.Select(t => EventSamples.Failed4625("94.203.133.74", EventSamples.Utc(t).AddSeconds(7))))
                .Concat(Burst("88.214.25.121", "2026-11-21T00:04:06Z", 25, 2)).ToArray();

            IList<Finding> findings = AttackChecks.Run(Logs(events), Input(Rule()));
            FindingAction all = AttackChecks.BuildBanAll(findings);

            Assert.AreEqual(FindingActionKind.BanAll, all.Kind);
            Assert.AreEqual(3, all.Addresses.Count);
            Assert.AreEqual(3, all.Addresses.Distinct().Count());
            StringAssert.Contains(all.ConfirmationText, "5.175.140.23");
        }

        [TestMethod]
        public void BanAllIsNullWithoutAttackers()
        {
            Assert.IsNull(AttackChecks.BuildBanAll(new List<Finding>()));
        }

        [TestMethod]
        public void InactiveRuleIsIgnored()
        {
            Assert.AreEqual(0, AttackChecks.Run(Logs(SlowAttacker()), Input(Rule(active: false))).Count);
        }
    }
}
