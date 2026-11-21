using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Analysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests.Analysis
{
    /// <summary>In-memory event logs for the analyzer and view-model tests.</summary>
    internal sealed class FakeEventSource : IEventSource
    {
        public readonly Dictionary<string, List<AnalyzedEvent>> Logs = new Dictionary<string, List<AnalyzedEvent>>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> Unreadable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly List<(string log, IReadOnlyCollection<int> ids)> Requests = new List<(string, IReadOnlyCollection<int>)>();

        /// <summary>When set, reading this log yields events forever (for cancellation tests).</summary>
        public string EndlessLog;

        public FakeEventSource Add(params AnalyzedEvent[] events)
        {
            foreach (AnalyzedEvent e in events)
            {
                if (!Logs.TryGetValue(e.LogName, out List<AnalyzedEvent> list))
                    Logs[e.LogName] = list = new List<AnalyzedEvent>();
                list.Add(e);
            }
            return this;
        }

        public FakeEventSource WithLogs(params string[] logs)
        {
            foreach (string log in logs)
                if (!Logs.ContainsKey(log))
                    Logs[log] = new List<AnalyzedEvent>();
            return this;
        }

        public bool LogExists(string logName) => Logs.ContainsKey(logName) || Unreadable.Contains(logName) || logName == EndlessLog;

        public IEnumerable<AnalyzedEvent> Read(string logName, IReadOnlyCollection<int> eventIds, DateTime fromUtc, CancellationToken ct)
        {
            lock (Requests)
                Requests.Add((logName, eventIds));
            if (Unreadable.Contains(logName))
                throw new UnauthorizedAccessException("Access denied");
            return ReadCore(logName, eventIds, fromUtc, ct);
        }

        private IEnumerable<AnalyzedEvent> ReadCore(string logName, IReadOnlyCollection<int> eventIds, DateTime fromUtc, CancellationToken ct)
        {
            if (logName == EndlessLog)
            {
                AnalyzedEvent sample = EventSamples.Failed4625("203.0.113.1", DateTime.UtcNow);
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    Thread.Sleep(1);
                    yield return sample;
                }
            }

            foreach (AnalyzedEvent e in Logs[logName])
            {
                ct.ThrowIfCancellationRequested();
                if (e.TimeUtc >= fromUtc && (eventIds == null || eventIds.Contains(e.EventId)))
                    yield return e;
            }
        }
    }

    [TestClass]
    public class AnalyzerTests
    {
        private static readonly DateTime Now = EventSamples.Utc("2026-11-21T00:30:00Z");

        private static GenericIPBlockingTaskDTO Rule(string name, params string[] logs) => new GenericIPBlockingTaskDTO
        {
            TaskName = name, Active = true, TriggerCount = 5, EventAge = 3600, LockTime = 3600, PermaBanCount = 3,
            EventPath = logs.ToList(), RegexBoosters = new List<string> { "4625", "IpAddress" },
            Regex = @"<Data Name=.IpAddress.>(\d*.\d*.\d*.\d*)"
        };

        private static AnalyzerInput Input(params GenericIPBlockingTaskDTO[] rules) => new AnalyzerInput
        {
            NowUtc = Now,
            Range = AnalysisRange.Last24Hours,
            Rules = rules.ToList(),
            LocalAddresses = new HashSet<string> { "127.0.0.1" }
        };

        private static AnalysisResult Analyze(FakeEventSource source, AnalyzerInput input) =>
            new Analyzer(source).Analyze(input, null, CancellationToken.None);

        [TestMethod]
        public void ReadsRuleLogsFullyAndOthersByIds()
        {
            var source = new FakeEventSource().WithLogs(EventSamples.Security, EventSamples.System, EventSamples.Application, EventSamples.RdpCore);
            Analyze(source, Input(Rule("R", "Security")));

            Assert.IsNull(source.Requests.Single(r => r.log == "Security").ids, "rule log is read in full");
            CollectionAssert.IsSubsetOf(new[] { 7045, 7031, 41 }, source.Requests.Single(r => r.log == "System").ids.ToList());
            CollectionAssert.IsSubsetOf(new[] { 1000, 833 }, source.Requests.Single(r => r.log == "Application").ids.ToList());
            CollectionAssert.AreEqual(new[] { 131 }, source.Requests.Single(r => r.log == EventSamples.RdpCore).ids.ToList());
        }

        [TestMethod]
        public void SecurityIsReadByIdsWhenNoRuleUsesIt()
        {
            var source = new FakeEventSource().WithLogs(EventSamples.Security);
            Analyze(source, Input());
            CollectionAssert.IsSubsetOf(new[] { 4624, 4625, 1102, 1104 }, source.Requests.Single(r => r.log == "Security").ids.ToList());
        }

        [TestMethod]
        public void MissingLogIsListed()
        {
            var source = new FakeEventSource().WithLogs(EventSamples.Security, EventSamples.System, EventSamples.Application);
            AnalysisResult result = Analyze(source, Input(Rule("R", "Security"), Rule("MSSQL", "Application", "MSSQL-Log")));

            CollectionAssert.Contains(result.LogsMissing.ToList(), "MSSQL-Log");
            CollectionAssert.Contains(result.LogsChecked.ToList(), "Security");
            CollectionAssert.DoesNotContain(result.LogsChecked.ToList(), "MSSQL-Log");
        }

        [TestMethod]
        public void UnreadableLogIsListedNotThrown()
        {
            var source = new FakeEventSource().WithLogs(EventSamples.System);
            source.Unreadable.Add("Security");
            AnalysisResult result = Analyze(source, Input(Rule("R", "Security")));

            CollectionAssert.Contains(result.LogsUnreadable.ToList(), "Security");
            CollectionAssert.Contains(result.LogsChecked.ToList(), "System");
        }

        [TestMethod]
        public void NoRulesSkipsAttacksWithNotice()
        {
            var source = new FakeEventSource().Add(EventSamples.Disk7(Now.AddHours(-1)));
            AnalyzerInput input = Input();
            input.Rules = null;

            AnalysisResult result = Analyze(source, input);

            StringAssert.Contains(result.Notice, "isn't responding");
            Assert.AreEqual(FindingCategory.ServerHealth, result.Findings.Single().Category);
        }

        [TestMethod]
        public void FindingsSortedCriticalFirstAndBanAllBuilt()
        {
            DateTime t = Now.AddHours(-3);
            var source = new FakeEventSource()
                .Add(Enumerable.Range(0, 25).Select(i => EventSamples.Failed4625("88.214.25.121", t.AddSeconds(i * 2))).ToArray())
                .Add(EventSamples.AppCrash1000("tally.exe", t), EventSamples.Disk7(t));

            AnalysisResult result = Analyze(source, Input(Rule("R", "Security")));

            CollectionAssert.AreEqual(
                new[] { FindingSeverity.Critical, FindingSeverity.Warning, FindingSeverity.Info },
                result.Findings.Select(f => f.Severity).ToArray());
            Assert.AreEqual("88.214.25.121", result.BanAllAction.Addresses.Single());
            Assert.IsTrue(result.EventsRead >= 27);
        }

        [TestMethod]
        public void RuleLogEventsAreNotKeptUnlessNeeded()
        {
            // a rule log is read in full, but only rule hits and the IDs other checks need may stay in memory
            DateTime t = Now.AddHours(-6);
            var source = new FakeEventSource()
                .Add(Enumerable.Range(0, 100).Select(i => EventSamples.Other("Security", "Microsoft-Windows-Security-Auditing", 5156, t.AddSeconds(i))).ToArray())
                .Add(Enumerable.Range(0, 7).Select(i => EventSamples.Failed4625("5.175.140.23", t.AddMinutes(i * 24))).ToArray());

            AnalysisResult result = Analyze(source, Input(Rule("R", "Security")));

            Assert.AreEqual(107, result.EventsRead);
            Assert.AreEqual(7, result.EventsKept);
            Assert.AreEqual("5.175.140.23", result.Findings.Single(f => f.Category == FindingCategory.Attack).Address);
        }

        [TestMethod]
        public void SecurityStateIsPassedToChecks()
        {
            DateTime t = Now.AddHours(-2);
            var source = new FakeEventSource()
                .Add(EventSamples.Failed4625("5.175.140.23", t))
                .Add(Enumerable.Range(0, 60).Select(i => EventSamples.RdpConnection131("203.0.113.9:51234", t.AddSeconds(i * 10))).ToArray());
            source.Unreadable.Add("Security");

            AnalysisResult result = Analyze(source, Input(Rule("R", "Security")));
            Assert.IsFalse(result.Findings.Any(f => f.Category == FindingCategory.Attack), "no flood verdict without the Security log");
        }

        [TestMethod]
        public void EventsOutsideTheRangeAreIgnored()
        {
            var source = new FakeEventSource().Add(EventSamples.Disk7(Now.AddDays(-2)));
            Assert.AreEqual(0, Analyze(source, Input()).Findings.Count);
        }

        [TestMethod]
        public void CancellationPropagates()
        {
            var source = new FakeEventSource { EndlessLog = "Security" };
            bool cancelled = false;
            using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
            {
                try
                {
                    new Analyzer(source).Analyze(Input(Rule("R", "Security")), null, cts.Token);
                }
                catch (OperationCanceledException)
                {
                    cancelled = true;
                }
            }
            Assert.IsTrue(cancelled);
        }
    }

    [TestClass]
    public class EventLogSourceTests
    {
        [TestMethod]
        public void ApplicationLogExistsAndReads()
        {
            var source = new EventLogSource();
            Assert.IsTrue(source.LogExists("Application"));
            int count = source.Read("Application", null, DateTime.UtcNow.AddDays(-1), CancellationToken.None).Take(50).Count();
            Assert.IsTrue(count >= 0);
            source.Read("Application", new[] { 1000, 1002 }, DateTime.UtcNow.AddDays(-1), CancellationToken.None).Take(5).ToList()
                .ForEach(e => Assert.IsTrue(e.EventId == 1000 || e.EventId == 1002));
        }

        [TestMethod]
        public void UnknownLogDoesNotExist()
        {
            Assert.IsFalse(new EventLogSource().LogExists("No-Such-Log-EvlWatcher"));
        }
    }
}
