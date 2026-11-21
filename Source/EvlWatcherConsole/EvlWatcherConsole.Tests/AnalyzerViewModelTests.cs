using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Analysis;
using EvlWatcherConsole.Rules;
using EvlWatcherConsole.Tests.Analysis;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    internal sealed class FakeAnalyzerClient : IAnalyzerClient
    {
        public List<GenericIPBlockingTaskDTO> Rules = new List<GenericIPBlockingTaskDTO>();
        public string FailWith;
        public bool FailOnlyActions;
        public readonly List<IList<string>> Bans = new List<IList<string>>();
        public readonly List<GenericIPBlockingTaskDTO> Saved = new List<GenericIPBlockingTaskDTO>();

        private void MaybeFail(bool isAction)
        {
            if (FailWith != null && (isAction || !FailOnlyActions))
                throw new RuleClientException(FailWith);
        }

        public IList<GenericIPBlockingTaskDTO> GetRules() { MaybeFail(false); return Rules.Select(Copy).ToList(); }
        public IList<string> GetWhiteListPatterns() { MaybeFail(false); return new List<string>(); }
        public IList<string> GetTemporarilyBannedIPs() { MaybeFail(false); return new List<string>(); }
        public IList<string> GetPermanentlyBannedIPs() { MaybeFail(false); return new List<string>(); }
        public void BanPermanently(IList<string> addresses) { MaybeFail(true); Bans.Add(addresses.ToList()); }
        public void SaveRule(GenericIPBlockingTaskDTO rule) { MaybeFail(true); Saved.Add(rule); }

        private static GenericIPBlockingTaskDTO Copy(GenericIPBlockingTaskDTO r) => new GenericIPBlockingTaskDTO
        {
            TaskName = r.TaskName, Active = r.Active, TriggerCount = r.TriggerCount, EventAge = r.EventAge, LockTime = r.LockTime,
            PermaBanCount = r.PermaBanCount, EventPath = r.EventPath.ToList(), RegexBoosters = r.RegexBoosters.ToList(), Regex = r.Regex,
            Description = r.Description
        };
    }

    internal sealed class FakeConfirmer : IConfirmer
    {
        public bool Answer = true;
        public readonly List<string> Asked = new List<string>();

        public bool Confirm(string title, string message)
        {
            Asked.Add(message);
            return Answer;
        }
    }

    [TestClass]
    public class AnalyzerViewModelTests
    {
        private static readonly DateTime Now = EventSamples.Utc("2026-11-21T00:30:00Z");

        private static readonly string[] SlowTimes =
        {
            "2026-11-20T18:36:28Z", "2026-11-20T19:00:47Z", "2026-11-20T19:25:03Z", "2026-11-20T19:49:16Z",
            "2026-11-20T20:13:36Z", "2026-11-20T20:37:53Z", "2026-11-20T21:04:53Z"
        };

        private static GenericIPBlockingTaskDTO Rule() => new GenericIPBlockingTaskDTO
        {
            TaskName = "BlockRDPBrutersBySecurity4625", Active = true, TriggerCount = 5, EventAge = 3600, LockTime = 3600,
            PermaBanCount = 3, EventPath = new List<string> { "Security" }, RegexBoosters = new List<string> { "4625", "IpAddress" },
            Regex = @"<Data Name=.IpAddress.>(\d*.\d*.\d*.\d*)"
        };

        private sealed class Harness
        {
            public FakeAnalyzerClient Client = new FakeAnalyzerClient();
            public FakeEventSource Source = new FakeEventSource();
            public FakeConfirmer Confirmer = new FakeConfirmer();
            private AnalyzerViewModel _vm;

            public AnalyzerViewModel Vm => _vm ?? (_vm = new AnalyzerViewModel(Client, Source, Confirmer, () => Now, () => new HashSet<string> { "127.0.0.1" }));

            public Harness WithSlowAttacker()
            {
                Client.Rules.Add(Rule());
                Source.Add(SlowTimes.Select(t => EventSamples.Failed4625("5.175.140.23", EventSamples.Utc(t))).ToArray());
                Source.Add(EventSamples.Disk7(Now.AddHours(-1)));
                return this;
            }
        }

        private static void Run(FindingViewModel finding, string labelStart) =>
            finding.Actions.Single(a => a.Label.StartsWith(labelStart, StringComparison.Ordinal)).Command.Execute(null);

        [TestMethod]
        public void DefaultRangeIs24Hours()
        {
            var h = new Harness();
            Assert.AreEqual(AnalysisRange.Last24Hours, h.Vm.SelectedRange);
            Assert.AreEqual(3, h.Vm.Ranges.Count);
            Assert.IsFalse(h.Vm.HasScanned);
        }

        [TestMethod]
        public async Task ScanFillsFindingsAndSummary()
        {
            var h = new Harness().WithSlowAttacker();
            await h.Vm.ScanAsync();

            Assert.IsTrue(h.Vm.HasScanned);
            Assert.IsFalse(h.Vm.IsScanning);
            Assert.AreEqual(2, h.Vm.Findings.Count);
            Assert.AreEqual("Critical", h.Vm.Findings[0].SeverityText);
            StringAssert.Contains(h.Vm.SummaryText, "1 critical");
            StringAssert.Contains(h.Vm.SummaryText, "Last 24 hours");
            Assert.IsTrue(h.Vm.BanAllCommand.CanExecute(null));
        }

        [TestMethod]
        public async Task CancelStopsScanAndShowsCancelled()
        {
            var h = new Harness();
            h.Source.EndlessLog = "Security";

            Task scan = h.Vm.ScanAsync();
            await Task.Delay(200);
            Assert.IsTrue(h.Vm.IsScanning);
            h.Vm.CancelCommand.Execute(null);

            var watch = Stopwatch.StartNew();
            await Task.WhenAny(scan, Task.Delay(2000));
            Assert.IsTrue(scan.IsCompleted, "scan did not stop within 2 s");
            Assert.IsTrue(watch.ElapsedMilliseconds < 2000);
            Assert.IsFalse(h.Vm.IsScanning);
            Assert.AreEqual("Scan cancelled.", h.Vm.ProgressText);
        }

        [TestMethod]
        public async Task ServiceDownStillShowsOtherGroups()
        {
            var h = new Harness().WithSlowAttacker();
            h.Client.FailWith = "EvlWatcher service is not responding.";

            await h.Vm.ScanAsync();

            StringAssert.Contains(h.Vm.NoticeText, "isn't responding");
            Assert.AreEqual("Server health", h.Vm.Findings.Single().CategoryText);
        }

        [TestMethod]
        public async Task ActionNotRunWhenNotConfirmed()
        {
            var h = new Harness().WithSlowAttacker();
            await h.Vm.ScanAsync();
            h.Confirmer.Answer = false;

            Run(h.Vm.Findings.Single(f => f.Title.Contains("5.175.140.23")), "Ban permanently");

            Assert.AreEqual(1, h.Confirmer.Asked.Count);
            Assert.AreEqual(0, h.Client.Bans.Count);
            Assert.IsFalse(h.Vm.Findings.Any(f => f.IsDone));
        }

        [TestMethod]
        public async Task BanMarksFindingDone()
        {
            var h = new Harness().WithSlowAttacker();
            await h.Vm.ScanAsync();

            FindingViewModel f = h.Vm.Findings.Single(x => x.Title.Contains("5.175.140.23"));
            Run(f, "Ban permanently");

            CollectionAssert.AreEqual(new[] { "5.175.140.23" }, h.Client.Bans.Single().ToArray());
            Assert.IsTrue(f.IsDone);
        }

        [TestMethod]
        public async Task BanAllSendsOneCall()
        {
            var h = new Harness().WithSlowAttacker();
            h.Source.Add(SlowTimes.Select(t => EventSamples.Failed4625("94.203.133.74", EventSamples.Utc(t).AddSeconds(5))).ToArray());
            await h.Vm.ScanAsync();

            h.Vm.BanAllCommand.Execute(null);

            Assert.AreEqual(1, h.Client.Bans.Count);
            Assert.AreEqual(2, h.Client.Bans[0].Count);
            Assert.IsTrue(h.Vm.Findings.Where(f => f.Title.Contains("tried")).All(f => f.IsDone));
        }

        [TestMethod]
        public async Task WidenUpdatesRuleWindowAndLockTime()
        {
            var h = new Harness().WithSlowAttacker();
            await h.Vm.ScanAsync();

            Run(h.Vm.Findings.Single(f => f.Title.Contains("5.175.140.23")), "Widen rule window");

            GenericIPBlockingTaskDTO saved = h.Client.Saved.Single();
            Assert.AreEqual("BlockRDPBrutersBySecurity4625", saved.TaskName);
            Assert.AreEqual(21600, saved.EventAge);
            Assert.AreEqual(21600, saved.LockTime);
            Assert.AreEqual(5, saved.TriggerCount);
        }

        [TestMethod]
        public async Task FailedActionShowsErrorAndStaysOpen()
        {
            var h = new Harness().WithSlowAttacker();
            await h.Vm.ScanAsync();
            h.Client.FailWith = "EvlWatcher service is not responding.";
            h.Client.FailOnlyActions = true;

            FindingViewModel f = h.Vm.Findings.Single(x => x.Title.Contains("5.175.140.23"));
            Run(f, "Ban permanently");

            Assert.AreEqual("EvlWatcher service is not responding.", f.Error);
            Assert.IsFalse(f.IsDone);
        }
    }
}
