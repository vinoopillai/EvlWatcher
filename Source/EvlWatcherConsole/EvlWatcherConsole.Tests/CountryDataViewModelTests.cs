using System;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    [TestClass]
    public class CountryDataViewModelTests
    {
        private static FakeRuleClient Client() => new FakeRuleClient
        {
            CountryStatus = new CountryDataStatusDTO
            {
                Loaded = true,
                RangeCount = 312000,
                UpdatedUtc = new DateTime(2026, 11, 21, 6, 0, 0, DateTimeKind.Utc),
                Registries = new[] { "APNIC", "RIPENCC", "ARIN", "LACNIC", "AFRINIC" },
                AutoUpdate = true
            }
        };

        [TestMethod]
        public void StatusTextShowsDateCountAndRegistries()
        {
            var vm = new CountryDataViewModel(Client());
            vm.Refresh();
            StringAssert.Contains(vm.StatusText, new DateTime(2026, 11, 21, 6, 0, 0, DateTimeKind.Utc).ToLocalTime().ToString("d"));
            StringAssert.Contains(vm.StatusText, 312000.ToString("N0"));
            StringAssert.Contains(vm.StatusText, "APNIC, RIPENCC, ARIN, LACNIC, AFRINIC");
            Assert.IsTrue(vm.AutoUpdate);
            Assert.AreEqual("", vm.Error);
        }

        [TestMethod]
        public void LastProblemIsShown()
        {
            FakeRuleClient client = Client();
            client.CountryStatus.LastError = "LACNIC: download failed";
            var vm = new CountryDataViewModel(client);
            vm.Refresh();
            StringAssert.Contains(vm.StatusText, "Last update problem: LACNIC: download failed");
        }

        [TestMethod]
        public void NotLoadedText()
        {
            var vm = new CountryDataViewModel(new FakeRuleClient { CountryStatus = new CountryDataStatusDTO { Loaded = false } });
            vm.Refresh();
            StringAssert.StartsWith(vm.StatusText, "Country data isn't loaded.");
        }

        [TestMethod]
        public void UpdateNowCallsService()
        {
            FakeRuleClient client = Client();
            var vm = new CountryDataViewModel(client);
            vm.UpdateNowCommand.Execute(null);
            Assert.AreEqual(1, client.UpdateNowCalls);
            StringAssert.Contains(vm.StatusText, "Updating");
        }

        [TestMethod]
        public void AutoUpdateToggleCallsService()
        {
            FakeRuleClient client = Client();
            var vm = new CountryDataViewModel(client);
            vm.Refresh();
            vm.AutoUpdate = false;
            CollectionAssert.AreEqual(new[] { false }, client.AutoUpdateCalls);
        }

        [TestMethod]
        public void RefreshDoesNotCallSetter()
        {
            FakeRuleClient client = Client();
            new CountryDataViewModel(client).Refresh();
            Assert.AreEqual(0, client.AutoUpdateCalls.Count);
        }

        [TestMethod]
        public void ServiceDownShowsError()
        {
            var vm = new CountryDataViewModel(new FakeRuleClient { FailWith = "EvlWatcher service is not responding." });
            vm.Refresh();
            Assert.AreEqual("EvlWatcher service is not responding.", vm.Error);
        }
    }
}
