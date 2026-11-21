using System.Collections.Generic;
using System.Linq;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Rules;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    [TestClass]
    public class CountryOptionTests
    {
        private static GenericIPBlockingTaskDTO Rule(params string[] countries) => new GenericIPBlockingTaskDTO
        {
            TaskName = "BlockRDPBrutersBySecurity4625", Description = "d", Active = true, TriggerCount = 5, EventAge = 3600,
            LockTime = 3600, PermaBanCount = 3, EventPath = new List<string> { "Security" },
            RegexBoosters = new List<string> { "4625" }, Regex = "(x)", AllowedCountries = countries.ToList()
        };

        private static RuleEditorViewModel Editor(FakeRuleClient client, GenericIPBlockingTaskDTO rule) =>
            new RuleEditorViewModel(client, rule, false, _ => { });

        [TestMethod]
        public void LoadsExistingCountries()
        {
            RuleEditorViewModel e = Editor(new FakeRuleClient(), Rule("IN"));
            Assert.IsTrue(e.RestrictCountries);
            Assert.AreEqual("IN", e.AllowedCountriesText);
            Assert.AreEqual("India", e.CountryNamesText);
            Assert.IsTrue(e.ShowCountryOption);
            Assert.IsFalse(e.IsDirty);
        }

        [TestMethod]
        public void ShowsCountryNames()
        {
            RuleEditorViewModel e = Editor(new FakeRuleClient(), Rule());
            e.RestrictCountries = true;
            e.AllowedCountriesText = "in, ae";
            Assert.AreEqual("India, United Arab Emirates", e.CountryNamesText);
            Assert.AreEqual("", e.CountryError);
        }

        [TestMethod]
        public void UnknownCodeBlocksSave()
        {
            RuleEditorViewModel e = Editor(new FakeRuleClient(), Rule());
            e.RestrictCountries = true;
            e.AllowedCountriesText = "IN, XX";
            Assert.AreEqual("Unknown country code: XX", e.CountryError);
            Assert.IsFalse(e.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        public void TickedWithoutCodesBlocksSave()
        {
            RuleEditorViewModel e = Editor(new FakeRuleClient(), Rule());
            e.RestrictCountries = true;
            StringAssert.Contains(e.CountryError, "e.g. IN");
            Assert.IsFalse(e.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        public void SaveSendsCodes()
        {
            var client = new FakeRuleClient();
            RuleEditorViewModel e = Editor(client, Rule());
            e.RestrictCountries = true;
            e.AllowedCountriesText = "in";
            e.SaveCommand.Execute(null);
            CollectionAssert.AreEqual(new[] { "IN" }, client.Saved.Single().Rule.AllowedCountries.ToArray());
        }

        [TestMethod]
        public void UntickedSavesEmptyList()
        {
            var client = new FakeRuleClient();
            RuleEditorViewModel e = Editor(client, Rule("IN"));
            e.RestrictCountries = false;
            Assert.IsTrue(e.IsDirty);
            e.SaveCommand.Execute(null);
            Assert.AreEqual(0, client.Saved.Single().Rule.AllowedCountries.Count);
        }

        [TestMethod]
        public void NewRuleHidesTheOption()
        {
            Assert.IsFalse(new RuleEditorViewModel(new FakeRuleClient(), Rule(), true, _ => { }).ShowCountryOption);
        }

        [TestMethod]
        public void NotLoadedShowsHint()
        {
            var client = new FakeRuleClient { Rules = { Rule("IN") }, CountryStatus = new CountryDataStatusDTO { Loaded = false } };
            var rules = new RulesViewModel(client);
            rules.Refresh();
            Assert.IsTrue(rules.Rules.Single().CountryDataUnavailable);

            client.CountryStatus = new CountryDataStatusDTO { Loaded = true };
            rules.Refresh();
            Assert.IsFalse(rules.Rules.Single().CountryDataUnavailable);
        }

        [TestMethod]
        public void NoteExplainsRegistrationAndTemporaryBans()
        {
            string note = Editor(new FakeRuleClient(), Rule("IN")).CountryNote;
            StringAssert.Contains(note, "registered");
            StringAssert.Contains(note, "whitelist");
            StringAssert.Contains(note, "temporary");
        }
    }
}
