using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Rules;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    internal class FakeRuleClient : IRuleClient
    {
        public List<GenericIPBlockingTaskDTO> Rules = new List<GenericIPBlockingTaskDTO>();
        public List<(GenericIPBlockingTaskDTO Rule, bool IsNew)> Saved = new List<(GenericIPBlockingTaskDTO, bool)>();
        public List<(string Name, bool Active)> Toggled = new List<(string, bool)>();
        public string FailWith;

        public IList<GenericIPBlockingTaskDTO> GetRules()
        {
            if (FailWith != null) throw new RuleClientException(FailWith);
            return Rules.ToList();
        }

        public void SaveRule(GenericIPBlockingTaskDTO rule, bool isNew)
        {
            if (FailWith != null) throw new RuleClientException(FailWith);
            Saved.Add((rule, isNew));
        }

        public void SetRuleActive(string name, bool active)
        {
            if (FailWith != null) throw new RuleClientException(FailWith);
            Toggled.Add((name, active));
        }
    }

    [TestClass]
    public class RulesViewModelTests
    {
        private static GenericIPBlockingTaskDTO Rule(string name, bool active = true) => new GenericIPBlockingTaskDTO
        {
            TaskName = name,
            Description = "Line one.\nLine two.",
            Active = active,
            TriggerCount = 5,
            EventAge = 120,
            LockTime = 3600,
            PermaBanCount = 3,
            EventPath = new List<string> { "Security" },
            RegexBoosters = new List<string> { "4625" },
            MissingEventLogs = new List<string>(),
            Regex = "(.*)",
        };

        private static (FakeRuleClient, RulesViewModel) Make(params GenericIPBlockingTaskDTO[] rules)
        {
            var client = new FakeRuleClient();
            client.Rules.AddRange(rules);
            var vm = new RulesViewModel(client);
            vm.Refresh();
            return (client, vm);
        }

        [TestMethod]
        public void Refresh_ListsDisabledRulesToo()
        {
            var (_, vm) = Make(Rule("A"), Rule("B", false));
            Assert.AreEqual(2, vm.Rules.Count);
            Assert.IsFalse(vm.Rules[1].IsActive);
        }

        [TestMethod]
        public void ToggleActive_CallsClientAndUpdatesStatus()
        {
            var (client, vm) = Make(Rule("A"));
            vm.Rules[0].IsActive = false;
            Assert.AreEqual(1, client.Toggled.Count);
            Assert.AreEqual(("A", false), client.Toggled[0]);
            Assert.AreEqual("Rule applied. EvlWatcher reloaded its rules.", vm.StatusMessage);
        }

        [TestMethod]
        public void ToggleActive_ServiceFails_RevertsAndShowsError()
        {
            var (client, vm) = Make(Rule("A"));
            client.FailWith = "EvlWatcher service is not responding.";
            vm.Rules[0].IsActive = false;
            Assert.IsTrue(vm.Rules[0].IsActive);
            Assert.AreEqual("EvlWatcher service is not responding.", vm.StatusMessage);
            Assert.AreEqual("EvlWatcher service is not responding.", vm.Rules[0].SaveError);
        }

        [TestMethod]
        public void EditMinutes_ConvertsToSecondsOnSave()
        {
            var (client, vm) = Make(Rule("A"));
            var e = vm.Rules[0];
            Assert.IsFalse(e.IsDirty);
            Assert.AreEqual("2", e.WindowMinutesText);
            Assert.AreEqual("60", e.BanMinutesText);
            e.WindowMinutesText = "3";
            e.BanMinutesText = "90";
            Assert.IsTrue(e.IsDirty);
            e.SaveCommand.Execute(null);
            Assert.AreEqual(1, client.Saved.Count);
            Assert.IsFalse(client.Saved[0].IsNew);
            Assert.AreEqual(180, client.Saved[0].Rule.EventAge);
            Assert.AreEqual(5400, client.Saved[0].Rule.LockTime);
            Assert.IsFalse(e.IsDirty);
        }

        [TestMethod]
        public void EditMinutes_Decimal()
        {
            var (client, vm) = Make(Rule("A"));
            vm.Rules[0].WindowMinutesText = "2";
            vm.Rules[0].BanMinutesText = "60";
            vm.Rules[0].AttemptsText = "7";
            vm.Rules[0].SaveCommand.Execute(null);
            Assert.AreEqual(120, client.Saved[0].Rule.EventAge);
            Assert.AreEqual(3600, client.Saved[0].Rule.LockTime);
            Assert.AreEqual(7, client.Saved[0].Rule.TriggerCount);
        }

        [TestMethod]
        public void NeverPermanent_SavesMinusOne()
        {
            var (client, vm) = Make(Rule("A"));
            vm.Rules[0].NeverPermanent = true;
            vm.Rules[0].SaveCommand.Execute(null);
            Assert.AreEqual(-1, client.Saved[0].Rule.PermaBanCount);
        }

        [TestMethod]
        [DataRow("")]
        [DataRow("abc")]
        [DataRow("-5")]
        public void NonNumericMinutes_DisablesSave(string text)
        {
            var (_, vm) = Make(Rule("A"));
            var e = vm.Rules[0];
            e.WindowMinutesText = text;
            Assert.IsFalse(string.IsNullOrEmpty(e.FieldError));
            Assert.IsFalse(e.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        public void SaveFault_ShowsServiceMessageVerbatim()
        {
            var (client, vm) = Make(Rule("A"));
            var e = vm.Rules[0];
            e.AttemptsText = "9";
            client.FailWith = "Line 1\nLine 2";
            e.SaveCommand.Execute(null);
            Assert.AreEqual("Line 1\nLine 2", e.SaveError);
            Assert.IsTrue(e.IsDirty);
        }

        [TestMethod]
        public void Refresh_KeepsSelectionByName()
        {
            var (_, vm) = Make(Rule("A"), Rule("B"));
            vm.Selected = vm.Rules[1];
            vm.Refresh();
            Assert.AreEqual("B", vm.Selected.Name);
            Assert.AreSame(vm.Rules[1], vm.Selected);
        }

        [TestMethod]
        public void Refresh_SkippedWhileDirty()
        {
            var (_, vm) = Make(Rule("A"));
            Assert.IsFalse(vm.IsBusyEditing);
            vm.Rules[0].AttemptsText = "9";
            Assert.IsTrue(vm.IsBusyEditing);
            vm.Rules[0].DiscardCommand.Execute(null);
            Assert.IsFalse(vm.IsBusyEditing);
            Assert.AreEqual("5", vm.Rules[0].AttemptsText);
        }


        [TestMethod]
        public void FetchThenApply_KeepsSelectionByName()
        {
            var (client, vm) = Make(Rule("A"), Rule("B"));
            vm.Selected = vm.Rules[1];
            var fetched = vm.Fetch(out string error);
            Assert.IsNull(error);
            vm.Apply(fetched, error);
            Assert.AreEqual("B", vm.Selected.Name);
            Assert.AreEqual(2, vm.Rules.Count);
        }

        [TestMethod]
        public void FetchFails_ApplyKeepsListAndShowsStatus()
        {
            var (client, vm) = Make(Rule("A"));
            client.FailWith = "EvlWatcher service is not responding.";
            var fetched = vm.Fetch(out string error);
            Assert.IsNull(fetched);
            vm.Apply(fetched, error);
            Assert.AreEqual(1, vm.Rules.Count);
            Assert.AreEqual("EvlWatcher service is not responding.", vm.StatusMessage);
        }
        [TestMethod]
        public void Refresh_ServiceDown_ShowsMessageAndKeepsList()
        {
            var (client, vm) = Make(Rule("A"));
            client.FailWith = "EvlWatcher service is not responding.";
            vm.Refresh();
            Assert.AreEqual(1, vm.Rules.Count);
            Assert.AreEqual("EvlWatcher service is not responding.", vm.StatusMessage);
        }

        [TestMethod]
        public void NewRuleSaved_SelectsItAndSetsStatus()
        {
            var (client, vm) = Make(Rule("A"));
            vm.NewRuleCommand.Execute(null);
            Assert.IsNotNull(vm.Wizard);
            Assert.IsTrue(vm.IsWizardOpen);
            Assert.IsTrue(vm.IsBusyEditing);

            vm.Wizard.PastedText = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "security-4625-pretty.xml"));
            vm.Wizard.NextCommand.Execute(null);
            vm.Wizard.NextCommand.Execute(null);
            // the fake service stores what was saved, as the real one would
            client.Rules.Add(Rule("Security-Auditing 4625"));
            vm.Wizard.SaveCommand.Execute(null);

            Assert.IsTrue(client.Saved[0].IsNew);
            Assert.IsNull(vm.Wizard);
            Assert.IsFalse(vm.IsWizardOpen);
            Assert.AreEqual("Security-Auditing 4625", vm.Selected.Name);
            Assert.AreEqual("Rule added and active.", vm.StatusMessage);
        }

        [TestMethod]
        public void NewRule_CancelClosesWizard()
        {
            var (_, vm) = Make(Rule("A"));
            vm.NewRuleCommand.Execute(null);
            vm.Wizard.CancelCommand.Execute(null);
            Assert.IsNull(vm.Wizard);
            Assert.IsFalse(vm.IsWizardOpen);
        }

        [TestMethod]
        public void NewRule_GoToRuleSelectsCoveringRule()
        {
            var (client, vm) = Make(Rule("A"));
            RuleBuilder.TryParse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "security-4625-pretty.xml")), out ParsedEvent ev, out _);
            var covering = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            covering.TaskName = "Covering";
            client.Rules.Add(covering);
            vm.Refresh();

            vm.NewRuleCommand.Execute(null);
            vm.Wizard.PastedText = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "security-4625-pretty.xml"));
            vm.Wizard.NextCommand.Execute(null);
            vm.Wizard.GoToRuleCommand.Execute(null);

            Assert.IsNull(vm.Wizard);
            Assert.IsFalse(vm.IsWizardOpen);
            Assert.AreEqual("Covering", vm.Selected.Name);
        }

        [TestMethod]
        public void NewRule_ServiceDown_DoesNotOpenWizard()
        {
            var (client, vm) = Make(Rule("A"));
            client.FailWith = "EvlWatcher service is not responding.";
            vm.NewRuleCommand.Execute(null);
            Assert.IsNull(vm.Wizard);
            Assert.AreEqual("EvlWatcher service is not responding.", vm.StatusMessage);
        }

        [TestMethod]
        public void NewRule_ToggleDoesNotCallClient_AndSavesAsNew()
        {
            var client = new FakeRuleClient();
            string saved = null;
            var e = new RuleEditorViewModel(client, Rule("N"), true, n => saved = n);
            e.IsActive = false;
            Assert.AreEqual(0, client.Toggled.Count);
            e.SaveCommand.Execute(null);
            Assert.IsTrue(client.Saved[0].IsNew);
            Assert.IsFalse(client.Saved[0].Rule.Active);
            Assert.AreEqual("N", saved);
        }

        [TestMethod]
        public void SavingOneRule_KeepsOtherRulesDirtyEdits()
        {
            var (client, vm) = Make(Rule("A"), Rule("B"));
            vm.Rules[0].AttemptsText = "9";
            vm.Selected = vm.Rules[1];
            vm.Rules[1].AttemptsText = "8";
            vm.Rules[1].SaveCommand.Execute(null);

            var a = vm.Rules.First(r => r.Name == "A");
            Assert.IsTrue(a.IsDirty);
            Assert.AreEqual("9", a.AttemptsText);
        }

        [TestMethod]
        public void FetchErrorStatus_ClearedAfterSuccessfulFetch()
        {
            var (client, vm) = Make(Rule("A"));
            client.FailWith = "EvlWatcher service is not responding.";
            vm.Refresh();
            Assert.AreEqual("EvlWatcher service is not responding.", vm.StatusMessage);
            client.FailWith = null;
            vm.Refresh();
            Assert.IsNull(vm.StatusMessage);
        }

        [TestMethod]
        public void EmptyListMessage_BeforeFirstFetch_SaysLoading()
        {
            var vm = new RulesViewModel(new FakeRuleClient());
            Assert.AreEqual("Loading rules…", vm.EmptyListMessage);
        }

        [TestMethod]
        public void EmptyListMessage_ServiceNotResponding_SaysSo()
        {
            var vm = new RulesViewModel(new FakeRuleClient());
            string changed = null;
            vm.PropertyChanged += (s, e) => { if (e.PropertyName == nameof(RulesViewModel.EmptyListMessage)) changed = e.PropertyName; };
            vm.ServiceResponding = false;
            Assert.AreEqual("No rules loaded. The EvlWatcher service isn't responding.", vm.EmptyListMessage);
            Assert.IsNotNull(changed);
        }

        [TestMethod]
        public void EmptyListMessage_FetchedOkButEmpty_SaysNoRulesConfigured()
        {
            var (_, vm) = Make();
            Assert.AreEqual("No rules are configured.", vm.EmptyListMessage);
            vm.ServiceResponding = false;
            Assert.AreEqual("No rules loaded. The EvlWatcher service isn't responding.", vm.EmptyListMessage);
            vm.ServiceResponding = true;
            Assert.AreEqual("No rules are configured.", vm.EmptyListMessage);
        }

        [TestMethod]
        public void EmptyListMessage_FetchFailed_SaysNotResponding()
        {
            var client = new FakeRuleClient { FailWith = "EvlWatcher service is not responding." };
            var vm = new RulesViewModel(client);
            vm.Refresh();
            Assert.AreEqual("No rules loaded. The EvlWatcher service isn't responding.", vm.EmptyListMessage);
        }

        [TestMethod]
        public void OpenWizardFetchError_ClearedAfterNextSuccessfulApply()
        {
            var (client, vm) = Make(Rule("A"));
            client.FailWith = "EvlWatcher service is not responding.";
            vm.NewRuleCommand.Execute(null);
            Assert.AreEqual("EvlWatcher service is not responding.", vm.StatusMessage);
            Assert.IsNull(vm.Wizard);

            client.FailWith = null;
            vm.Refresh();

            Assert.IsNull(vm.StatusMessage);
        }

        [TestMethod]
        public void LegacyPermaBanCountZero_ShowsEmptyFieldAndAsksForChoice()
        {
            var r = Rule("A"); r.PermaBanCount = 0;
            var (_, vm) = Make(r);
            Assert.AreEqual("", vm.Rules[0].PermanentAfterText);
            Assert.IsFalse(vm.Rules[0].IsDirty);
            Assert.IsFalse(string.IsNullOrEmpty(vm.Rules[0].FieldError));
        }

        [TestMethod]
        public void Save_TrimsTaskNameForCallback()
        {
            var client = new FakeRuleClient();
            var vm = new RulesViewModel(client);
            var r = Rule("  Padded  ");
            client.Rules.Add(r);
            vm.Refresh();
            vm.Rules[0].AttemptsText = "9";
            vm.Rules[0].SaveCommand.Execute(null);
            Assert.AreEqual("Padded", client.Saved[0].Rule.TaskName);
        }
    }
}
