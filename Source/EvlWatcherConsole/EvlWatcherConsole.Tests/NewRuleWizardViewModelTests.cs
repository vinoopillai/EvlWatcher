using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Rules;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    [TestClass]
    public class NewRuleWizardViewModelTests
    {
        private static string Sample(string name) =>
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", name));

        private class Harness
        {
            public FakeRuleClient Client = new FakeRuleClient();
            public List<GenericIPBlockingTaskDTO> Existing = new List<GenericIPBlockingTaskDTO>();
            public string Saved;
            public int Cancelled;
            public string WentTo;
            public NewRuleWizardViewModel Vm;

            public Harness()
            {
                Vm = new NewRuleWizardViewModel(Client, Existing, n => Saved = n, () => Cancelled++, n => WentTo = n);
            }

            public void Paste(string sample)
            {
                Vm.PastedText = Sample(sample);
            }
        }

        private static Harness ToStep3()
        {
            var h = new Harness();
            h.Paste("security-4625-pretty.xml");
            h.Vm.NextCommand.Execute(null);
            h.Vm.NextCommand.Execute(null);
            return h;
        }

        [TestMethod]
        public void Step1_NextDisabledUntilParses()
        {
            var h = new Harness();
            Assert.AreEqual(1, h.Vm.Step);
            Assert.IsFalse(h.Vm.NextCommand.CanExecute(null));
            h.Vm.PastedText = "hello";
            Assert.IsFalse(h.Vm.NextCommand.CanExecute(null));
            h.Paste("security-4625-pretty.xml");
            Assert.IsTrue(h.Vm.NextCommand.CanExecute(null));
        }

        [TestMethod]
        public void Step1_InvalidText_ShowsParseError()
        {
            var h = new Harness();
            h.Vm.PastedText = "Log Name: Security";
            Assert.AreEqual(RuleBuilder.ParseErrorMessage, h.Vm.ParseError);
            h.Paste("security-4625-pretty.xml");
            Assert.IsTrue(string.IsNullOrEmpty(h.Vm.ParseError));
        }

        [TestMethod]
        public void Step2_PreselectsSingleUsableCandidate()
        {
            var h = new Harness();
            h.Paste("security-4625-pretty.xml");
            h.Vm.NextCommand.Execute(null);
            Assert.AreEqual(2, h.Vm.Step);
            Assert.IsNotNull(h.Vm.SelectedCandidate);
            Assert.AreEqual("203.0.113.7", h.Vm.SelectedCandidate.Address.ToString());
            Assert.IsFalse(h.Vm.NoUsableCandidate);
            Assert.IsTrue(h.Vm.NextCommand.CanExecute(null));
        }

        [TestMethod]
        public void Step2_FreeTextOnly_NoUsableCandidateAndNextDisabled()
        {
            var h = new Harness();
            h.Paste("freetext-only.xml");
            h.Vm.NextCommand.Execute(null);
            Assert.AreEqual(2, h.Vm.Step);
            Assert.IsTrue(h.Vm.NoUsableCandidate);
            Assert.IsFalse(h.Vm.NextCommand.CanExecute(null));
        }

        [TestMethod]
        public void Step2_CoveredByExistingRule_SetsCoveredByRule()
        {
            var h = new Harness();
            h.Paste("security-4625-pretty.xml");
            RuleBuilder.TryParse(h.Vm.PastedText, out ParsedEvent ev, out _);
            var rule = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            rule.TaskName = "Existing";
            h.Existing.Add(rule);

            h.Vm.NextCommand.Execute(null);
            Assert.AreEqual("Existing", h.Vm.CoveredByRule);

            h.Vm.GoToRuleCommand.Execute(null);
            Assert.AreEqual("Existing", h.WentTo);
        }

        [TestMethod]
        public void Step2_ContinueAnyway_ClearsCoverAndAllowsNext()
        {
            var h = new Harness();
            h.Paste("security-4625-pretty.xml");
            RuleBuilder.TryParse(h.Vm.PastedText, out ParsedEvent ev, out _);
            var rule = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            h.Existing.Add(rule);
            h.Vm.NextCommand.Execute(null);
            Assert.IsFalse(h.Vm.NextCommand.CanExecute(null));
            h.Vm.ContinueAnywayCommand.Execute(null);
            Assert.IsNull(h.Vm.CoveredByRule);
            Assert.IsTrue(h.Vm.NextCommand.CanExecute(null));
            h.Vm.NextCommand.Execute(null);
            Assert.AreEqual(3, h.Vm.Step);
            Assert.AreEqual("Security-Auditing 4625 (2)", h.Vm.Draft.Name);
        }

        [TestMethod]
        public void Step3_PrefillsDraftAndSelfTestPasses()
        {
            var h = ToStep3();
            Assert.AreEqual(3, h.Vm.Step);
            Assert.AreEqual("Security-Auditing 4625", h.Vm.Draft.Name);
            Assert.IsTrue(h.Vm.SelfTestPassed);
            Assert.AreEqual("✓ This rule finds 203.0.113.7 in your event.", h.Vm.SelfTestMessage);
            Assert.IsTrue(h.Vm.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        public void Step3_EditingRegexToNonMatching_FailsSelfTestAndDisablesSave()
        {
            var h = ToStep3();
            h.Vm.Draft.Regex = "<Nope>([0-9.]+)</Nope>";
            Assert.IsFalse(h.Vm.SelfTestPassed);
            Assert.IsFalse(h.Vm.SaveCommand.CanExecute(null));
            Assert.IsFalse(string.IsNullOrEmpty(h.Vm.SelfTestMessage));
        }

        [TestMethod]
        public void Step3_EditingBoostersToNonMatching_FailsSelfTest()
        {
            var h = ToStep3();
            h.Vm.Draft.BoostersText = "NeverInEvent";
            Assert.IsFalse(h.Vm.SelfTestPassed);
            Assert.IsFalse(h.Vm.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        [DataRow("Application")]
        [DataRow("")]
        public void Step3_EventLogNotMatchingChannel_FailsSelfTestAndDisablesSave(string logs)
        {
            var h = ToStep3();
            h.Vm.Draft.EventLogsText = logs;
            Assert.IsFalse(h.Vm.SelfTestPassed);
            Assert.IsFalse(h.Vm.SaveCommand.CanExecute(null));
            Assert.AreEqual("This rule doesn't read the Security log your event came from.", h.Vm.SelfTestMessage);
            h.Vm.Draft.EventLogsText = "application\r\nsecurity";
            Assert.IsTrue(h.Vm.SelfTestPassed);
            Assert.IsTrue(h.Vm.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        public void Step3_InvalidThreshold_DisablesSave()
        {
            var h = ToStep3();
            h.Vm.Draft.AttemptsText = "abc";
            Assert.IsFalse(h.Vm.SaveCommand.CanExecute(null));
        }

        [TestMethod]
        public void Back_ReturnsToPreviousStep()
        {
            var h = ToStep3();
            h.Vm.BackCommand.Execute(null);
            Assert.AreEqual(2, h.Vm.Step);
            h.Vm.BackCommand.Execute(null);
            Assert.AreEqual(1, h.Vm.Step);
            Assert.IsFalse(h.Vm.BackCommand.CanExecute(null));
        }

        [TestMethod]
        public void Save_CallsSaveRuleIsNewAndInvokesOnSavedWithName()
        {
            var h = ToStep3();
            h.Vm.SaveCommand.Execute(null);
            Assert.AreEqual(1, h.Client.Saved.Count);
            Assert.IsTrue(h.Client.Saved[0].IsNew);
            Assert.AreEqual("Security-Auditing 4625", h.Client.Saved[0].Rule.TaskName);
            Assert.AreEqual("Security-Auditing 4625", h.Saved);
        }

        [TestMethod]
        public void Save_ServiceFault_StaysOnStep3WithMessage()
        {
            var h = ToStep3();
            h.Client.FailWith = "EvlWatcher service is not responding.";
            h.Vm.SaveCommand.Execute(null);
            Assert.AreEqual(3, h.Vm.Step);
            Assert.IsNull(h.Saved);
            Assert.AreEqual("EvlWatcher service is not responding.", h.Vm.SaveError);
        }

        [TestMethod]
        public void Cancel_InvokesOnCancel()
        {
            var h = new Harness();
            h.Vm.CancelCommand.Execute(null);
            Assert.AreEqual(1, h.Cancelled);
        }
    }
}
