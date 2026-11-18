using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Input;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.MVVMBase;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>
    /// "New rule from an event": paste the event XML, pick the attacker IP, review and save.
    /// Step 3 reuses <see cref="RuleEditorViewModel"/>; the only save the UI sees is <see cref="SaveCommand"/>,
    /// which is gated by the self-test.
    /// </summary>
    public class NewRuleWizardViewModel : GuiObject
    {
        #region private members

        private readonly IRuleClient _client;
        private readonly IList<GenericIPBlockingTaskDTO> _existingRules;
        private readonly Action<string> _onSaved;
        private readonly Action _onCancel;
        private readonly Action<string> _onGoToRule;

        private int _step = 1;
        private string _pastedText;
        private string _parseError;
        private ParsedEvent _event;
        private IReadOnlyList<IpCandidate> _candidates = new List<IpCandidate>();
        private IpCandidate _selectedCandidate;
        private string _coveredByRule;
        private RuleEditorViewModel _draft;
        private bool _selfTestPassed;
        private string _selfTestMessage;

        #endregion

        #region public .ctor

        public NewRuleWizardViewModel(IRuleClient client, IList<GenericIPBlockingTaskDTO> existingRules,
            Action<string> onSaved, Action onCancel, Action<string> onGoToRule = null)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));

            _client = client;
            _existingRules = existingRules ?? new List<GenericIPBlockingTaskDTO>();
            _onSaved = onSaved;
            _onCancel = onCancel;
            _onGoToRule = onGoToRule;

            NextCommand = new RelayCommand(p => Next(), p => CanNext());
            BackCommand = new RelayCommand(p => Back(), p => _step > 1);
            CancelCommand = new RelayCommand(p => _onCancel?.Invoke());
            SaveCommand = new RelayCommand(p => Save(), p => CanSave());
            GoToRuleCommand = new RelayCommand(p => _onGoToRule?.Invoke(_coveredByRule), p => _coveredByRule != null);
            ContinueAnywayCommand = new RelayCommand(p => CoveredByRule = null, p => _coveredByRule != null);
        }

        #endregion

        #region public properties

        /// <summary>1 = paste, 2 = pick the IP, 3 = review and save.</summary>
        public int Step
        {
            get { return _step; }
            private set
            {
                _step = value;
                Notify(nameof(Step));
                Notify(nameof(IsStep1));
                Notify(nameof(IsStep2));
                Notify(nameof(IsStep3));
            }
        }

        public bool IsStep1 { get { return _step == 1; } }

        public bool IsStep2 { get { return _step == 2; } }

        public bool IsStep3 { get { return _step == 3; } }

        public string PastedText
        {
            get { return _pastedText; }
            set
            {
                if (_pastedText == value) return;
                _pastedText = value;
                Notify(nameof(PastedText));
                Reparse();
            }
        }

        /// <summary>Message for text that can't be used; empty while nothing was pasted or the text parses.</summary>
        public string ParseError
        {
            get { return _parseError; }
            private set { _parseError = value; Notify(nameof(ParseError)); }
        }

        public IReadOnlyList<IpCandidate> Candidates
        {
            get { return _candidates; }
            private set { _candidates = value; Notify(nameof(Candidates)); Notify(nameof(NoUsableCandidate)); }
        }

        public IpCandidate SelectedCandidate
        {
            get { return _selectedCandidate; }
            set
            {
                if (ReferenceEquals(_selectedCandidate, value)) return;
                _selectedCandidate = value;
                Notify(nameof(SelectedCandidate));
            }
        }

        /// <summary>True when the event has no IP that could belong to an attacker.</summary>
        public bool NoUsableCandidate
        {
            get { return !_candidates.Any(c => !c.IsLocal); }
        }

        /// <summary>Name of an enabled rule that already finds an IP in the pasted event, or null.</summary>
        public string CoveredByRule
        {
            get { return _coveredByRule; }
            private set { _coveredByRule = value; Notify(nameof(CoveredByRule)); Notify(nameof(IsCovered)); }
        }

        public bool IsCovered { get { return _coveredByRule != null; } }

        public RuleEditorViewModel Draft
        {
            get { return _draft; }
            private set { _draft = value; Notify(nameof(Draft)); }
        }

        public bool SelfTestPassed
        {
            get { return _selfTestPassed; }
            private set { _selfTestPassed = value; Notify(nameof(SelfTestPassed)); }
        }

        public string SelfTestMessage
        {
            get { return _selfTestMessage; }
            private set { _selfTestMessage = value; Notify(nameof(SelfTestMessage)); }
        }

        /// <summary>Message of the last failed save, verbatim from the service.</summary>
        public string SaveError { get { return _draft?.SaveError; } }

        public ICommand NextCommand { get; }

        public ICommand BackCommand { get; }

        public ICommand CancelCommand { get; }

        public ICommand SaveCommand { get; }

        public ICommand GoToRuleCommand { get; }

        public ICommand ContinueAnywayCommand { get; }

        #endregion

        #region private operations

        private void Reparse()
        {
            _event = null;
            if (string.IsNullOrWhiteSpace(_pastedText))
            {
                ParseError = null;
            }
            else if (RuleBuilder.TryParse(_pastedText, out ParsedEvent ev, out string error))
            {
                _event = ev;
                ParseError = null;
            }
            else
            {
                ParseError = error;
            }
        }

        private bool CanNext()
        {
            switch (_step)
            {
                case 1: return _event != null;
                case 2: return _selectedCandidate != null && !_selectedCandidate.IsLocal && _coveredByRule == null;
                default: return false;
            }
        }

        private void Next()
        {
            if (!CanNext()) return;
            if (_step == 1)
                EnterStep2();
            else
                EnterStep3();
        }

        private void Back()
        {
            if (_step == 3)
            {
                DetachDraft();
                Draft = null;
                SelfTestPassed = false;
                SelfTestMessage = null;
            }
            if (_step > 1)
                Step = _step - 1;
        }

        private void EnterStep2()
        {
            Candidates = _event.Candidates;
            var usable = _candidates.Where(c => !c.IsLocal).ToList();
            SelectedCandidate = usable.Count == 1 ? usable[0] : null;
            CoveredByRule = RuleBuilder.FindCoveringRule(_existingRules, _event);
            Step = 2;
        }

        private void EnterStep3()
        {
            var names = new HashSet<string>(_existingRules.Select(r => r.TaskName));
            GenericIPBlockingTaskDTO rule = RuleBuilder.BuildRule(_event, _selectedCandidate, names);
            DetachDraft();
            Draft = new RuleEditorViewModel(_client, rule, true, name => _onSaved?.Invoke(name));
            _draft.Dirtied += RunSelfTest;
            RunSelfTest();
            Step = 3;
        }

        private void DetachDraft()
        {
            if (_draft != null)
                _draft.Dirtied -= RunSelfTest;
        }

        private void RunSelfTest()
        {
            if (_draft == null || _event == null || _selectedCandidate == null)
                return;

            var probe = new GenericIPBlockingTaskDTO
            {
                Regex = _draft.Regex,
                RegexBoosters = (_draft.BoostersText ?? "")
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Trim()).Where(l => l.Length > 0).ToList(),
            };

            bool readsLog = (_draft.EventLogsText ?? "")
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Any(l => string.Equals(l.Trim(), _event.Channel, StringComparison.OrdinalIgnoreCase));
            if (!readsLog)
            {
                SelfTestPassed = false;
                SelfTestMessage = $"This rule doesn't read the {_event.Channel} log your event came from.";
                Notify(nameof(SaveError));
                return;
            }

            bool ok = RuleBuilder.SelfTest(probe, _event, _selectedCandidate.Address);
            SelfTestPassed = ok;
            SelfTestMessage = ok
                ? $"✓ This rule finds {_selectedCandidate.Address} in your event."
                : $"This rule does not find {_selectedCandidate.Address} in your event. Check the booster words and the regex under Advanced.";
            Notify(nameof(SaveError));
        }

        private bool CanSave()
        {
            return _step == 3 && _draft != null && _selfTestPassed && string.IsNullOrEmpty(_draft.FieldError);
        }

        private void Save()
        {
            if (!CanSave()) return;
            _draft.SaveCommand.Execute(null);
            Notify(nameof(SaveError));
        }

        #endregion
    }
}
