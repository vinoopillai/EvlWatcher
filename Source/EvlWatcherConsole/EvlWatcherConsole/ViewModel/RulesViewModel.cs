using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.MVVMBase;
using System.Windows.Input;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>
    /// The Rules tab: list of rules, the selected rule's editor and a status line.
    /// Has no UI-thread dependency; the caller marshals Refresh() if needed.
    /// </summary>
    public class RulesViewModel : GuiObject
    {
        #region private members

        private readonly IRuleClient _client;
        private RuleEditorViewModel _selected;
        private string _statusMessage;
        private bool _isWizardOpen;
        private NewRuleWizardViewModel _wizard;
        private string _lastFetchError;
        private bool _hasFetched;
        private bool _serviceResponding = true;

        #endregion

        #region public .ctor

        public RulesViewModel(IRuleClient client)
        {
            _client = client;
            NewRuleCommand = new RelayCommand(p => OpenWizard(), p => _wizard == null);
        }

        #endregion

        #region public properties

        public ObservableCollection<RuleEditorViewModel> Rules { get; } = new ObservableCollection<RuleEditorViewModel>();

        public RuleEditorViewModel Selected
        {
            get { return _selected; }
            set
            {
                if (ReferenceEquals(_selected, value)) return;
                _selected = value;
                Notify(nameof(Selected));
                Notify(nameof(HasSelection));
                Notify(nameof(ShowDetails)); Notify(nameof(ShowSelectHint));
            }
        }

        public bool HasSelection { get { return _selected != null; } }

        /// <summary>The new-rule wizard while it is open (the details pane shows it instead of the selected rule), otherwise null.</summary>
        public NewRuleWizardViewModel Wizard
        {
            get { return _wizard; }
            private set
            {
                _wizard = value;
                Notify(nameof(Wizard));
                Notify(nameof(HasWizard));
                Notify(nameof(ShowDetails)); Notify(nameof(ShowSelectHint));
            }
        }

        public bool HasWizard { get { return _wizard != null; } }

        /// <summary>True when the selected rule's editor should be shown.</summary>
        public bool ShowDetails { get { return _wizard == null && _selected != null; } }

        /// <summary>True when the details pane has nothing to show (no rule selected, wizard closed).</summary>
        public bool ShowSelectHint { get { return _wizard == null && _selected == null; } }

        /// <summary>Set by the main view model on every tick: false while the service isn't responding.</summary>
        public bool ServiceResponding
        {
            get { return _serviceResponding; }
            set
            {
                if (_serviceResponding == value) return;
                _serviceResponding = value;
                Notify(nameof(ServiceResponding));
                Notify(nameof(EmptyListMessage));
            }
        }

        /// <summary>What the empty rules list says: not responding, still loading, or really no rules.</summary>
        public string EmptyListMessage
        {
            get
            {
                if (!_serviceResponding || _lastFetchError != null)
                    return "No rules loaded. The EvlWatcher service isn't responding.";
                if (!_hasFetched)
                    return "Loading rules…";
                return "No rules are configured.";
            }
        }

        public ICommand NewRuleCommand { get; }

        public string StatusMessage
        {
            get { return _statusMessage; }
            set { _statusMessage = value; Notify(nameof(StatusMessage)); }
        }

        /// <summary>Set by the new-rule wizard while it is open.</summary>
        public bool IsWizardOpen
        {
            get { return _isWizardOpen; }
            set { _isWizardOpen = value; Notify(nameof(IsWizardOpen)); Notify(nameof(IsBusyEditing)); }
        }

        /// <summary>True while an editor has unsaved changes or the wizard is open. Callers skip Refresh() then.</summary>
        public bool IsBusyEditing
        {
            get { return _isWizardOpen || Rules.Any(r => r.IsDirty); }
        }

        #endregion

        #region public operations

        /// <summary>Reloads the list from the service and keeps the selection by name (synchronous).</summary>
        public void Refresh()
        {
            IList<GenericIPBlockingTaskDTO> rules = Fetch(out string error);
            Apply(rules, error);
        }

        /// <summary>
        /// Asks the service for the rules. Touches no UI-bound state, so it may run on a background thread.
        /// Returns null and sets <paramref name="error"/> when the service can't be reached.
        /// </summary>
        public IList<GenericIPBlockingTaskDTO> Fetch(out string error)
        {
            try
            {
                error = null;
                return _client.GetRules();
            }
            catch (RuleClientException ex)
            {
                error = ex.Message;
                return null;
            }
        }

        /// <summary>
        /// Applies a fetched result to the list (must run on the UI thread). A null result keeps the list and shows the error.
        /// </summary>
        public void Apply(IList<GenericIPBlockingTaskDTO> rules, string error)
        {
            if (rules == null)
            {
                if (error != null) SetFetchError(error);
                return;
            }

            _hasFetched = true;
            if (_lastFetchError != null)
            {
                if (StatusMessage == _lastFetchError) StatusMessage = null;
                _lastFetchError = null;
            }
            Notify(nameof(EmptyListMessage));

            string selectedName = _selected?.Name;
            // Keep unchanged editors as they are, so the periodic refresh doesn't reset the UI (expanders, scroll, focus).
            var fresh = new List<RuleEditorViewModel>();
            foreach (var r in rules)
            {
                var editor = Rules.FirstOrDefault(e => e.Name == r.TaskName && (e.IsDirty || e.IsUnchangedFrom(r)));
                if (editor == null)
                {
                    editor = new RuleEditorViewModel(_client, r, false, OnSaved);
                    editor.StatusReported += s => StatusMessage = s;
                    editor.Dirtied += () => Notify(nameof(IsBusyEditing));
                }
                fresh.Add(editor);
            }

            if (!fresh.SequenceEqual(Rules))
            {
                Rules.Clear();
                foreach (var editor in fresh)
                    Rules.Add(editor);
            }

            Selected = Rules.FirstOrDefault(r => r.Name == selectedName);
            Notify(nameof(IsBusyEditing));
        }

        #endregion

        #region private operations

        private void SetFetchError(string error)
        {
            _lastFetchError = error;
            StatusMessage = error;
            Notify(nameof(EmptyListMessage));
        }

        private void OpenWizard()
        {
            IList<GenericIPBlockingTaskDTO> rules = Fetch(out string error);
            if (rules == null)
            {
                if (error != null) SetFetchError(error);
                return;
            }

            IsWizardOpen = true;
            Wizard = new NewRuleWizardViewModel(_client, rules, OnWizardSaved, CloseWizard, OnWizardGoToRule);
        }

        private void CloseWizard()
        {
            Wizard = null;
            IsWizardOpen = false;
        }

        private void OnWizardSaved(string name)
        {
            CloseWizard();
            Refresh();
            Selected = Rules.FirstOrDefault(r => r.Name == name) ?? Selected;
            StatusMessage = "Rule added and active.";
        }

        private void OnWizardGoToRule(string name)
        {
            CloseWizard();
            Refresh();
            Selected = Rules.FirstOrDefault(r => r.Name == name) ?? Selected;
        }

        private void OnSaved(string name)
        {
            Refresh();
            Selected = Rules.FirstOrDefault(r => r.Name == name) ?? Selected;
            StatusMessage = "Rule saved. EvlWatcher reloaded its rules.";
        }

        #endregion
    }
}
