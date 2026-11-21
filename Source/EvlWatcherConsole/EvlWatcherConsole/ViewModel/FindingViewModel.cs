using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Input;
using EvlWatcherConsole.Analysis;
using EvlWatcherConsole.MVVMBase;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>One finding card on the Analyzer tab.</summary>
    public sealed class FindingViewModel : GuiObject
    {
        #region private members

        private bool _isDone;
        private string _error = "";

        #endregion

        #region constructor

        public FindingViewModel(Finding finding, Action<FindingViewModel, ActionViewModel> execute)
        {
            Model = finding;
            Actions = finding.Actions.Select(a => new ActionViewModel(this, a, execute)).ToList();
        }

        #endregion

        #region public properties

        public Finding Model { get; }

        public string SeverityText => Model.Severity.ToString();

        public FindingSeverity Severity => Model.Severity;

        public string CategoryText
        {
            get
            {
                switch (Model.Category)
                {
                    case FindingCategory.Attack: return "Attack";
                    case FindingCategory.SecurityChange: return "Security change";
                    default: return "Server health";
                }
            }
        }

        public string Title => Model.Title;

        public string Details => Model.Details;

        public string Advice => Model.Advice;

        public IList<ActionViewModel> Actions { get; }

        public bool HasActions => Actions.Count > 0;

        /// <summary>True once the finding was handled (its address was banned).</summary>
        public bool IsDone
        {
            get { return _isDone; }
            set
            {
                if (_isDone == value)
                    return;
                _isDone = value;
                Notify(nameof(IsDone));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public string Error
        {
            get { return _error; }
            set
            {
                _error = value ?? "";
                Notify(nameof(Error));
            }
        }

        #endregion
    }

    /// <summary>One action button on a finding card.</summary>
    public sealed class ActionViewModel : GuiObject
    {
        private bool _isDone;

        public ActionViewModel(FindingViewModel owner, FindingAction action, Action<FindingViewModel, ActionViewModel> execute)
        {
            Owner = owner;
            Action = action;
            Command = new RelayCommand(_ => execute(owner, this), _ => !IsDone && !owner.IsDone);
        }

        public FindingViewModel Owner { get; }

        public FindingAction Action { get; }

        public string Label => Action.Label;

        public ICommand Command { get; }

        public bool IsDone
        {
            get { return _isDone; }
            set
            {
                if (_isDone == value)
                    return;
                _isDone = value;
                Notify(nameof(IsDone));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
}
