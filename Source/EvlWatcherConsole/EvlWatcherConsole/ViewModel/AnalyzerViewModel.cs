using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Analysis;
using EvlWatcherConsole.MVVMBase;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>
    /// The Analyzer tab: scans the event logs in the background (cancellable), shows the findings and runs their
    /// actions after a confirmation.
    /// </summary>
    public sealed class AnalyzerViewModel : GuiObject
    {
        #region private members

        private readonly IAnalyzerClient _client;
        private readonly IEventSource _source;
        private readonly IConfirmer _confirmer;
        private readonly Func<DateTime> _utcNow;
        private readonly Func<ISet<string>> _localAddresses;

        private AnalysisRange _selectedRange = AnalysisRange.Last24Hours;
        private bool _isScanning;
        private bool _hasScanned;
        private string _progressText = "";
        private string _summaryText = "";
        private string _noticeText = "";
        private string _logsText = "";
        private string _actionError = "";
        private FindingAction _banAll;
        private CancellationTokenSource _cts;

        #endregion

        #region constructor

        public AnalyzerViewModel(IAnalyzerClient client, IEventSource source, IConfirmer confirmer, Func<DateTime> utcNow, Func<ISet<string>> localAddresses)
        {
            _client = client;
            _source = source;
            _confirmer = confirmer;
            _utcNow = utcNow;
            _localAddresses = localAddresses;

            ScanCommand = new RelayCommand(async _ => await ScanAsync(), _ => !IsScanning);
            CancelCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsScanning);
            BanAllCommand = new RelayCommand(_ => ExecuteBanAll(), _ => _banAll != null && !IsScanning);
        }

        #endregion

        #region public properties

        public IList<AnalysisRange> Ranges { get; } = new List<AnalysisRange> { AnalysisRange.Last24Hours, AnalysisRange.Last7Days, AnalysisRange.Last30Days };

        public AnalysisRange SelectedRange
        {
            get { return _selectedRange; }
            set
            {
                _selectedRange = value;
                Notify(nameof(SelectedRange));
                Notify(nameof(EmptyText));
            }
        }

        public ObservableCollection<FindingViewModel> Findings { get; } = new ObservableCollection<FindingViewModel>();

        public bool IsScanning
        {
            get { return _isScanning; }
            private set
            {
                _isScanning = value;
                Notify(nameof(IsScanning));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public bool HasScanned
        {
            get { return _hasScanned; }
            private set
            {
                _hasScanned = value;
                Notify(nameof(HasScanned));
                Notify(nameof(EmptyText));
            }
        }

        public string ProgressText
        {
            get { return _progressText; }
            private set { _progressText = value; Notify(nameof(ProgressText)); }
        }

        public string SummaryText
        {
            get { return _summaryText; }
            private set { _summaryText = value; Notify(nameof(SummaryText)); }
        }

        public string NoticeText
        {
            get { return _noticeText; }
            private set { _noticeText = value ?? ""; Notify(nameof(NoticeText)); }
        }

        public string LogsText
        {
            get { return _logsText; }
            private set { _logsText = value; Notify(nameof(LogsText)); }
        }

        /// <summary>Error of the "Ban all" action, shown in the summary card.</summary>
        public string ActionError
        {
            get { return _actionError; }
            private set { _actionError = value ?? ""; Notify(nameof(ActionError)); }
        }

        public string BanAllLabel => _banAll?.Label ?? "";

        public bool HasBanAll => _banAll != null;

        /// <summary>Shown when the list is empty.</summary>
        public string EmptyText => HasScanned
            ? $"No risks found in the {SelectedRange.Label().ToLowerInvariant()}."
            : $"Click Scan to check the {SelectedRange.Label().ToLowerInvariant()}.";

        public ICommand ScanCommand { get; }

        public ICommand CancelCommand { get; }

        public ICommand BanAllCommand { get; }

        #endregion

        #region public operations

        public async Task ScanAsync()
        {
            if (IsScanning)
                return;

            var cts = new CancellationTokenSource();
            _cts = cts;
            IsScanning = true;
            ActionError = "";
            ProgressText = "Contacting the EvlWatcher service…";

            var input = new AnalyzerInput { NowUtc = _utcNow(), Range = SelectedRange, LocalAddresses = _localAddresses() };
            SynchronizationContext ui = SynchronizationContext.Current;
            var progress = new SyncProgress(text =>
            {
                if (cts.IsCancellationRequested)
                    return;
                if (ui != null)
                    ui.Post(_ => { if (!cts.IsCancellationRequested) ProgressText = text; }, null);
                else
                    ProgressText = text;
            });

            try
            {
                AnalysisResult result = await Task.Run(() =>
                {
                    FillServiceState(input);
                    cts.Token.ThrowIfCancellationRequested();
                    return new Analyzer(_source).Analyze(input, progress, cts.Token);
                });
                Show(result, input.Range);
                ProgressText = "";
            }
            catch (OperationCanceledException)
            {
                ProgressText = "Scan cancelled.";
            }
            catch (Exception ex)
            {
                ProgressText = "The scan failed: " + ex.Message;
            }
            finally
            {
                IsScanning = false;
                if (_cts == cts)
                    _cts = null;
                cts.Dispose();
            }
        }

        #endregion

        #region private operations

        private void FillServiceState(AnalyzerInput input)
        {
            try
            {
                input.Rules = _client.GetRules();
                input.WhitelistPatterns = _client.GetWhiteListPatterns();
                input.TemporarilyBanned = new HashSet<string>(_client.GetTemporarilyBannedIPs());
                input.PermanentlyBanned = new HashSet<string>(_client.GetPermanentlyBannedIPs());
            }
            catch (RuleClientException)
            {
                input.Rules = null;
                input.WhitelistPatterns = new List<string>();
                input.TemporarilyBanned = new HashSet<string>();
                input.PermanentlyBanned = new HashSet<string>();
            }
        }

        private void Show(AnalysisResult result, AnalysisRange range)
        {
            Findings.Clear();
            foreach (Finding f in result.Findings)
                Findings.Add(new FindingViewModel(f, Execute));

            _banAll = result.BanAllAction;
            Notify(nameof(BanAllLabel));
            Notify(nameof(HasBanAll));

            int critical = result.Findings.Count(f => f.Severity == FindingSeverity.Critical);
            int warnings = result.Findings.Count(f => f.Severity == FindingSeverity.Warning);
            int info = result.Findings.Count(f => f.Severity == FindingSeverity.Info);
            SummaryText = $"{critical} critical · {Plural(warnings, "warning")} · {info} info — {range.Label()}, " +
                          $"{result.EventsRead:N0} events in {Plural(result.LogsChecked.Count, "log")}, {result.Duration.TotalSeconds:0.0} s";
            NoticeText = result.Notice;

            var parts = new List<string>();
            if (result.LogsChecked.Count > 0)
                parts.Add("Logs checked: " + string.Join(", ", result.LogsChecked));
            if (result.LogsMissing.Count > 0)
                parts.Add("Not on this server: " + string.Join(", ", result.LogsMissing));
            if (result.LogsUnreadable.Count > 0)
                parts.Add("Couldn't read (run the console as administrator): " + string.Join(", ", result.LogsUnreadable));
            LogsText = string.Join(" · ", parts);

            HasScanned = true;
        }

        private void Execute(FindingViewModel owner, ActionViewModel actionVm)
        {
            FindingAction action = actionVm.Action;
            if (!_confirmer.Confirm(action.Label, action.ConfirmationText))
                return;

            try
            {
                owner.Error = "";
                if (action.Kind == FindingActionKind.WidenRuleWindow)
                {
                    GenericIPBlockingTaskDTO rule = _client.GetRules().FirstOrDefault(r => r.TaskName == action.RuleName);
                    if (rule == null)
                        throw new RuleClientException($"Rule {action.RuleName} no longer exists.");
                    rule.EventAge = action.NewEventAgeSeconds;
                    rule.LockTime = action.NewLockTimeSeconds;
                    _client.SaveRule(rule);
                    foreach (ActionViewModel a in Findings.SelectMany(f => f.Actions)
                                 .Where(a => a.Action.Kind == FindingActionKind.WidenRuleWindow && a.Action.RuleName == action.RuleName))
                        a.IsDone = true;
                }
                else
                {
                    Ban(action.Addresses);
                }
            }
            catch (RuleClientException ex)
            {
                owner.Error = ex.Message;
            }
        }

        private void ExecuteBanAll()
        {
            if (_banAll == null || !_confirmer.Confirm(_banAll.Label, _banAll.ConfirmationText))
                return;
            try
            {
                ActionError = "";
                Ban(_banAll.Addresses);
                _banAll = null;
                Notify(nameof(HasBanAll));
                CommandManager.InvalidateRequerySuggested();
            }
            catch (RuleClientException ex)
            {
                ActionError = ex.Message;
            }
        }

        private void Ban(IReadOnlyList<string> addresses)
        {
            _client.BanPermanently(addresses.ToList());
            var banned = new HashSet<string>(addresses);
            foreach (FindingViewModel f in Findings.Where(f => f.Model.Address != null && banned.Contains(f.Model.Address)))
                f.IsDone = true;
        }

        private static string Plural(int n, string word) => n == 1 ? $"1 {word}" : $"{n} {word}s";

        #endregion

        /// <summary>Reports synchronously; the callback decides how to marshal to the UI.</summary>
        private sealed class SyncProgress : IProgress<string>
        {
            private readonly Action<string> _report;

            public SyncProgress(Action<string> report)
            {
                _report = report;
            }

            public void Report(string value) => _report(value);
        }
    }
}
