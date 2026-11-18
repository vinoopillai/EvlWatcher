using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows.Input;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.MVVMBase;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>
    /// Plain-language editor for one rule. Works on a copy of the DTO; minutes in the UI, seconds in the DTO.
    /// </summary>
    public class RuleEditorViewModel : GuiObject
    {
        #region private members

        private readonly IRuleClient _client;
        private readonly Action<string> _onSaved;
        private GenericIPBlockingTaskDTO _original;
        private bool _isNew;

        private string _name;
        private string _description;
        private bool _isActive;
        private string _attemptsText;
        private string _windowMinutesText;
        private string _banMinutesText;
        private string _permanentAfterText;
        private bool _neverPermanent;
        private string _eventLogsText;
        private string _boostersText;
        private string _regex;
        private bool _onlyNewEvents;
        private string _saveError;

        #endregion

        #region public .ctor

        public RuleEditorViewModel(IRuleClient client, GenericIPBlockingTaskDTO rule, bool isNew, Action<string> onSaved)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (rule == null) throw new ArgumentNullException(nameof(rule));

            _client = client;
            _isNew = isNew;
            _onSaved = onSaved;
            _original = Copy(rule);
            LoadFrom(_original);

            SaveCommand = new RelayCommand(p => Save(), p => IsDirty && string.IsNullOrEmpty(FieldError));
            DiscardCommand = new RelayCommand(p => Discard(), p => IsDirty);
        }

        #endregion

        #region public events

        /// <summary>Raised with a status line after the on/off toggle was applied or failed.</summary>
        public event Action<string> StatusReported;

        /// <summary>Raised whenever IsDirty may have changed (used by the list to track busy editing).</summary>
        public event Action Dirtied;

        #endregion

        #region private operations

        private static GenericIPBlockingTaskDTO Copy(GenericIPBlockingTaskDTO r)
        {
            return new GenericIPBlockingTaskDTO
            {
                Active = r.Active,
                TaskName = r.TaskName,
                Description = r.Description,
                LockTime = r.LockTime,
                OnlyNewEvents = r.OnlyNewEvents,
                EventAge = r.EventAge,
                TriggerCount = r.TriggerCount,
                PermaBanCount = r.PermaBanCount,
                EventPath = new List<string>(r.EventPath ?? new List<string>()),
                RegexBoosters = new List<string>(r.RegexBoosters ?? new List<string>()),
                MissingEventLogs = new List<string>(r.MissingEventLogs ?? new List<string>()),
                Regex = r.Regex,
            };
        }

        private static string FormatMinutes(int seconds)
        {
            return (seconds / 60.0).ToString("0.##########", CultureInfo.CurrentCulture);
        }

        private static string Join(IEnumerable<string> lines)
        {
            return string.Join(Environment.NewLine, lines ?? new List<string>());
        }

        private static List<string> Lines(string text)
        {
            return (text ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                               .Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        }

        private void LoadFrom(GenericIPBlockingTaskDTO r)
        {
            _name = r.TaskName;
            _description = r.Description;
            _isActive = r.Active;
            _attemptsText = r.TriggerCount.ToString(CultureInfo.CurrentCulture);
            _windowMinutesText = FormatMinutes(r.EventAge);
            _banMinutesText = FormatMinutes(r.LockTime);
            _neverPermanent = r.PermaBanCount < 0;
            _permanentAfterText = r.PermaBanCount > 0 ? r.PermaBanCount.ToString(CultureInfo.CurrentCulture) : ""; // legacy 0: leave empty so the admin must choose
            _eventLogsText = Join(r.EventPath);
            _boostersText = Join(r.RegexBoosters);
            _regex = r.Regex;
            _onlyNewEvents = r.OnlyNewEvents;
            _saveError = null;
        }

        private static bool TryParseWhole(string text, out int value)
        {
            return int.TryParse((text ?? "").Trim(), NumberStyles.Integer, CultureInfo.CurrentCulture, out value);
        }

        private static bool TryParseSeconds(string text, out int seconds)
        {
            seconds = 0;
            if (!double.TryParse((text ?? "").Trim(), NumberStyles.Float, CultureInfo.CurrentCulture, out double minutes)
                || double.IsNaN(minutes) || double.IsInfinity(minutes) || minutes < 0 || minutes > 35791394)
                return false;
            seconds = (int)Math.Round(minutes * 60.0, MidpointRounding.AwayFromZero);
            return true;
        }

        private string Validate()
        {
            if (_isNew && string.IsNullOrWhiteSpace(_name))
                return "Enter a name for the rule.";
            if (!TryParseWhole(_attemptsText, out int attempts) || attempts < 1)
                return "Failed attempts must be a whole number, 1 or more.";
            if (!TryParseSeconds(_windowMinutesText, out int window) || window < 10)
                return "The time window must be a number of minutes, at least 10 seconds (0.17).";
            if (!TryParseSeconds(_banMinutesText, out int ban) || ban < 60)
                return "The ban duration must be a number of minutes, 1 or more.";
            if (!_neverPermanent && (!TryParseWhole(_permanentAfterText, out int perma) || perma < 1))
                return "Permanent ban count must be a whole number, 1 or more.";
            return null;
        }

        private GenericIPBlockingTaskDTO BuildDto()
        {
            TryParseWhole(_attemptsText, out int attempts);
            TryParseSeconds(_windowMinutesText, out int window);
            TryParseSeconds(_banMinutesText, out int ban);
            TryParseWhole(_permanentAfterText, out int perma);

            return new GenericIPBlockingTaskDTO
            {
                TaskName = (_name ?? string.Empty).Trim(),
                Description = _description,
                Active = _isActive,
                TriggerCount = attempts,
                EventAge = window,
                LockTime = ban,
                PermaBanCount = _neverPermanent ? -1 : perma,
                EventPath = Lines(_eventLogsText),
                RegexBoosters = Lines(_boostersText),
                MissingEventLogs = new List<string>(_original.MissingEventLogs ?? new List<string>()),
                Regex = _regex,
                OnlyNewEvents = _onlyNewEvents,
            };
        }

        private void Changed(string property)
        {
            Notify(property);
            Notify(nameof(IsDirty));
            Notify(nameof(FieldError));
            if (_saveError != null)
            {
                _saveError = null;
                Notify(nameof(SaveError));
            }
            Dirtied?.Invoke();
        }

        private void Save()
        {
            GenericIPBlockingTaskDTO dto = BuildDto();
            try
            {
                _client.SaveRule(dto, _isNew);
            }
            catch (RuleClientException ex)
            {
                _saveError = ex.Message;
                Notify(nameof(SaveError));
                return;
            }

            _original = Copy(dto);
            _isNew = false;
            LoadFrom(_original);
            NotifyAll();
            _onSaved?.Invoke(dto.TaskName);
        }

        private void Discard()
        {
            LoadFrom(_original);
            NotifyAll();
        }

        private void NotifyAll()
        {
            foreach (string p in new[] { nameof(Name), nameof(Description), nameof(IsActive), nameof(AttemptsText),
                nameof(WindowMinutesText), nameof(BanMinutesText), nameof(PermanentAfterText), nameof(NeverPermanent),
                nameof(EventLogsText), nameof(BoostersText), nameof(Regex), nameof(OnlyNewEvents),
                nameof(IsDirty), nameof(FieldError), nameof(SaveError), nameof(IsNameEditable), nameof(IsDimmed),
                nameof(Subtitle) })
                Notify(p);
            Dirtied?.Invoke();
        }

        #endregion

        #region public properties

        public bool IsNameEditable { get { return _isNew; } }

        public string Name
        {
            get { return _name; }
            set { if (_isNew && _name != value) { _name = value; Changed(nameof(Name)); } }
        }

        public string Description
        {
            get { return _description; }
            set { if (_description != value) { _description = value; Changed(nameof(Description)); } }
        }

        /// <summary>First line of the description, shown under the name in the list.</summary>
        public string Subtitle
        {
            get
            {
                string d = _original.Description ?? "";
                int i = d.IndexOfAny(new[] { '\r', '\n' });
                return (i < 0 ? d : d.Substring(0, i)).Trim();
            }
        }

        public bool IsActive
        {
            get { return _isActive; }
            set
            {
                if (_isActive == value) return;
                bool previous = _isActive;
                _isActive = value;
                if (!_isNew)
                {
                    try
                    {
                        _client.SetRuleActive(_name, value);
                        _original.Active = value;
                        _saveError = null;
                        StatusReported?.Invoke("Rule applied. EvlWatcher reloaded its rules.");
                    }
                    catch (RuleClientException ex)
                    {
                        _isActive = previous;
                        _saveError = ex.Message;
                        StatusReported?.Invoke(ex.Message);
                    }
                    Notify(nameof(SaveError));
                }
                Notify(nameof(IsActive));
                Notify(nameof(IsDimmed));
            }
        }

        public bool IsDimmed { get { return !_isActive; } }

        public bool HasMissingLogs
        {
            get { return _original.MissingEventLogs != null && _original.MissingEventLogs.Count > 0; }
        }

        public string MissingLogsTooltip
        {
            get
            {
                return HasMissingLogs
                    ? "This rule has no effect on this machine until the software that writes "
                      + string.Join(", ", _original.MissingEventLogs) + " is installed."
                    : null;
            }
        }

        public string AttemptsText
        {
            get { return _attemptsText; }
            set { if (_attemptsText != value) { _attemptsText = value; Changed(nameof(AttemptsText)); } }
        }

        public string WindowMinutesText
        {
            get { return _windowMinutesText; }
            set { if (_windowMinutesText != value) { _windowMinutesText = value; Changed(nameof(WindowMinutesText)); } }
        }

        public string BanMinutesText
        {
            get { return _banMinutesText; }
            set { if (_banMinutesText != value) { _banMinutesText = value; Changed(nameof(BanMinutesText)); } }
        }

        public string PermanentAfterText
        {
            get { return _permanentAfterText; }
            set { if (_permanentAfterText != value) { _permanentAfterText = value; Changed(nameof(PermanentAfterText)); } }
        }

        public bool NeverPermanent
        {
            get { return _neverPermanent; }
            set { if (_neverPermanent != value) { _neverPermanent = value; Changed(nameof(NeverPermanent)); } }
        }

        public string EventLogsText
        {
            get { return _eventLogsText; }
            set { if (_eventLogsText != value) { _eventLogsText = value; Changed(nameof(EventLogsText)); } }
        }

        public string BoostersText
        {
            get { return _boostersText; }
            set { if (_boostersText != value) { _boostersText = value; Changed(nameof(BoostersText)); } }
        }

        public string Regex
        {
            get { return _regex; }
            set { if (_regex != value) { _regex = value; Changed(nameof(Regex)); } }
        }

        public bool OnlyNewEvents
        {
            get { return _onlyNewEvents; }
            set { if (_onlyNewEvents != value) { _onlyNewEvents = value; Changed(nameof(OnlyNewEvents)); } }
        }

        public bool IsDirty
        {
            get
            {
                if (_isNew) return true;
                GenericIPBlockingTaskDTO o = _original;
                string perma = o.PermaBanCount > 0 ? o.PermaBanCount.ToString(CultureInfo.CurrentCulture) : "";
                return _description != o.Description
                    || _attemptsText != o.TriggerCount.ToString(CultureInfo.CurrentCulture)
                    || _windowMinutesText != FormatMinutes(o.EventAge)
                    || _banMinutesText != FormatMinutes(o.LockTime)
                    || _neverPermanent != (o.PermaBanCount < 0)
                    || (!_neverPermanent && _permanentAfterText != perma)
                    || _eventLogsText != Join(o.EventPath)
                    || _boostersText != Join(o.RegexBoosters)
                    || _regex != o.Regex
                    || _onlyNewEvents != o.OnlyNewEvents;
            }
        }

        /// <summary>Validation message for the current input, or null when it can be saved.</summary>
        public string FieldError { get { return Validate(); } }

        /// <summary>Message of the last failed save or toggle, verbatim from the service.</summary>
        public string SaveError { get { return _saveError; } }

        public ICommand SaveCommand { get; }

        public ICommand DiscardCommand { get; }

        /// <summary>True when this editor was built from the same rule content and has no unsaved edits (so a refresh can keep it).</summary>
        public bool IsUnchangedFrom(GenericIPBlockingTaskDTO r)
        {
            if (IsDirty) return false;
            GenericIPBlockingTaskDTO o = _original;
            return o.TaskName == r.TaskName && o.Description == r.Description && o.Active == r.Active
                && o.LockTime == r.LockTime && o.EventAge == r.EventAge && o.TriggerCount == r.TriggerCount
                && o.PermaBanCount == r.PermaBanCount && o.OnlyNewEvents == r.OnlyNewEvents && o.Regex == r.Regex
                && Join(o.EventPath) == Join(r.EventPath) && Join(o.RegexBoosters) == Join(r.RegexBoosters)
                && Join(o.MissingEventLogs) == Join(r.MissingEventLogs);
        }

        #endregion
    }
}
