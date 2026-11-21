using System.Globalization;
using System.Linq;
using System.Windows.Input;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.MVVMBase;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>The "Country data" card on the Settings tab: status, weekly auto-update, Update now.</summary>
    public sealed class CountryDataViewModel : GuiObject
    {
        #region private members

        private readonly IRuleClient _client;
        private string _statusText = "";
        private string _error = "";
        private bool _autoUpdate = true;

        #endregion

        #region constructor

        public CountryDataViewModel(IRuleClient client)
        {
            _client = client;
            UpdateNowCommand = new RelayCommand(_ => UpdateNow());
        }

        #endregion

        #region public properties

        public string StatusText
        {
            get { return _statusText; }
            private set { _statusText = value; Notify(nameof(StatusText)); }
        }

        public string Error
        {
            get { return _error; }
            private set { _error = value ?? ""; Notify(nameof(Error)); }
        }

        /// <summary>Weekly refresh from the internet registries; changing it tells the service at once.</summary>
        public bool AutoUpdate
        {
            get { return _autoUpdate; }
            set
            {
                if (_autoUpdate == value)
                    return;
                try
                {
                    _client.SetCountryDataAutoUpdate(value);
                    _autoUpdate = value;
                    Error = "";
                }
                catch (RuleClientException ex)
                {
                    Error = ex.Message;
                }
                Notify(nameof(AutoUpdate));
            }
        }

        public ICommand UpdateNowCommand { get; }

        #endregion

        #region public operations

        public void Refresh()
        {
            try
            {
                CountryDataStatusDTO status = _client.GetCountryDataStatus();
                StatusText = Describe(status);
                _autoUpdate = status.AutoUpdate;
                Notify(nameof(AutoUpdate));
                Error = "";
            }
            catch (RuleClientException ex)
            {
                Error = ex.Message;
            }
        }

        #endregion

        #region private operations

        private void UpdateNow()
        {
            try
            {
                _client.UpdateCountryDataNow();
                StatusText = "Updating… check back in a minute.";
                Error = "";
            }
            catch (RuleClientException ex)
            {
                Error = ex.Message;
            }
        }

        private static string Describe(CountryDataStatusDTO s)
        {
            string text = s.Loaded
                ? (s.UpdatedUtc.HasValue ? "Updated " + s.UpdatedUtc.Value.ToLocalTime().ToString("d", CultureInfo.CurrentCulture) + " · " : "")
                  + s.RangeCount.ToString("N0", CultureInfo.CurrentCulture) + " ranges from "
                  + string.Join(", ", s.Registries ?? new string[0])
                : "Country data isn't loaded. Rules with allowed countries use their normal limit for everyone.";
            if (!string.IsNullOrEmpty(s.LastError))
                text += " · Last update problem: " + s.LastError;
            return text;
        }

        #endregion
    }
}
