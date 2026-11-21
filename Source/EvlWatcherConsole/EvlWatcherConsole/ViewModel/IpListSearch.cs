using System;
using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using System.Windows.Input;
using EvlWatcherConsole.MVVMBase;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>
    /// One search box for the Bans &amp; Whitelist tab: filters the temporary, permanent and whitelist lists
    /// (their default views) to entries that contain the typed text. Commands still act on the full lists.
    /// </summary>
    public sealed class IpListSearch : GuiObject
    {
        #region private members

        private readonly IEnumerable[] _lists;
        private string _text = "";

        #endregion

        #region public .ctor

        public IpListSearch(params IEnumerable[] lists)
        {
            _lists = lists;
            foreach (IEnumerable list in _lists)
            {
                CollectionViewSource.GetDefaultView(list).Filter = item => Matches(item, _text);
                if (list is INotifyCollectionChanged observable)
                    observable.CollectionChanged += (s, e) => Notify(nameof(Summary));
            }
        }

        #endregion

        #region public properties

        public string Text
        {
            get => _text;
            set
            {
                value = value ?? "";
                if (_text == value)
                    return;
                _text = value;
                foreach (IEnumerable list in _lists)
                    CollectionViewSource.GetDefaultView(list).Refresh();
                Notify(nameof(Text));
                Notify(nameof(IsActive));
                Notify(nameof(Summary));
            }
        }

        public bool IsActive => _text.Trim().Length > 0;

        /// <summary>"3 of 120 entries match." while searching, empty otherwise.</summary>
        public string Summary
        {
            get
            {
                if (!IsActive)
                    return "";
                int total = _lists.Sum(l => l.Cast<object>().Count());
                int shown = _lists.Sum(l => l.Cast<object>().Count(i => Matches(i, _text)));
                return shown == 0 ? $"No entry matches \"{_text.Trim()}\"." : $"{shown} of {total} entries match.";
            }
        }

        public ICommand ClearCommand => new RelayCommand(p => Text = "");

        #endregion

        #region public operations

        /// <summary>True when the entry's text contains the query (trimmed, any case); an empty query matches everything.</summary>
        public static bool Matches(object item, string query)
        {
            string q = (query ?? "").Trim();
            if (q.Length == 0)
                return true;
            return (item?.ToString() ?? "").IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        #endregion
    }
}
