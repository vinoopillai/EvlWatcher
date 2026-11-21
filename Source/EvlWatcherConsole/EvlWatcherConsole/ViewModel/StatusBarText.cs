using System;
using System.Collections.Generic;
using System.Linq;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.ViewModel
{
    /// <summary>Texts for the status bar: the service's latest activity and the age of the IP country data. Pure, no WPF.</summary>
    public static class StatusBarText
    {
        #region private members

        private const int MaxMessageLength = 120;

        /// <summary>Same limit the service uses to call registry data out as old.</summary>
        private const int StaleDays = 14;

        #endregion

        #region public operations

        /// <summary>
        /// The newest Info-or-higher log entry with its age, e.g. "3 min ago: Temporarily banning 203.0.113.7".
        /// Times are the service's local time (same machine).
        /// </summary>
        public static string Activity(IEnumerable<LogEntryDTO> history, DateTime nowLocal)
        {
            LogEntryDTO last = (history ?? Enumerable.Empty<LogEntryDTO>())
                .Where(e => e != null && e.Severity >= SeverityLevelDTO.Info && e.Severity < SeverityLevelDTO.Off)
                .OrderByDescending(e => e.Date)
                .FirstOrDefault();
            if (last == null)
                return "No activity logged yet";

            return $"{Age(nowLocal - last.Date)}: {OneLine(last.Message)}";
        }

        public static string CountryData(CountryDataStatusDTO status, DateTime nowUtc)
        {
            if (status == null)
                return "";
            if (!status.Loaded)
                return "IP country data: not loaded";
            if (status.UpdatedUtc == null)
                return "IP country data: loaded";

            int days = Days(status, nowUtc);
            return days == 0 ? "IP country data: updated today"
                 : days == 1 ? "IP country data: 1 day old"
                 : $"IP country data: {days} days old";
        }

        /// <summary>True when rules with a country list can't work as intended: data missing or older than two weeks.</summary>
        public static bool CountryDataNeedsAttention(CountryDataStatusDTO status, DateTime nowUtc)
        {
            if (status == null)
                return false;
            return !status.Loaded || (status.UpdatedUtc != null && Days(status, nowUtc) > StaleDays);
        }

        #endregion

        #region private operations

        private static int Days(CountryDataStatusDTO status, DateTime nowUtc) =>
            Math.Max(0, (int)(nowUtc - status.UpdatedUtc.Value).TotalDays);

        private static string Age(TimeSpan age)
        {
            if (age.TotalMinutes < 1)
                return "Just now";
            if (age.TotalHours < 1)
                return $"{(int)age.TotalMinutes} min ago";
            if (age.TotalDays < 1)
                return $"{(int)age.TotalHours} h ago";
            int days = (int)age.TotalDays;
            return days == 1 ? "1 day ago" : $"{days} days ago";
        }

        private static string OneLine(string message)
        {
            string line = (message ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            line = line.Trim();
            return line.Length <= MaxMessageLength ? line : line.Substring(0, MaxMessageLength - 1) + "…";
        }

        #endregion
    }
}
