using System;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    [TestClass]
    public class StatusBarTextTests
    {
        private static readonly DateTime Now = new DateTime(2026, 11, 21, 12, 0, 0);

        private static LogEntryDTO Entry(int minutesAgo, SeverityLevelDTO severity, string message) =>
            new LogEntryDTO { Date = Now.AddMinutes(-minutesAgo), Severity = severity, Message = message };

        [TestMethod]
        public void ShowsTheNewestInfoOrHigherEntryWithItsAge()
        {
            string text = StatusBarText.Activity(new[]
            {
                Entry(30, SeverityLevelDTO.Info, "Saved rule \"RDP\""),
                Entry(3, SeverityLevelDTO.Info, "Temporarily banning 203.0.113.7, this is strike 1"),
                Entry(1, SeverityLevelDTO.Verbose, "checked 4 events"),
            }, Now);
            Assert.AreEqual("3 min ago: Temporarily banning 203.0.113.7, this is strike 1", text);
        }

        [TestMethod]
        public void RecentEntriesSayJustNowAndOldOnesUseHoursOrDays()
        {
            Assert.AreEqual("Just now: x", StatusBarText.Activity(new[] { Entry(0, SeverityLevelDTO.Warning, "x") }, Now));
            Assert.AreEqual("2 h ago: x", StatusBarText.Activity(new[] { Entry(125, SeverityLevelDTO.Info, "x") }, Now));
            Assert.AreEqual("3 days ago: x", StatusBarText.Activity(new[] { Entry(3 * 1440 + 5, SeverityLevelDTO.Info, "x") }, Now));
        }

        [TestMethod]
        public void LongOrMultiLineMessagesAreShortened()
        {
            string text = StatusBarText.Activity(new[] { Entry(3, SeverityLevelDTO.Error, "first line\r\nstack trace " + new string('x', 300)) }, Now);
            Assert.AreEqual("3 min ago: first line", text);

            text = StatusBarText.Activity(new[] { Entry(3, SeverityLevelDTO.Info, new string('y', 300)) }, Now);
            Assert.IsTrue(text.EndsWith("…"));
            Assert.IsTrue(text.Length <= "3 min ago: ".Length + 120);
        }

        [TestMethod]
        public void NoEntriesSaysSo()
        {
            Assert.AreEqual("No activity logged yet", StatusBarText.Activity(new LogEntryDTO[0], Now));
            Assert.AreEqual("No activity logged yet", StatusBarText.Activity(null, Now));
        }

        [TestMethod]
        public void CountryDataAge()
        {
            DateTime utc = new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc);
            Assert.AreEqual("IP country data: updated today",
                StatusBarText.CountryData(new CountryDataStatusDTO { Loaded = true, UpdatedUtc = utc.AddHours(-5) }, utc));
            Assert.AreEqual("IP country data: 1 day old",
                StatusBarText.CountryData(new CountryDataStatusDTO { Loaded = true, UpdatedUtc = utc.AddDays(-1) }, utc));
            Assert.AreEqual("IP country data: 9 days old",
                StatusBarText.CountryData(new CountryDataStatusDTO { Loaded = true, UpdatedUtc = utc.AddDays(-9) }, utc));
            Assert.AreEqual("IP country data: not loaded",
                StatusBarText.CountryData(new CountryDataStatusDTO { Loaded = false }, utc));
            Assert.AreEqual("", StatusBarText.CountryData(null, utc), "older service without country data: hidden");
        }

        [TestMethod]
        public void CountryDataNeedsAttentionWhenMissingOrOld()
        {
            DateTime utc = new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc);
            Assert.IsFalse(StatusBarText.CountryDataNeedsAttention(new CountryDataStatusDTO { Loaded = true, UpdatedUtc = utc.AddDays(-9) }, utc));
            Assert.IsTrue(StatusBarText.CountryDataNeedsAttention(new CountryDataStatusDTO { Loaded = true, UpdatedUtc = utc.AddDays(-15) }, utc));
            Assert.IsTrue(StatusBarText.CountryDataNeedsAttention(new CountryDataStatusDTO { Loaded = false }, utc));
            Assert.IsFalse(StatusBarText.CountryDataNeedsAttention(null, utc));
        }
    }
}
