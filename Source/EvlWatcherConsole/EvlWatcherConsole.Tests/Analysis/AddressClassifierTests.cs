using System.Collections.Generic;
using System.Net;
using EvlWatcherConsole.Analysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests.Analysis
{
    [TestClass]
    public class AddressClassifierTests
    {
        [DataTestMethod]
        [DataRow("1.2.3.4", "1.2.3.4")]
        [DataRow("1.2.3.4:51234", "1.2.3.4")]
        [DataRow("[2001:db8::1]:3389", "2001:db8::1")]
        [DataRow("2001:db8::1", "2001:db8::1")]
        public void TryParseAcceptsAddressesAndPorts(string value, string expected)
        {
            Assert.IsTrue(AddressClassifier.TryParse(value, out IPAddress ip));
            Assert.AreEqual(IPAddress.Parse(expected), ip);
        }

        [DataTestMethod]
        [DataRow("-")]
        [DataRow("")]
        [DataRow(null)]
        [DataRow("4625")]
        public void TryParseRejectsNonAddresses(string value)
        {
            Assert.IsFalse(AddressClassifier.TryParse(value, out _));
        }

        [DataTestMethod]
        [DataRow("10.0.0.5", true)]
        [DataRow("172.20.1.1", true)]
        [DataRow("192.168.1.50", true)]
        [DataRow("169.254.3.3", true)]
        [DataRow("fe80::1", true)]
        [DataRow("fd00::1", true)]
        [DataRow("5.175.140.23", false)]
        [DataRow("172.32.0.1", false)]
        public void IsPrivate(string value, bool expected)
        {
            Assert.AreEqual(expected, AddressClassifier.IsPrivate(IPAddress.Parse(value)));
        }

        [TestMethod]
        public void WhitelistUsesServiceWildcards()
        {
            Assert.IsTrue(AddressClassifier.IsWhitelisted("192.168.1.50", new[] { "192.168.*" }));
            Assert.IsFalse(AddressClassifier.IsWhitelisted("10.0.0.15", new[] { "10.0.0.1" }));
            Assert.IsTrue(AddressClassifier.IsWhitelisted("10.0.0.1", new[] { "10.0.0.1" }));
            Assert.IsFalse(AddressClassifier.IsWhitelisted("10.0.0.1", null));
        }

        [TestMethod]
        public void IsLocal()
        {
            var own = new HashSet<string> { "203.0.113.5" };
            Assert.IsTrue(AddressClassifier.IsLocal(IPAddress.Parse("127.0.0.1"), own));
            Assert.IsTrue(AddressClassifier.IsLocal(IPAddress.Parse("::1"), own));
            Assert.IsTrue(AddressClassifier.IsLocal(IPAddress.Parse("0.0.0.0"), own));
            Assert.IsTrue(AddressClassifier.IsLocal(IPAddress.Parse("203.0.113.5"), own));
            Assert.IsFalse(AddressClassifier.IsLocal(IPAddress.Parse("5.175.140.23"), own));
        }
    }

    [TestClass]
    public class AnalyzedEventTests
    {
        [TestMethod]
        public void FailedLogonRoundTrips()
        {
            var t = EventSamples.Utc("2026-11-20T18:36:28Z");
            AnalyzedEvent ev = EventSamples.Failed4625("5.175.140.23", t, "administrator");

            Assert.AreEqual(4625, ev.EventId);
            Assert.AreEqual("Microsoft-Windows-Security-Auditing", ev.Provider);
            Assert.AreEqual("Security", ev.LogName);
            Assert.AreEqual("5.175.140.23", ev.Get("IpAddress"));
            Assert.AreEqual("administrator", ev.Get("TargetUserName"));
            Assert.AreEqual(t, ev.TimeUtc);
            Assert.AreEqual(System.DateTimeKind.Utc, ev.TimeUtc.Kind);
            Assert.IsTrue(ev.RecordId > 0);
            Assert.IsNull(ev.Get("NoSuchField"));
        }

        [TestMethod]
        public void UserDataFieldsAreExposed()
        {
            AnalyzedEvent ev = EventSamples.LogCleared1102(EventSamples.Utc("2026-11-20T10:00:00Z"), "admin2");
            Assert.AreEqual(1102, ev.EventId);
            Assert.AreEqual("admin2", ev.Get("SubjectUserName"));
        }

        [TestMethod]
        public void UnnamedDataIsNumbered()
        {
            AnalyzedEvent ev = EventSamples.Disk7(EventSamples.Utc("2026-11-20T10:00:00Z"));
            Assert.AreEqual("disk", ev.Provider);
            Assert.AreEqual("\\Device\\Harddisk0\\DR0", ev.Get("#1"));
        }

        [TestMethod]
        public void RangesHaveLabelsAndSpans()
        {
            Assert.AreEqual("Last 24 hours", AnalysisRange.Last24Hours.Label());
            Assert.AreEqual(System.TimeSpan.FromDays(7), AnalysisRange.Last7Days.ToTimeSpan());
            Assert.AreEqual(System.TimeSpan.FromDays(30), AnalysisRange.Last30Days.ToTimeSpan());
        }
    }
}
