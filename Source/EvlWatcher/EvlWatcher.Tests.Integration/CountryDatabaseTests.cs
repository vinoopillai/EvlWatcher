using System.Collections.Generic;
using System.IO;
using System.Net;
using EvlWatcher.Geo;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests.Integration
{
    [TestClass]
    public class CountryDatabaseTests
    {
        internal const string ApnicSample =
            "2|apnic|20261120|67000|19830613|20261119|+1000\n" +
            "apnic|*|ipv4|*|52000|summary\n" +
            "# a comment\n" +
            "apnic|IN|ipv4|103.228.148.0|1024|20160101|allocated\n" +
            "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n" +
            "apnic|IN|ipv6|2401:4900::|32|20130101|allocated\n" +
            "apnic||ipv4|1.2.3.0|256||reserved\n";

        private static IList<CountryRange> Parse(string text, out string? registry)
        {
            using (var reader = new StringReader(text))
            {
                IList<CountryRange> ranges = DelegatedFileParser.Parse(reader, out string r);
                registry = r;
                return ranges;
            }
        }

        private static CountryDatabase Database(string text) =>
            new CountryDatabase(new[] { Parse(text, out _) });

        [TestMethod]
        public void ParsesIpv4CountAndIpv6Prefix()
        {
            IList<CountryRange> ranges = Parse(ApnicSample, out string? registry);
            Assert.AreEqual(3, ranges.Count);
            Assert.AreEqual("apnic", registry);
        }

        [TestMethod]
        public void LooksUpIPv4AtEdges()
        {
            CountryDatabase db = Database(ApnicSample);
            Assert.AreEqual("IN", db.GetCountry(IPAddress.Parse("103.228.148.0")));
            Assert.AreEqual("IN", db.GetCountry(IPAddress.Parse("103.228.151.255")));
            Assert.IsNull(db.GetCountry(IPAddress.Parse("103.228.152.0")));
            Assert.IsNull(db.GetCountry(IPAddress.Parse("103.228.147.255")));
            Assert.IsTrue(db.IsLoaded);
            Assert.AreEqual(3, db.RangeCount);
        }

        [TestMethod]
        public void LooksUpIPv6()
        {
            CountryDatabase db = Database(ApnicSample);
            Assert.AreEqual("IN", db.GetCountry(IPAddress.Parse("2401:4900:1:2::5")));
            Assert.IsNull(db.GetCountry(IPAddress.Parse("2401:4901::1")));
        }

        [TestMethod]
        public void IPv4MappedIsLookedUpAsIPv4()
        {
            Assert.AreEqual("CN", Database(ApnicSample).GetCountry(IPAddress.Parse("::ffff:1.0.1.7")));
        }

        [TestMethod]
        public void ReservedAndSummaryLinesAreSkipped()
        {
            Assert.IsNull(Database(ApnicSample).GetCountry(IPAddress.Parse("1.2.3.4")));
        }

        [TestMethod]
        public void EmptyDatabaseIsNotLoaded()
        {
            Assert.IsFalse(CountryDatabase.Empty.IsLoaded);
            Assert.IsNull(CountryDatabase.Empty.GetCountry(IPAddress.Parse("1.0.1.7")));
        }

        [TestMethod]
        public void LineWithEmptyFirstFieldIsSkipped()
        {
            IList<CountryRange> ranges = Parse("|xx|ipv4|1.1.1.0|256|20200101|allocated\n" + ApnicSample, out string? registry);
            Assert.AreEqual(3, ranges.Count);
            Assert.AreEqual("apnic", registry);
        }

        [TestMethod]
        public void MalformedLinesAreSkipped()
        {
            IList<CountryRange> ranges = Parse(ApnicSample +
                "apnic|IN|ipv4|not-an-ip|256|x|allocated\n" +
                "apnic|IN|ipv4|1.1.1.0\n" +
                "apnic|IN|ipv6|2401::|abc|x|allocated\n", out _);
            Assert.AreEqual(3, ranges.Count);
        }

        [TestMethod]
        public void SeveralRegistriesCombine()
        {
            var db = new CountryDatabase(new[]
            {
                Parse(ApnicSample, out _),
                Parse("2|ripencc|20261120|1|x|x|+0000\nripencc|DE|ipv4|5.175.0.0|65536|20120101|allocated\n", out _)
            });
            Assert.AreEqual("DE", db.GetCountry(IPAddress.Parse("5.175.140.23")));
            Assert.AreEqual("IN", db.GetCountry(IPAddress.Parse("103.228.149.59")));
        }
    }
}
