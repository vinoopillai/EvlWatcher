using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using EvlWatcher.Config;
using EvlWatcher.DTOs;
using EvlWatcher.Geo;
using EvlWatcher.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests.Integration
{
    internal sealed class FakeCountries : ICountryLookup
    {
        public readonly Dictionary<string, string> Map = new Dictionary<string, string>();
        public bool IsLoaded { get; set; } = true;
        public string? GetCountry(IPAddress ip) => Map.TryGetValue(ip.ToString(), out string? cc) ? cc : null;
    }

    [TestClass]
    public class CountryRuleTests
    {
        private const string Foreign = "5.175.140.23";
        private const string Indian = "103.228.149.59";
        private const string Unknown = "198.51.100.7";

        private static FakeCountries Countries() => new FakeCountries
        {
            Map = { { Foreign, "DE" }, { Indian, "IN" }, { "192.168.1.20", "CN" } }
        };

        private static GenericIPBlockingTask Task(ICountryLookup countries, params string[] allowed)
        {
            GenericIPBlockingTask t = GenericIPBlockingTask.FromConfiguration(new TestTaskConfig { AllowedCountriesList = allowed.ToList() }, new TestLogger(), countries);
            return t;
        }

        private static List<ExtractedEventRecord> Failures(string ip, int count) =>
            Enumerable.Range(0, count).Select(i => new ExtractedEventRecord
            {
                TimeCreated = DateTime.Now.AddSeconds(-i),
                Xml = "<Event><System><EventID>4625</EventID></System><EventData><Data Name='TargetUserName'>administrator</Data>" +
                      "<Data Name='IpAddress'>" + ip + "</Data><Data Name='IpPort'>0</Data></EventData></Event>"
            }).ToList();

        [TestMethod]
        public void ForeignAddressBannedAfterOneAttemptWithoutStrike()
        {
            GenericIPBlockingTask t = Task(Countries(), "IN");

            t.ProvideEvents(Failures(Foreign, 1));
            CollectionAssert.Contains(t.GetTempBanVictims(), IPAddress.Parse(Foreign));

            // three more bans after the lock time ran out: still never permanent
            t.LockTime = 0;
            for (int i = 0; i < 3; i++)
            {
                t.GetTempBanVictims(); // lifts the expired ban
                t.ProvideEvents(Failures(Foreign, 1));
            }
            Assert.AreEqual(0, t.GetPermaBanVictims().Count);
        }

        [TestMethod]
        public void ForeignAddressReachingTriggerCountGetsStrike()
        {
            GenericIPBlockingTask t = Task(Countries(), "IN");
            t.PermaBanCount = 1;
            t.ProvideEvents(Failures(Foreign, 5));
            CollectionAssert.Contains(t.GetPermaBanVictims(), IPAddress.Parse(Foreign));
        }

        [TestMethod]
        public void AllowedCountryNeedsTriggerCount()
        {
            GenericIPBlockingTask t = Task(Countries(), "IN");
            t.ProvideEvents(Failures(Indian, 1));
            Assert.AreEqual(0, t.GetTempBanVictims().Count);
            t.ProvideEvents(Failures(Indian, 5));
            CollectionAssert.Contains(t.GetTempBanVictims(), IPAddress.Parse(Indian));
        }

        [TestMethod]
        public void UnknownCountryNeedsTriggerCount()
        {
            GenericIPBlockingTask t = Task(Countries(), "IN");
            t.ProvideEvents(Failures(Unknown, 1));
            Assert.AreEqual(0, t.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void NotLoadedNeedsTriggerCount()
        {
            FakeCountries countries = Countries();
            countries.IsLoaded = false;
            GenericIPBlockingTask t = Task(countries, "IN");
            t.ProvideEvents(Failures(Foreign, 1));
            Assert.AreEqual(0, t.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void PrivateAddressUsesNormalTrigger()
        {
            GenericIPBlockingTask t = Task(Countries(), "IN");
            t.ProvideEvents(Failures("192.168.1.20", 1));
            Assert.AreEqual(0, t.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void RuleWithoutCountriesUsesNormalTrigger()
        {
            GenericIPBlockingTask t = Task(Countries());
            t.ProvideEvents(Failures(Foreign, 1));
            Assert.AreEqual(0, t.GetTempBanVictims().Count);
        }

        private static XmlTaskConfig LoadTask(string allowedCountries, TestLogger logger)
        {
            var task = new XElement("Task", new XAttribute("Name", "R"), new XAttribute("Active", "true"),
                new XElement("Description", "d"), new XElement("LockTime", "3600"), new XElement("OnlyNew", "False"),
                new XElement("EventAge", "120"), new XElement("TriggerCount", "5"), new XElement("PermaBanCount", "3"),
                new XElement("EventPath", "Security"), new XElement("RegexBoosters", new XElement("Booster", "4625")),
                new XElement("Regex", "(x)"), new XElement("AllowedCountries", allowedCountries));
            return XmlTaskConfig.FromXmlElement(task, new object(), logger);
        }

        [TestMethod]
        public void HandEditedSemicolonsAndSpacesAreAccepted()
        {
            CollectionAssert.AreEqual(new[] { "IN", "AE" }, LoadTask(" IN; ae ", new TestLogger()).AllowedCountries.ToArray());
            CollectionAssert.AreEqual(new[] { "IN", "AE" }, LoadTask("IN AE", new TestLogger()).AllowedCountries.ToArray());
        }

        [TestMethod]
        public void InvalidHandEditedCountriesTurnTheFilterOff()
        {
            // a typo must never give every user of the intended country a first-attempt ban
            var logger = new TestLogger();
            Assert.AreEqual(0, LoadTask("India", logger).AllowedCountries.Count);
            Assert.IsTrue(logger.Messages.Any(m => m.StartsWith("Warning") && m.Contains("India")));
            Assert.AreEqual(0, LoadTask("IN, IND", new TestLogger()).AllowedCountries.Count);
        }

        [TestMethod]
        public void XmlTaskConfigRoundTripsAllowedCountries()
        {
            string folder = Path.Combine(Path.GetTempPath(), "evlwatcher-cfg-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            string oldPath = ConfigFile.Path;
            try
            {
                ConfigFile.Path = Path.Combine(folder, "config.xml");
                var task = new XElement("Task", new XAttribute("Name", "R"), new XAttribute("Active", "true"),
                    new XElement("Description", "d"), new XElement("LockTime", "3600"), new XElement("OnlyNew", "False"),
                    new XElement("EventAge", "120"), new XElement("TriggerCount", "5"), new XElement("PermaBanCount", "3"),
                    new XElement("EventPath", "Security"), new XElement("RegexBoosters", new XElement("Booster", "4625")),
                    new XElement("Regex", "(x)"), new XElement("AllowedCountries", "in, AE"));
                new XDocument(new XElement("Config", new XElement("Global"), new XElement("Tasks", task))).Save(ConfigFile.Path);

                XmlTaskConfig cfg = XmlTaskConfig.FromXmlElement(task, new object(), new TestLogger());
                CollectionAssert.AreEqual(new[] { "IN", "AE" }, cfg.AllowedCountries.ToArray());

                cfg.SetAllowedCountries(new string[0]);
                Assert.IsNull(XDocument.Load(ConfigFile.Path).Descendants("AllowedCountries").FirstOrDefault(), "empty list removes the element");

                cfg.SetAllowedCountries(new[] { "in" });
                Assert.AreEqual("IN", XDocument.Load(ConfigFile.Path).Descendants("AllowedCountries").Single().Value);
            }
            finally
            {
                ConfigFile.Path = oldPath;
                Directory.Delete(folder, true);
            }
        }
    }

    /// <summary>The shipped 4625 rule as a plain configuration object.</summary>
    internal sealed class TestTaskConfig : IPersistentTaskConfiguration
    {
        public List<string> AllowedCountriesList = new List<string>();
        public string TaskName => "BlockRDPBrutersBySecurity4625";
        public bool Active { get; set; } = true;
        public string Description { get; set; } = "test";
        public int LockTime { get; set; } = 3600;
        public bool OnlyNewEvents { get; set; }
        public int EventAge { get; set; } = 3600;
        public int TriggerCount { get; set; } = 5;
        public int PermaBanCount { get; set; } = 3;
        public string EventPath { get; set; } = "Security";
        public string Regex { get; set; } = @"<Data Name=.IpAddress.>(\d*.\d*.\d*.\d*)";
        public IQueryable<string> RegexBoosters => new[] { "4625", "IpAddress" }.AsQueryable();
        public IList<string> AllowedCountries => AllowedCountriesList;
        public bool AddRegexBooster(string regexBooster) => false;
        public bool RemoveRegexBooster(string regexBooster) => false;
        public void SetRegexBoosters(IEnumerable<string> boosters) { }
        public void SetAllowedCountries(IEnumerable<string> countries) { AllowedCountriesList = countries.ToList(); }
    }
}
