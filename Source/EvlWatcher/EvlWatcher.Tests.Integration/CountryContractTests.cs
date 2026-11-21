using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using EvlWatcher.Config;
using EvlWatcher.WCF.DTO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests.Integration
{
    [TestClass]
    public class CountryContractTests
    {
        private const string CountryMessage = "Country codes must be two letters, e.g. IN.";

        private static GenericIPBlockingTaskDTO Dto(params string[] countries) => new GenericIPBlockingTaskDTO
        {
            TaskName = "BlockRDPBrutersBySecurity4625", Active = true, Description = "d", LockTime = 3600, EventAge = 3600,
            TriggerCount = 5, PermaBanCount = 3, EventPath = new List<string> { "Security" },
            RegexBoosters = new List<string> { "4625" }, Regex = "(x)",
            AllowedCountries = countries == null ? null : countries.ToList()
        };

        [TestMethod]
        public void MapperRoundTripsAllowedCountries()
        {
            var config = new TestTaskConfig();
            RuleMapper.Apply(Dto(" in", "ae "), config);
            CollectionAssert.AreEqual(new[] { "IN", "AE" }, config.AllowedCountries.ToArray());

            GenericIPBlockingTaskDTO back = RuleMapper.ToDto(config, _ => true);
            CollectionAssert.AreEqual(new[] { "IN", "AE" }, back.AllowedCountries.ToArray());
        }

        [TestMethod]
        public void SaveRuleWithoutCountriesFieldKeepsExistingValue()
        {
            var config = new TestTaskConfig { AllowedCountriesList = new List<string> { "IN" } };
            GenericIPBlockingTaskDTO olderConsole = Dto();
            olderConsole.AllowedCountries = null;

            RuleMapper.Apply(olderConsole, config);

            CollectionAssert.AreEqual(new[] { "IN" }, config.AllowedCountries.ToArray());
        }

        [TestMethod]
        public void EmptyListClearsCountries()
        {
            var config = new TestTaskConfig { AllowedCountriesList = new List<string> { "IN" } };
            RuleMapper.Apply(Dto(new string[0]), config);
            Assert.AreEqual(0, config.AllowedCountries.Count);
        }

        [TestMethod]
        public void ValidatorRejectsBadCodes()
        {
            Func<string, bool> logs = _ => true;
            var names = new[] { "BlockRDPBrutersBySecurity4625" };
            CollectionAssert.Contains(RuleValidator.Validate(Dto("IND"), false, names, logs).ToList(), CountryMessage);
            CollectionAssert.Contains(RuleValidator.Validate(Dto("I1"), false, names, logs).ToList(), CountryMessage);
            CollectionAssert.Contains(RuleValidator.Validate(Dto(""), false, names, logs).ToList(), CountryMessage);
            CollectionAssert.DoesNotContain(RuleValidator.Validate(Dto("in"), false, names, logs).ToList(), CountryMessage);
            CollectionAssert.DoesNotContain(RuleValidator.Validate(Dto(), false, names, logs).ToList(), CountryMessage);
        }

        [TestMethod]
        public void ServiceConfigDefaultsAutoUpdateToTrue()
        {
            string folder = Path.Combine(Path.GetTempPath(), "evlwatcher-cfg-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            string oldPath = ConfigFile.Path;
            try
            {
                ConfigFile.Path = Path.Combine(folder, "config.xml");
                new XDocument(new XElement("Config",
                    new XElement("Global", new XElement("LogLevel", "Info"), new XElement("ConsoleBacklog", "100"),
                                 new XElement("CheckInterval", "30"), new XElement("WhiteList", ""), new XElement("Banlist", "")),
                    new XElement("Tasks"))).Save(ConfigFile.Path);

                var config = new XmlServiceConfiguration(new TestLogger());
                config.Load();
                Assert.IsTrue(config.CountryDataAutoUpdate, "missing element means on");

                config.CountryDataAutoUpdate = false;
                Assert.AreEqual("False", XDocument.Load(ConfigFile.Path).Root!.Element("Global")!.Element("CountryDataAutoUpdate")!.Value);

                var reloaded = new XmlServiceConfiguration(new TestLogger());
                reloaded.Load();
                Assert.IsFalse(reloaded.CountryDataAutoUpdate);
            }
            finally
            {
                ConfigFile.Path = oldPath;
                Directory.Delete(folder, true);
            }
        }
    }
}
