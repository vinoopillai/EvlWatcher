using System;
using System.Linq;
using System.Xml.Linq;
using EvlWatcher.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests
{
    [TestClass]
    public class XmlConfigPersistenceTests
    {
        private static XmlServiceConfiguration Reload()
        {
            var config = new XmlServiceConfiguration(new NullLogger());
            config.Load();
            return config;
        }

        [TestMethod]
        public void SetActive_PersistsAttribute()
        {
            using (var temp = new TempConfig())
            {
                var config = Reload();
                config.TaskConfigurations.First().Active = false;

                var reloaded = Reload().TaskConfigurations.First();
                Assert.IsFalse(reloaded.Active);

                var attr = XDocument.Load(temp.FilePath).Descendants("Task").First().Attribute("Active");
                Assert.AreEqual("false", attr.Value);
            }
        }

        [TestMethod]
        public void SetRegexBoosters_ReplacesBoosters()
        {
            using (new TempConfig())
            {
                var config = Reload();
                config.TaskConfigurations.First().SetRegexBoosters(new[] { "a", "b" });

                var reloaded = Reload().TaskConfigurations.First();
                CollectionAssert.AreEqual(new[] { "a", "b" }, reloaded.RegexBoosters.ToList());
            }
        }

        [TestMethod]
        public void AddTask_ThenSetProperties_ReloadsIdentically()
        {
            using (new TempConfig())
            {
                var config = Reload();
                var task = config.AddTask("New");
                task.Description = "desc";
                task.LockTime = 7200;
                task.OnlyNewEvents = true;
                task.EventAge = 300;
                task.TriggerCount = 7;
                task.PermaBanCount = -1;
                task.EventPath = "Security,Application";
                task.Regex = "(x)";
                task.SetRegexBoosters(new[] { "one", "two" });
                task.Active = true;

                var r = Reload().TaskConfigurations.Single(t => t.TaskName == "New");
                Assert.AreEqual("desc", r.Description);
                Assert.AreEqual(7200, r.LockTime);
                Assert.IsTrue(r.OnlyNewEvents);
                Assert.AreEqual(300, r.EventAge);
                Assert.AreEqual(7, r.TriggerCount);
                Assert.AreEqual(-1, r.PermaBanCount);
                Assert.AreEqual("Security,Application", r.EventPath);
                Assert.AreEqual("(x)", r.Regex);
                CollectionAssert.AreEqual(new[] { "one", "two" }, r.RegexBoosters.ToList());
                Assert.IsTrue(r.Active);
            }
        }

        [TestMethod]
        public void AddTask_DuplicateName_Throws()
        {
            using (new TempConfig())
            {
                var config = Reload();
                Assert.ThrowsExactly<InvalidOperationException>(() => config.AddTask("Sample"));
            }
        }

        [TestMethod]
        public void AddTask_RoundTripsXmlSpecialCharacters()
        {
            using (new TempConfig())
            {
                const string name = "A<&\"'>";
                const string regex = @"<Data Name=.IpAddress.>(\d+)</Data>";
                var config = Reload();
                var task = config.AddTask(name);
                task.Regex = regex;

                var r = Reload().TaskConfigurations.Single(t => t.TaskName == name);
                Assert.AreEqual(name, r.TaskName);
                Assert.AreEqual(regex, r.Regex);
            }
        }
    }
}
