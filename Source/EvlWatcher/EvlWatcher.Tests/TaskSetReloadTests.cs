using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using EvlWatcher.Config;
using EvlWatcher.DTOs;
using EvlWatcher.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests
{
    [TestClass]
    public class TaskSetReloadTests
    {
        private sealed class Cfg : IPersistentTaskConfiguration
        {
            private readonly List<string> _boosters = new List<string> { "ip=" };

            public bool Active { get; set; } = true;
            public string TaskName { get; set; }
            public string Description { get; set; } = "d";
            public int LockTime { get; set; } = 3600;
            public bool OnlyNewEvents { get; set; } = false;
            public int EventAge { get; set; } = 120;
            public int TriggerCount { get; set; } = 2;
            public int PermaBanCount { get; set; } = 3;
            public string EventPath { get; set; } = "Security";
            public IQueryable<string> RegexBoosters => _boosters.AsQueryable();
            public string Regex { get; set; } = @"ip=(\S+)";

            public bool AddRegexBooster(string regexBooster) { _boosters.Add(regexBooster); return true; }
            public bool RemoveRegexBooster(string regexBooster) => _boosters.Remove(regexBooster);
            public void SetRegexBoosters(IEnumerable<string> boosters) { _boosters.Clear(); _boosters.AddRange(boosters); }
        }

        private sealed class StubTask : LogTask
        {
            public StubTask(string name) { Name = name; }
            protected override void OnComputeEvents(List<ExtractedEventRecord> events) { }
        }

        private static readonly IPAddress Ip = IPAddress.Parse("203.0.113.7");

        private static GenericIPBlockingTask NewTask(string name)
        {
            return GenericIPBlockingTask.FromConfiguration(new Cfg { TaskName = name }, new NullLogger());
        }

        private static GenericIPBlockingTask Banned(string name)
        {
            var t = NewTask(name);
            t.ProvideEvents(Enumerable.Range(0, 2)
                .Select(i => new ExtractedEventRecord { TimeCreated = DateTime.Now, Xml = "ip=203.0.113.7" }).ToList());
            Assert.AreEqual(1, t.GetTempBanVictims().Count);
            return t;
        }

        [TestMethod]
        public void CarryOverByName_MatchesOnlySameNames()
        {
            var oldA = Banned("A");
            var oldB = Banned("B");
            var newA = NewTask("A");
            var newC = NewTask("C");

            EvlWatcher.CarryOverByName(new LogTask[] { oldA, oldB }, new LogTask[] { newA, newC });

            CollectionAssert.AreEqual(new[] { Ip }, newA.GetTempBanVictims());
            Assert.AreEqual(0, newC.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void CarryOverByName_IgnoresNonGenericTasks()
        {
            var oldTasks = new LogTask[] { new StubTask("A"), Banned("B") };
            var newTasks = new LogTask[] { new StubTask("B"), NewTask("A") };

            EvlWatcher.CarryOverByName(oldTasks, newTasks);

            Assert.AreEqual(0, ((GenericIPBlockingTask)newTasks[1]).GetTempBanVictims().Count);
        }

        [TestMethod]
        public void Load_Twice_DoesNotDuplicateWhitelistOrBanlist()
        {
            using (var temp = new TempConfig())
            {
                var xml = System.IO.File.ReadAllText(temp.FilePath)
                    .Replace("<Banlist></Banlist>", "<Banlist>203.0.113.9;</Banlist>");
                System.IO.File.WriteAllText(temp.FilePath, xml);

                var config = new XmlServiceConfiguration(new NullLogger());
                config.Load();
                config.Load();

                Assert.AreEqual(1, config.WhitelistPatterns.Count());
                Assert.AreEqual(1, config.BlacklistAddresses.Count());
                Assert.AreEqual(1, config.TaskConfigurations.Count());
            }
        }

        [TestMethod]
        public void Load_BadBanlistAfterGoodLoad_KeepsPreviousLists()
        {
            using (var temp = new TempConfig())
            {
                var config = new XmlServiceConfiguration(new NullLogger());
                config.Load();

                var xml = System.IO.File.ReadAllText(temp.FilePath)
                    .Replace("<Banlist></Banlist>", "<Banlist>not-an-ip;</Banlist>")
                    .Replace("127.0.0.1;", "10.0.0.*;");
                System.IO.File.WriteAllText(temp.FilePath, xml);

                Assert.ThrowsExactly<FormatException>(() => config.Load());

                CollectionAssert.AreEqual(new[] { "127.0.0.1" }, config.WhitelistPatterns.ToArray());
                Assert.AreEqual(0, config.BlacklistAddresses.Count());
                Assert.AreEqual(1, config.TaskConfigurations.Count());
            }
        }

        [TestMethod]
        public void Load_BadTaskAfterGoodLoad_KeepsPreviousTasks()
        {
            using (var temp = new TempConfig())
            {
                var config = new XmlServiceConfiguration(new NullLogger());
                config.Load();

                var xml = System.IO.File.ReadAllText(temp.FilePath)
                    .Replace("<Banlist></Banlist>", "<Banlist>203.0.113.9;</Banlist>")
                    .Replace("<LockTime>3600</LockTime>", "<LockTime>abc</LockTime>");
                System.IO.File.WriteAllText(temp.FilePath, xml);

                Assert.ThrowsExactly<FormatException>(() => config.Load());

                Assert.AreEqual(0, config.BlacklistAddresses.Count());
                Assert.AreEqual("Sample", config.TaskConfigurations.Single().TaskName);
                Assert.AreEqual(3600, config.TaskConfigurations.Single().LockTime);
            }
        }
    }
}
