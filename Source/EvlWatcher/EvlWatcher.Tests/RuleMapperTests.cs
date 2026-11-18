using System.Collections.Generic;
using System.Linq;
using EvlWatcher.Config;
using EvlWatcher.WCF.DTO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests
{
    [TestClass]
    public class RuleMapperTests
    {
        private static XmlServiceConfiguration Reload()
        {
            var config = new XmlServiceConfiguration(new NullLogger());
            config.Load();
            return config;
        }

        [TestMethod]
        public void ToDto_SplitsEventPathAndFlagsMissingLogs()
        {
            using (new TempConfig())
            {
                var task = Reload().TaskConfigurations.First();
                task.EventPath = "Security, Foo/Bar,";

                var dto = RuleMapper.ToDto(task, name => name == "Security");

                CollectionAssert.AreEqual(new[] { "Security", "Foo/Bar" }, dto.EventPath.ToList());
                CollectionAssert.AreEqual(new[] { "Foo/Bar" }, dto.MissingEventLogs.ToList());
                Assert.AreEqual("Sample", dto.TaskName);
                Assert.AreEqual(5, dto.TriggerCount);
                CollectionAssert.AreEqual(new[] { "Sample" }, dto.RegexBoosters.ToList());
            }
        }

        [TestMethod]
        public void Apply_JoinsEventPathAndSetsAllFields()
        {
            using (new TempConfig())
            {
                var task = Reload().TaskConfigurations.First();
                var dto = new GenericIPBlockingTaskDTO
                {
                    TaskName = "Ignored",
                    Active = false,
                    Description = "new desc",
                    LockTime = 600,
                    OnlyNewEvents = true,
                    EventAge = 30,
                    TriggerCount = 7,
                    PermaBanCount = -1,
                    EventPath = new List<string> { "Security", "Application" },
                    RegexBoosters = new List<string> { "a", "b" },
                    Regex = "x(y)"
                };

                RuleMapper.Apply(dto, task);

                var t = Reload().TaskConfigurations.First();
                Assert.AreEqual("Sample", t.TaskName);
                Assert.IsFalse(t.Active);
                Assert.AreEqual("new desc", t.Description);
                Assert.AreEqual(600, t.LockTime);
                Assert.IsTrue(t.OnlyNewEvents);
                Assert.AreEqual(30, t.EventAge);
                Assert.AreEqual(7, t.TriggerCount);
                Assert.AreEqual(-1, t.PermaBanCount);
                Assert.AreEqual("Security,Application", t.EventPath);
                CollectionAssert.AreEqual(new[] { "a", "b" }, t.RegexBoosters.ToList());
                Assert.AreEqual("x(y)", t.Regex);
            }
        }

        [TestMethod]
        public void Apply_FailingMidway_DoesNotActivateNewRule()
        {
            using (new TempConfig())
            {
                var config = Reload();
                var task = config.AddTask("Fresh");
                Assert.IsFalse(task.Active);
                var dto = new GenericIPBlockingTaskDTO
                {
                    Active = true,
                    Description = "bad\vchar",
                    LockTime = 600, EventAge = 30, TriggerCount = 7, PermaBanCount = 1,
                    EventPath = new List<string> { "Security" },
                    RegexBoosters = new List<string> { "a" },
                    Regex = "x(y)"
                };

                Assert.ThrowsExactly<System.ArgumentException>(() => RuleMapper.Apply(dto, task));

                Assert.IsFalse(Reload().TaskConfigurations.First(t => t.TaskName == "Fresh").Active);
            }
        }

        [TestMethod]
        public void RemoveTask_RemovesFromFileAndMemory()
        {
            using (new TempConfig())
            {
                var config = Reload();
                config.AddTask("Fresh");

                Assert.IsTrue(config.RemoveTask("Fresh"));

                Assert.IsFalse(config.TaskConfigurations.Any(t => t.TaskName == "Fresh"));
                Assert.IsFalse(Reload().TaskConfigurations.Any(t => t.TaskName == "Fresh"));
                Assert.IsTrue(Reload().TaskConfigurations.Any(t => t.TaskName == "Sample"));
                Assert.IsFalse(config.RemoveTask("Fresh"));
            }
        }

        [TestMethod]
        public void NewRule_ApplyFailsThenRollback_LeavesNoTaskAndAllowsRetry()
        {
            using (new TempConfig())
            {
                var config = Reload();
                var task = config.AddTask("Fresh");
                var dto = new GenericIPBlockingTaskDTO
                {
                    Active = true,
                    Description = "bad\vchar",
                    LockTime = 600, EventAge = 30, TriggerCount = 7, PermaBanCount = 1,
                    EventPath = new List<string> { "Security" },
                    RegexBoosters = new List<string> { "a" },
                    Regex = "x(y)"
                };
                Assert.ThrowsExactly<System.ArgumentException>(() => RuleMapper.Apply(dto, task));

                config.RemoveTask("Fresh");

                Assert.IsFalse(Reload().TaskConfigurations.Any(t => t.TaskName == "Fresh"));
                config.AddTask("Fresh");
            }
        }
    }
}
