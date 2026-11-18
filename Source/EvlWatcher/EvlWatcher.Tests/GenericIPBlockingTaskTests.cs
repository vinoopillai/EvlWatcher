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
    public class GenericIPBlockingTaskTests
    {
        private sealed class FakeTaskConfig : IPersistentTaskConfiguration
        {
            private readonly List<string> _boosters = new List<string> { "ip=" };

            public bool Active { get; set; } = true;
            public string TaskName { get; set; } = "Fake";
            public string Description { get; set; } = "fake";
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

        private static readonly IPAddress Ip = IPAddress.Parse("203.0.113.7");

        private static GenericIPBlockingTask NewTask(int permaBanCount = 3, bool active = true)
        {
            return GenericIPBlockingTask.FromConfiguration(
                new FakeTaskConfig { PermaBanCount = permaBanCount, Active = active }, new NullLogger());
        }

        private static List<ExtractedEventRecord> Events(DateTime time, int count = 2)
        {
            return Enumerable.Range(0, count)
                .Select(i => new ExtractedEventRecord { TimeCreated = time, Xml = "ip=203.0.113.7" })
                .ToList();
        }

        [TestMethod]
        public void CarryOver_KeepsTemporaryBan()
        {
            var old = NewTask();
            old.ProvideEvents(Events(DateTime.Now));
            Assert.AreEqual(1, old.GetTempBanVictims().Count);

            var fresh = NewTask();
            fresh.CarryOverStateFrom(old);

            CollectionAssert.AreEqual(new[] { Ip }, fresh.GetTempBanVictims());
        }

        [TestMethod]
        public void CarryOver_CopiesEntriesNotReferences()
        {
            var old = NewTask();
            old.ProvideEvents(Events(DateTime.Now));
            var fresh = NewTask();
            fresh.CarryOverStateFrom(old);

            old.Forget(Ip);

            Assert.AreEqual(1, fresh.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void CarryOver_KeepsStrikeCount()
        {
            var old = NewTask(permaBanCount: 2);
            old.ProvideEvents(Events(DateTime.Now)); // strike 1
            Assert.AreEqual(0, old.GetPermaBanVictims().Count);

            var fresh = NewTask(permaBanCount: 2);
            fresh.CarryOverStateFrom(old);
            fresh.LockTime = -1; // let the carried temp ban expire so a second cycle can happen
            Assert.AreEqual(0, fresh.GetTempBanVictims().Count);

            fresh.ProvideEvents(Events(DateTime.Now)); // strike 2
            CollectionAssert.AreEqual(new[] { Ip }, fresh.GetPermaBanVictims());
        }

        [TestMethod]
        public void CarryOver_KeepsForgottenIp()
        {
            var old = NewTask();
            old.Forget(Ip);

            var fresh = NewTask();
            fresh.CarryOverStateFrom(old);
            fresh.ProvideEvents(Events(DateTime.Now.AddSeconds(-30)));

            Assert.AreEqual(0, fresh.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void WithoutCarryOver_ForgottenIpIsRebanned()
        {
            var old = NewTask();
            old.Forget(Ip);

            var fresh = NewTask();
            fresh.ProvideEvents(Events(DateTime.Now.AddSeconds(-30)));

            CollectionAssert.AreEqual(new[] { Ip }, fresh.GetTempBanVictims());
        }

        [TestMethod]
        public void CarryOver_NullPrevious_Throws()
        {
            try { NewTask().CarryOverStateFrom(null); }
            catch (ArgumentNullException) { return; }
            Assert.Fail("expected ArgumentNullException");
        }

        [TestMethod]
        public void CarryOver_Self_IsNoOp()
        {
            var t = NewTask();
            t.ProvideEvents(Events(DateTime.Now));
            t.CarryOverStateFrom(t);
            Assert.AreEqual(1, t.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void FromConfiguration_SetsActive()
        {
            Assert.IsTrue(NewTask(active: true).Active);
            Assert.IsFalse(NewTask(active: false).Active);
        }
    }
}
