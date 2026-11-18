using System;
using System.Collections.Generic;
using EvlWatcher.Config;
using EvlWatcher.WCF.DTO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests
{
    [TestClass]
    public class RuleValidatorTests
    {
        private static GenericIPBlockingTaskDTO ValidRule()
        {
            return new GenericIPBlockingTaskDTO
            {
                TaskName = "My rule",
                Description = "d",
                Active = true,
                TriggerCount = 5,
                EventAge = 120,
                LockTime = 3600,
                PermaBanCount = 3,
                EventPath = new List<string> { "Security" },
                RegexBoosters = new List<string> { "Foo" },
                Regex = "<Data>([0-9.]+)</Data>"
            };
        }

        private static IList<string> Validate(GenericIPBlockingTaskDTO rule, bool isNew = true, string[] existing = null, Func<string, bool> logExists = null)
        {
            return RuleValidator.Validate(rule, isNew, existing ?? new string[0], logExists ?? (_ => true));
        }

        [TestMethod]
        public void ValidRule_HasNoMessages()
        {
            Assert.AreEqual(0, Validate(ValidRule()).Count);
        }

        [TestMethod]
        public void TriggerCountZero_IsRejected()
        {
            var r = ValidRule(); r.TriggerCount = 0;
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void EventAgeBelowTen_IsRejected()
        {
            var r = ValidRule(); r.EventAge = 9;
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void LockTimeBelowSixty_IsRejectedWithMessage()
        {
            var r = ValidRule(); r.LockTime = 59;
            var messages = Validate(r);
            Assert.AreEqual(1, messages.Count);
            Assert.AreEqual("Ban length must be at least 1 minute.", messages[0]);
        }

        [TestMethod]
        public void PermaBanCountZero_IsRejected()
        {
            var r = ValidRule(); r.PermaBanCount = 0;
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void PermaBanCountNegative_IsValid()
        {
            var r = ValidRule(); r.PermaBanCount = -1;
            Assert.AreEqual(0, Validate(r).Count);
        }

        [TestMethod]
        public void EmptyName_IsRejected()
        {
            var r = ValidRule(); r.TaskName = "  ";
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void NameLongerThan64_IsRejected()
        {
            var r = ValidRule(); r.TaskName = new string('a', 65);
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void NameOf64_IsValid()
        {
            var r = ValidRule(); r.TaskName = new string('a', 64);
            Assert.AreEqual(0, Validate(r).Count);
        }

        [TestMethod]
        public void DuplicateName_WhenNew_IsRejected()
        {
            var r = ValidRule(); r.TaskName = " My rule ";
            Assert.AreEqual(1, Validate(r, true, new[] { "My rule" }).Count);
        }

        [TestMethod]
        public void UnknownName_WhenUpdating_IsRejected()
        {
            Assert.AreEqual(1, Validate(ValidRule(), false, new[] { "Other" }).Count);
        }

        [TestMethod]
        public void ExistingName_WhenUpdating_IsValid()
        {
            Assert.AreEqual(0, Validate(ValidRule(), false, new[] { "My rule" }).Count);
        }

        [TestMethod]
        public void RegexThatDoesNotCompile_IsRejected()
        {
            var r = ValidRule(); r.Regex = "(";
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void RegexWithTwoGroups_IsRejected()
        {
            var r = ValidRule(); r.Regex = "(a)(b)";
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void RegexWithoutGroup_IsRejected()
        {
            var r = ValidRule(); r.Regex = "abc";
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void NoEventLog_IsRejected()
        {
            var r = ValidRule(); r.EventPath = new List<string>();
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void MissingEventLog_WhenNew_IsRejected()
        {
            Assert.AreEqual(1, Validate(ValidRule(), true, null, _ => false).Count);
        }

        [TestMethod]
        public void MissingEventLog_WhenUpdating_IsValidAndNotChecked()
        {
            var checkedLogs = 0;
            var messages = Validate(ValidRule(), false, new[] { "My rule" }, _ => { checkedLogs++; return false; });
            Assert.AreEqual(0, messages.Count);
            Assert.AreEqual(0, checkedLogs);
        }

        [TestMethod]
        public void NoBooster_IsRejected()
        {
            var r = ValidRule(); r.RegexBoosters = new List<string>();
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        public void BlankBooster_IsRejected()
        {
            var r = ValidRule(); r.RegexBoosters = new List<string> { " " };
            Assert.AreEqual(1, Validate(r).Count);
        }

        [TestMethod]
        [DataRow("\v")]
        [DataRow("\0")]
        [DataRow("SURR")]
        public void UnsavableCharacters_AreRejectedPerField(string bad)
        {
            if (bad == "SURR") bad = new string((char)0xD800, 1);
            var r = ValidRule(); r.TaskName = "a" + bad + "b";
            Assert.AreEqual(1, Validate(r).Count, "name");
            r = ValidRule(); r.Description = "a" + bad;
            Assert.AreEqual(1, Validate(r).Count, "description");
            r = ValidRule(); r.Regex = "(a" + bad + ")";
            Assert.IsTrue(Validate(r).Count >= 1, "regex");
            r = ValidRule(); r.EventPath = new List<string> { "Sec" + bad };
            Assert.AreEqual(1, Validate(r).Count, "path");
            r = ValidRule(); r.RegexBoosters = new List<string> { "x" + bad };
            Assert.AreEqual(1, Validate(r).Count, "booster");
        }

        [TestMethod]
        public void ValidSurrogatePair_IsAccepted()
        {
            var r = ValidRule(); r.Description = "ok \ud83d\ude00";
            Assert.AreEqual(0, Validate(r).Count);
        }
    }
}
