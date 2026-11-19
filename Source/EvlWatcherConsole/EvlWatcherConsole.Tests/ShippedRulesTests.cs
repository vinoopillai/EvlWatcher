using System.Net;
using System.Xml.Linq;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Rules;

namespace EvlWatcherConsole.Tests
{
    /// <summary>
    /// Runs the rules shipped in EvlWatcher/config.xml against real event samples, using the same matching as the service
    /// (all boosters contained, then the regex, capture group 1 = IP) on both the pasted and the compact (EventRecord.ToXml) form.
    /// </summary>
    [TestClass]
    public class ShippedRulesTests
    {
        private static GenericIPBlockingTaskDTO ShippedRule(string taskName)
        {
            XDocument config = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "ShippedConfig", "config.xml"));
            XElement task = config.Descendants("Task").Single(t => (string)t.Attribute("Name") == taskName);

            // read like the service loader (XmlTaskConfig.FromXmlElement): trimmed values, boosters as written
            return new GenericIPBlockingTaskDTO
            {
                TaskName = taskName,
                Active = bool.Parse(task.Attribute("Active").Value),
                EventPath = task.Element("EventPath").Value.Split(',').Select(p => p.Trim()).Where(p => p.Length > 0).ToList(),
                RegexBoosters = task.Element("RegexBoosters").Elements("Booster").Select(b => b.Value).ToList(),
                Regex = task.Element("Regex").Value.Trim(),
            };
        }

        private static ParsedEvent Sample(string name)
        {
            string text = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", name));
            Assert.IsTrue(RuleBuilder.TryParse(text, out ParsedEvent ev, out string error), error);
            return ev;
        }

        [TestMethod]
        [DataRow("mssql-18456-evaluating-password.xml", "203.0.113.44")]
        [DataRow("mssql-18456-password-mismatch.xml", "203.0.113.45")]
        public void MssqlRule_CatchesFailedLoginWhateverTheReason(string sample, string expectedIp)
        {
            GenericIPBlockingTaskDTO rule = ShippedRule("BlockMSSQLBruteforce");
            ParsedEvent ev = Sample(sample);

            Assert.IsTrue(rule.Active);
            CollectionAssert.Contains(rule.EventPath.ToList(), ev.Channel);
            Assert.AreEqual(IPAddress.Parse(expectedIp), RuleBuilder.Match(rule, ev.PastedText), "pasted form");
            Assert.AreEqual(IPAddress.Parse(expectedIp), RuleBuilder.Match(rule, ev.CompactXml), "compact form the service matches");
        }

        [TestMethod]
        public void MssqlRule_IgnoresLocalMachineLogins()
        {
            GenericIPBlockingTaskDTO rule = ShippedRule("BlockMSSQLBruteforce");
            ParsedEvent ev = Sample("mssql-18456-local-machine.xml");

            Assert.IsNull(RuleBuilder.Match(rule, ev.PastedText));
            Assert.IsNull(RuleBuilder.Match(rule, ev.CompactXml));
        }
    }
}
