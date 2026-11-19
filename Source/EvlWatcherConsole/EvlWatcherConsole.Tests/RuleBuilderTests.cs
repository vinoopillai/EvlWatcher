using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using EvlWatcher.WCF.DTO;
using EvlWatcherConsole.Rules;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    [TestClass]
    public class RuleBuilderTests
    {
        private const string ParseError = "That doesn't look like an event's XML. Make sure you copied it from the XML View.";

        private static string Sample(string name) =>
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", name));

        private static ParsedEvent Parse(string sample)
        {
            Assert.IsTrue(RuleBuilder.TryParse(Sample(sample), out ParsedEvent ev, out string error), error);
            return ev;
        }

        [TestMethod]
        public void TryParse_RejectsPlainText()
        {
            string text = "Log Name: Security\r\nSource: Microsoft-Windows-Security-Auditing\r\nEvent ID: 4625";
            Assert.IsFalse(RuleBuilder.TryParse(text, out ParsedEvent ev, out string error));
            Assert.IsNull(ev);
            Assert.AreEqual(ParseError, error);
        }

        [TestMethod]
        public void TryParse_AcceptsLeadingWhitespaceAndNoNamespace()
        {
            string xml = "\r\n  ﻿<Event><System><Provider Name='X'/><EventID>1</EventID><Channel>Application</Channel></System>"
                       + "<EventData><Data Name='IpAddress'>203.0.113.1</Data></EventData></Event>  \r\n";
            Assert.IsTrue(RuleBuilder.TryParse(xml, out ParsedEvent ev, out string error), error);
            Assert.AreEqual("X", ev.Provider);
            Assert.AreEqual(1, ev.Candidates.Count);
        }

        [TestMethod]
        public void TryParse_AcceptsEventViewerCollapseMarkers()
        {
            // copied from Event Viewer's XML View: expandable elements are prefixed with "- " (and leading spaces)
            string pasted =
                "- <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\r\n" +
                "- <System>\r\n" +
                "  <Provider Name=\"MSSQLSERVER\" /> \r\n" +
                "  <EventID Qualifiers=\"49152\">18456</EventID> \r\n" +
                "  <Channel>Application</Channel> \r\n" +
                "  </System>\r\n" +
                "- <EventData>\r\n" +
                "  <Data>sa</Data> \r\n" +
                "  <Data>Reason: An error occurred while evaluating the password. - check the password</Data> \r\n" +
                "  <Data>[CLIENT: 203.0.113.44]</Data> \r\n" +
                "  </EventData>\r\n" +
                "  </Event>";

            Assert.IsTrue(RuleBuilder.TryParse(pasted, out ParsedEvent ev, out string error), error);
            Assert.AreEqual("MSSQLSERVER", ev.Provider);
            Assert.AreEqual("18456", ev.EventId);
            Assert.AreEqual("Application", ev.Channel);
            // text content that merely contains " - " is untouched
            StringAssert.Contains(ev.PastedText, "evaluating the password. - check the password");
            StringAssert.Contains(ev.CompactXml, "evaluating the password. - check the password");
        }

        [TestMethod]
        public void TryParse_RejectsNonEventRootAndEmpty()
        {
            Assert.IsFalse(RuleBuilder.TryParse("<Foo/>", out _, out string e1));
            Assert.AreEqual(ParseError, e1);
            Assert.IsFalse(RuleBuilder.TryParse("", out _, out _));
            Assert.IsFalse(RuleBuilder.TryParse(null, out _, out _));
        }

        [TestMethod]
        [DataRow("<Event><System><Provider Name='X'/><EventID>1</EventID></System></Event>")]
        [DataRow("<Event><System><EventID>1</EventID><Channel>Security</Channel></System></Event>")]
        [DataRow("<Event><System><Provider Name='X'/><Channel>Security</Channel></System></Event>")]
        [DataRow("<Event><EventData><Data Name='IpAddress'>203.0.113.1</Data></EventData></Event>")]
        public void TryParse_RejectsEventMissingChannel(string xml)
        {
            Assert.IsFalse(RuleBuilder.TryParse(xml, out ParsedEvent ev, out string error));
            Assert.IsNull(ev);
            Assert.AreEqual("This event is missing its source, ID or log name, so EvlWatcher can't build a rule from it.", error);
        }

        [TestMethod]
        public void TryParse_ReadsProviderEventIdChannel()
        {
            ParsedEvent ev = Parse("security-4625-pretty.xml");
            Assert.AreEqual("Microsoft-Windows-Security-Auditing", ev.Provider);
            Assert.AreEqual("4625", ev.EventId);
            Assert.AreEqual("Security", ev.Channel);
        }

        [TestMethod]
        public void Candidates_FindsNamedDataField()
        {
            ParsedEvent ev = Parse("security-4625-pretty.xml");
            Assert.AreEqual(1, ev.Candidates.Count);
            IpCandidate c = ev.Candidates[0];
            Assert.AreEqual("IpAddress", c.FieldLabel);
            Assert.AreEqual("Data", c.ElementName);
            Assert.IsTrue(c.IsNamedData);
            Assert.AreEqual(IPAddress.Parse("203.0.113.7"), c.Address);
            Assert.IsFalse(c.IsLocal);
        }

        [TestMethod]
        public void Candidates_FindsUserDataElement()
        {
            ParsedEvent ev = Parse("userdata-rdpcore.xml");
            Assert.AreEqual(1, ev.Candidates.Count);
            Assert.AreEqual("Address", ev.Candidates[0].FieldLabel);
            Assert.AreEqual("Address", ev.Candidates[0].ElementName);
            Assert.IsFalse(ev.Candidates[0].IsNamedData);
            Assert.AreEqual(IPAddress.Parse("198.51.100.4"), ev.Candidates[0].Address);
        }

        [TestMethod]
        public void Candidates_IncludeIpv6AndMappedAddresses()
        {
            ParsedEvent ev = Parse("ipv6.xml");
            Assert.AreEqual(2, ev.Candidates.Count);
            Assert.AreEqual(IPAddress.Parse("2001:db8::1a2b"), ev.Candidates[0].Address);
            Assert.AreEqual(IPAddress.Parse("::ffff:203.0.113.9"), ev.Candidates[1].Address);
            Assert.AreEqual("ForwardedFrom", ev.Candidates[1].FieldLabel);
        }

        [TestMethod]
        public void Candidates_MarksLoopbackLocal()
        {
            ParsedEvent ev = Parse("loopback.xml");
            Assert.AreEqual(1, ev.Candidates.Count);
            Assert.IsTrue(ev.Candidates[0].IsLocal);
        }

        [TestMethod]
        public void Candidates_FreeTextOnly_IsEmpty()
        {
            Assert.AreEqual(0, Parse("freetext-only.xml").Candidates.Count);
        }

        [TestMethod]
        public void Candidates_IgnoreBareNumbers()
        {
            Assert.IsTrue(RuleBuilder.TryParse(
                "<Event><System><Provider Name='P'/><EventID>1</EventID><Channel>C</Channel></System><EventData><Data Name='IpPort'>4625</Data></EventData></Event>",
                out ParsedEvent ev, out _));
            Assert.AreEqual(0, ev.Candidates.Count);
        }

        [TestMethod]
        public void BuildRule_UsesSpecDefaultsAndPatterns()
        {
            ParsedEvent ev = Parse("security-4625-pretty.xml");
            GenericIPBlockingTaskDTO rule = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            Assert.AreEqual("Security-Auditing 4625", rule.TaskName);
            Assert.AreEqual("Bans IPs found in IpAddress of event 4625 from Microsoft-Windows-Security-Auditing.", rule.Description);
            CollectionAssert.AreEqual(new[] { "Microsoft-Windows-Security-Auditing", ">4625</EventID>" }, rule.RegexBoosters.ToArray());
            Assert.AreEqual("<Data Name=.IpAddress.>([0-9A-Fa-f:.]+)</Data>", rule.Regex);
            CollectionAssert.AreEqual(new[] { "Security" }, rule.EventPath.ToArray());
            Assert.IsTrue(rule.Active);
            Assert.AreEqual(5, rule.TriggerCount);
            Assert.AreEqual(120, rule.EventAge);
            Assert.AreEqual(3600, rule.LockTime);
            Assert.AreEqual(3, rule.PermaBanCount);
        }

        [TestMethod]
        public void BuildRule_NonNamedElementPattern()
        {
            ParsedEvent ev = Parse("userdata-rdpcore.xml");
            GenericIPBlockingTaskDTO rule = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            Assert.AreEqual("<Address(?:\\s[^>]*)?>([0-9A-Fa-f:.]+)</Address>", rule.Regex);
            Assert.AreEqual("RemoteDesktopServices-RdpCoreTS 140", rule.TaskName);
        }

        [TestMethod]
        public void BuildRule_MakesNameUnique()
        {
            ParsedEvent ev = Parse("security-4625-pretty.xml");
            var existing = new List<string> { "Security-Auditing 4625" };
            Assert.AreEqual("Security-Auditing 4625 (2)", RuleBuilder.BuildRule(ev, ev.Candidates[0], existing).TaskName);
            existing.Add("Security-Auditing 4625 (2)");
            Assert.AreEqual("Security-Auditing 4625 (3)", RuleBuilder.BuildRule(ev, ev.Candidates[0], existing).TaskName);
        }

        [TestMethod]
        [DataRow("security-4625-pretty.xml")]
        [DataRow("qualifiers.xml")]
        [DataRow("userdata-rdpcore.xml")]
        [DataRow("ipv6.xml")]
        public void SelfTest_PassesOnPrettyAndCompactForEverySample(string sample)
        {
            ParsedEvent ev = Parse(sample);
            Assert.IsTrue(ev.Candidates.Count > 0);
            foreach (IpCandidate c in ev.Candidates)
            {
                GenericIPBlockingTaskDTO rule = RuleBuilder.BuildRule(ev, c, new List<string>());
                Assert.IsTrue(RuleBuilder.SelfTest(rule, ev, c.Address), $"{sample}: {c.FieldLabel}");
            }
        }

        [TestMethod]
        public void SelfTest_FailsForWrongExpectedIp()
        {
            ParsedEvent ev = Parse("security-4625-pretty.xml");
            GenericIPBlockingTaskDTO rule = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            Assert.IsFalse(RuleBuilder.SelfTest(rule, ev, IPAddress.Parse("203.0.113.8")));
        }

        [TestMethod]
        public void CompactXml_IsSingleLineSingleQuoted()
        {
            ParsedEvent ev = Parse("security-4625-pretty.xml");
            Assert.IsFalse(ev.CompactXml.Contains('\n'));
            Assert.IsFalse(ev.CompactXml.Contains('"'));
            StringAssert.Contains(ev.CompactXml, "<Data Name='IpAddress'>203.0.113.7</Data>");
            StringAssert.Contains(ev.CompactXml, "<Provider Name='Microsoft-Windows-Security-Auditing'");
        }

        [TestMethod]
        public void Match_QualifiersEventId_MatchesBooster()
        {
            ParsedEvent ev = Parse("qualifiers.xml");
            Assert.AreEqual("18456", ev.EventId);
            GenericIPBlockingTaskDTO rule = RuleBuilder.BuildRule(ev, ev.Candidates[0], new List<string>());
            Assert.AreEqual(IPAddress.Parse("198.51.100.23"), RuleBuilder.Match(rule, ev.PastedText));
            Assert.AreEqual(IPAddress.Parse("198.51.100.23"), RuleBuilder.Match(rule, ev.CompactXml));
        }

        [TestMethod]
        public void Match_ReturnsNullWhenBoosterMissingOrIpInvalid()
        {
            var rule = new GenericIPBlockingTaskDTO
            {
                RegexBoosters = new List<string> { "nope" },
                Regex = "<A>([0-9.]+)</A>"
            };
            Assert.IsNull(RuleBuilder.Match(rule, "<A>203.0.113.1</A>"));
            rule.RegexBoosters = new List<string> { "A" };
            Assert.IsNull(RuleBuilder.Match(rule, "<A>999.1.1.1.1</A>"));
            Assert.AreEqual(IPAddress.Parse("203.0.113.1"), RuleBuilder.Match(rule, "<A>203.0.113.1</A>"));
        }

        [TestMethod]
        public void FindCoveringRule_ReturnsExistingRuleName()
        {
            // values copied from EvlWatcher/config.xml (trimmed like the service loader does)
            var shipped = new GenericIPBlockingTaskDTO
            {
                TaskName = "BlockRDPBrutersBySecurity4625",
                Active = true,
                RegexBoosters = new List<string> { "4625", "IpAddress" },
                Regex = @"<Data Name=.IpAddress.>(\d*.\d*.\d*.\d*)"
            };
            var other = new GenericIPBlockingTaskDTO
            {
                TaskName = "Other", Active = true,
                RegexBoosters = new List<string> { "zzz" }, Regex = "(x)"
            };
            foreach (string sample in new[] { "security-4625-pretty.xml", "security-4625-compact.xml" })
            {
                ParsedEvent ev = Parse(sample);
                Assert.AreEqual("BlockRDPBrutersBySecurity4625", RuleBuilder.FindCoveringRule(new[] { other, shipped }, ev), sample);
            }

            shipped.Active = false;
            Assert.IsNull(RuleBuilder.FindCoveringRule(new[] { other, shipped }, Parse("security-4625-pretty.xml")));
        }

        [TestMethod]
        public void ShortProviderName_StripsPrefix()
        {
            Assert.AreEqual("Security-Auditing", RuleBuilder.ShortProviderName("Microsoft-Windows-Security-Auditing"));
            Assert.AreEqual("MSSQLSERVER", RuleBuilder.ShortProviderName("MSSQLSERVER"));
        }
    }
}
