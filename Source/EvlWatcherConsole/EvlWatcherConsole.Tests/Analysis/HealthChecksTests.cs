using System;
using System.Collections.Generic;
using System.Linq;
using EvlWatcherConsole.Analysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests.Analysis
{
    [TestClass]
    public class HealthChecksTests
    {
        private static readonly DateTime T0 = EventSamples.Utc("2026-11-20T20:00:00Z");

        private static IList<Finding> Run(params AnalyzedEvent[] events) =>
            HealthChecks.Run(events.GroupBy(e => e.LogName).ToDictionary(g => g.Key, g => (IList<AnalyzedEvent>)g.ToList()),
                new AnalyzerInput { NowUtc = EventSamples.Utc("2026-11-21T00:30:00Z") });

        [TestMethod]
        public void DiskErrorIsCritical()
        {
            Finding f = Run(EventSamples.Disk7(T0), EventSamples.Disk7(T0.AddHours(1))).Single();
            Assert.AreEqual(FindingSeverity.Critical, f.Severity);
            Assert.AreEqual(FindingCategory.ServerHealth, f.Category);
            StringAssert.Contains(f.Advice, "Back up");
            Assert.AreEqual(T0.AddHours(1), f.LastSeenUtc);
        }

        [TestMethod]
        public void UnexpectedRestartIsWarning()
        {
            Assert.AreEqual(FindingSeverity.Warning, Run(EventSamples.KernelPower41(T0)).Single().Severity);
        }

        [TestMethod]
        public void TwoCrashesOfOneServiceIsWarningOneIsInfo()
        {
            IList<Finding> findings = Run(EventSamples.ServiceCrash7031("Spooler", T0), EventSamples.ServiceCrash7031("Spooler", T0.AddHours(1)),
                                          EventSamples.ServiceCrash7031("W32Time", T0));
            Assert.AreEqual(FindingSeverity.Warning, findings.Single(f => f.Title.Contains("Spooler")).Severity);
            Assert.AreEqual(FindingSeverity.Info, findings.Single(f => f.Title.Contains("W32Time")).Severity);
        }

        [TestMethod]
        public void SingleAppCrashIsInfoThreeIsWarning()
        {
            IList<Finding> findings = Run(EventSamples.AppCrash1000("tally.exe", T0),
                EventSamples.AppCrash1000("sqlservr.exe", T0), EventSamples.AppCrash1000("sqlservr.exe", T0.AddMinutes(1)),
                EventSamples.AppCrash1000("sqlservr.exe", T0.AddMinutes(2)));
            Assert.AreEqual(FindingSeverity.Info, findings.Single(f => f.Title.Contains("tally.exe")).Severity);
            Assert.AreEqual(FindingSeverity.Warning, findings.Single(f => f.Title.Contains("sqlservr.exe")).Severity);
        }

        [TestMethod]
        public void SameIdOtherProviderIsIgnored()
        {
            Assert.AreEqual(0, Run(EventSamples.Other(EventSamples.System, "Foo", 7, T0),
                                   EventSamples.Other(EventSamples.Application, "Foo", 1000, T0)).Count);
        }

        [TestMethod]
        public void SecurityLogFullIsCritical()
        {
            Finding f = Run(EventSamples.SecurityLogFull1104(T0)).Single();
            Assert.AreEqual(FindingSeverity.Critical, f.Severity);
            StringAssert.Contains(f.Advice, "EvlWatcher");
        }
    }
}
