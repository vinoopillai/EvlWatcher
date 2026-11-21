using System;
using System.IO;
using System.Net;
using EvlWatcher.Geo;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests.Integration
{
    /// <summary>
    /// Opt-in check against real registry files (e.g. from NSIS\fetch-geo.ps1): set EVLWATCHER_GEO_DIR to that folder.
    /// Skipped otherwise, so the normal test run needs no network or downloads.
    /// </summary>
    [TestClass]
    public class RealRegistryDataTests
    {
        [TestMethod]
        [TestCategory("RealData")]
        public void RealFilesLoadAndLocateIndia()
        {
            string? folder = Environment.GetEnvironmentVariable("EVLWATCHER_GEO_DIR");
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                Assert.Inconclusive("Set EVLWATCHER_GEO_DIR to a folder with the registries' delegated-*.txt files.");

            var logger = new TestLogger();
            var service = new CountryDataService(folder, new FakeDownloader(), logger, () => DateTime.UtcNow);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            service.Load();
            watch.Stop();

            CountryDataStatus status = service.GetStatus();
            Console.WriteLine($"{status.RangeCount} ranges from {string.Join(", ", status.Registries)} in {watch.ElapsedMilliseconds} ms");
            foreach (string ip in new[] { "103.228.149.59", "182.70.246.15", "223.181.87.130", "103.30.30.123", "5.175.140.23",
                                          "94.203.133.74", "148.113.55.45", "195.7.7.119", "88.214.25.124", "2401:4900::1" })
                Console.WriteLine($"{ip,-16} {service.GetCountry(IPAddress.Parse(ip)) ?? "(unknown)"}");

            Assert.AreEqual(5, status.Registries.Count);
            Assert.IsTrue(status.RangeCount > 100000);
            Assert.AreEqual("IN", service.GetCountry(IPAddress.Parse("103.228.149.59")));
            Assert.AreEqual("IN", service.GetCountry(IPAddress.Parse("2401:4900::1")));
            Assert.IsNull(service.GetCountry(IPAddress.Parse("192.168.1.5")));
        }
    }
}
