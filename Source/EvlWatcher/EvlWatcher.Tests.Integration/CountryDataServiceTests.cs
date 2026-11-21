using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using EvlWatcher.Geo;
using EvlWatcher.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcher.Tests.Integration
{
    internal sealed class TestLogger : ILogger
    {
        public readonly List<string> Messages = new List<string>();
        public SeverityLevel LogLevel { get; set; } = SeverityLevel.Debug;
        public void Dump(string message, SeverityLevel severity) { lock (Messages) Messages.Add(severity + ": " + message); }
        public void Dump(Exception e, SeverityLevel severity = SeverityLevel.Error) { lock (Messages) Messages.Add(severity + ": " + e.Message); }
        public int GetConsoleHistoryMaxCount() => 0;
        public void SetConsoleHistoryMaxCount(int count) { }
        public IList<LogEntry> GetConsoleHistory() => new List<LogEntry>();
    }

    internal sealed class FakeDownloader : IRegistryDownloader
    {
        public readonly Dictionary<string, string> Files = new Dictionary<string, string>();
        public readonly HashSet<string> Failing = new HashSet<string>();
        public int Calls;

        public string Download(string url)
        {
            Calls++;
            string registry = CountryDataService.Sources.Single(s => s.Value == url).Key;
            if (Failing.Contains(registry))
                throw new WebException("The remote name could not be resolved");
            return Files[registry];
        }
    }

    [TestClass]
    public class CountryDataServiceTests
    {
        private string _folder = "";

        [TestInitialize]
        public void Init()
        {
            _folder = Path.Combine(Path.GetTempPath(), "evlwatcher-geo-" + Guid.NewGuid().ToString("N"));
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_folder))
                Directory.Delete(_folder, true);
        }

        /// <summary>A registry file in the real format with <paramref name="count"/> /24 ranges starting at <paramref name="firstOctet"/>.x.</summary>
        internal static string RegistryFile(string registry, string cc, int firstOctet, int count)
        {
            var sb = new StringBuilder();
            sb.Append("2|").Append(registry).Append("|20261120|").Append(count).Append("|19830613|20261119|+0000\n");
            sb.Append(registry).Append("|*|ipv4|*|").Append(count).Append("|summary\n");
            for (int i = 0; i < count; i++)
                sb.Append(registry).Append('|').Append(cc).Append("|ipv4|").Append(firstOctet + i / 65536).Append('.')
                  .Append((i / 256) % 256).Append('.').Append(i % 256).Append(".0|256|20200101|allocated\n");
            return sb.ToString();
        }

        private static readonly (string registry, string cc, int octet)[] Registries =
        {
            ("apnic", "IN", 103), ("ripencc", "DE", 5), ("arin", "US", 20), ("lacnic", "BR", 177), ("afrinic", "ZA", 41)
        };

        private FakeDownloader AllRegistries(int count = 1200)
        {
            var d = new FakeDownloader();
            foreach (var r in Registries)
                d.Files[r.registry] = RegistryFile(r.registry, r.cc, r.octet, count);
            return d;
        }

        private CountryDataService Service(IRegistryDownloader downloader, DateTime? now = null) =>
            new CountryDataService(_folder, downloader, new TestLogger(), () => now ?? new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc));

        private void WriteFile(string registry, string content)
        {
            Directory.CreateDirectory(_folder);
            File.WriteAllText(Path.Combine(_folder, "delegated-" + registry + ".txt"), content);
        }

        [TestMethod]
        public void LoadReadsAllRegistryFiles()
        {
            foreach (var r in Registries)
                WriteFile(r.registry, RegistryFile(r.registry, r.cc, r.octet, 1200));
            CountryDataService s = Service(new FakeDownloader());

            s.Load();

            Assert.IsTrue(s.IsLoaded);
            Assert.AreEqual("IN", s.GetCountry(IPAddress.Parse("103.0.5.9")));
            Assert.AreEqual("DE", s.GetCountry(IPAddress.Parse("5.1.2.3")));
            Assert.AreEqual(5, s.GetStatus().Registries.Count);
        }

        [TestMethod]
        public void MissingFolderLoadsNothingAndReportsNotLoaded()
        {
            CountryDataService s = Service(new FakeDownloader());
            s.Load();
            Assert.IsFalse(s.IsLoaded);
            Assert.IsFalse(s.GetStatus().Loaded);
            Assert.IsNull(s.GetCountry(IPAddress.Parse("103.0.5.9")));
        }

        [TestMethod]
        public void CorruptFileIsSkippedOthersLoad()
        {
            WriteFile("apnic", RegistryFile("apnic", "IN", 103, 1200));
            WriteFile("ripencc", "this is not a registry file\n\u0000\u0001");
            CountryDataService s = Service(new FakeDownloader());

            s.Load();

            Assert.IsTrue(s.IsLoaded);
            Assert.AreEqual("IN", s.GetCountry(IPAddress.Parse("103.0.5.9")));
            CollectionAssert.AreEqual(new[] { "APNIC" }, s.GetStatus().Registries.ToArray());
        }

        [TestMethod]
        public void UpdateWritesValidFilesAndReloads()
        {
            FakeDownloader d = AllRegistries();
            CountryDataService s = Service(d);

            s.UpdateAll();

            Assert.AreEqual(5, Directory.GetFiles(_folder, "delegated-*.txt").Length);
            Assert.AreEqual(0, Directory.GetFiles(_folder, "*.tmp").Length);
            Assert.AreEqual("BR", s.GetCountry(IPAddress.Parse("177.0.0.1")));
            CountryDataStatus status = s.GetStatus();
            Assert.IsTrue(status.Loaded);
            Assert.AreEqual(new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc), status.UpdatedUtc);
            Assert.IsNull(status.LastError);
            Assert.AreEqual(6000, status.RangeCount);
        }

        [TestMethod]
        public void FailingRegistryKeepsItsFileOthersUpdate()
        {
            WriteFile("lacnic", RegistryFile("lacnic", "AR", 177, 1100));
            FakeDownloader d = AllRegistries();
            d.Failing.Add("lacnic");
            CountryDataService s = Service(d);

            s.UpdateAll();

            Assert.AreEqual("AR", s.GetCountry(IPAddress.Parse("177.0.0.1")), "old LACNIC data kept");
            Assert.AreEqual("IN", s.GetCountry(IPAddress.Parse("103.0.0.1")), "others updated");
            StringAssert.Contains(s.GetStatus().LastError, "LACNIC");
        }

        [TestMethod]
        public void TooSmallDownloadIsRejected()
        {
            WriteFile("apnic", RegistryFile("apnic", "IN", 103, 1200));
            FakeDownloader d = AllRegistries();
            d.Files["apnic"] = RegistryFile("apnic", "CN", 103, 10);
            CountryDataService s = Service(d);

            s.UpdateAll();

            Assert.AreEqual("IN", s.GetCountry(IPAddress.Parse("103.0.0.1")));
            StringAssert.Contains(s.GetStatus().LastError, "APNIC");
        }

        [TestMethod]
        public void NeedsUpdateAfterSevenDays()
        {
            CountryDataService fresh = Service(new FakeDownloader());
            Assert.IsTrue(fresh.NeedsUpdate, "no files at all");

            WriteFile("apnic", RegistryFile("apnic", "IN", 103, 1200));
            string path = Path.Combine(_folder, "delegated-apnic.txt");
            DateTime now = new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc);

            File.SetLastWriteTimeUtc(path, now.AddDays(-2));
            Assert.IsFalse(Service(new FakeDownloader(), now).NeedsUpdate);

            File.SetLastWriteTimeUtc(path, now.AddDays(-8));
            Assert.IsTrue(Service(new FakeDownloader(), now).NeedsUpdate);
        }
    }
}
