using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using EvlWatcher.Logging;

namespace EvlWatcher.Geo
{
    /// <summary>What the console shows about the country data.</summary>
    public sealed class CountryDataStatus
    {
        public bool Loaded { get; set; }
        public DateTime? UpdatedUtc { get; set; }
        public int RangeCount { get; set; }
        public string LastError { get; set; }
        public IList<string> Registries { get; set; } = new List<string>();
    }

    /// <summary>
    /// Keeps the registries' country data in <c>geo\delegated-&lt;registry&gt;.txt</c>: loads it, refreshes each registry
    /// on its own (a failing registry keeps its previous file) and swaps the lookup atomically. Never runs on the scan
    /// thread. When nothing could be loaded, <see cref="IsLoaded"/> is false and country filters stay inactive.
    /// </summary>
    public sealed class CountryDataService : ICountryLookup, IDisposable
    {
        #region public properties

        public static readonly IReadOnlyDictionary<string, string> Sources = new Dictionary<string, string>
        {
            { "apnic", "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest" },
            { "ripencc", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest" },
            { "arin", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest" },
            { "lacnic", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest" },
            { "afrinic", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest" }
        };

        public const int MinimumRanges = 1000;

        public static readonly TimeSpan RefreshAge = TimeSpan.FromDays(7);

        #endregion

        #region private members

        private static readonly TimeSpan CheckEvery = TimeSpan.FromHours(6);

        /// <summary>A registry file older than this is called out in the status.</summary>
        private const int StaleDays = 14;

        private readonly object _syncObject = new object();
        private readonly string _folder;
        private readonly IRegistryDownloader _downloader;
        private readonly ILogger _logger;
        private readonly Func<DateTime> _utcNow;

        private volatile CountryDatabase _database = CountryDatabase.Empty;
        private List<string> _loadedRegistries = new List<string>();
        private DateTime? _updatedUtc;
        private string _lastError;
        private int _updating;
        private Timer _timer;

        #endregion

        #region constructor

        public CountryDataService(string geoFolder, IRegistryDownloader downloader, ILogger logger, Func<DateTime> utcNow)
        {
            _folder = geoFolder;
            _downloader = downloader;
            _logger = logger;
            _utcNow = utcNow;
        }

        #endregion

        #region ICountryLookup

        public bool IsLoaded => _database.IsLoaded;

        public string GetCountry(IPAddress ip) => _database.GetCountry(ip);

        #endregion

        #region public operations

        /// <summary>True when any registry's file is missing or older than <see cref="RefreshAge"/>.</summary>
        public bool NeedsUpdate => DueRegistries().Count > 0;

        /// <summary>Registries whose own file is missing or older than <see cref="RefreshAge"/>; a failing one is retried every check.</summary>
        internal IList<string> DueRegistries()
        {
            DateTime now = _utcNow();
            return Sources.Keys.Where(name =>
            {
                string path = FilePath(name);
                return !File.Exists(path) || now - File.GetLastWriteTimeUtc(path) > RefreshAge;
            }).ToList();
        }

        public void Load()
        {
            var registries = new List<IList<CountryRange>>();
            var names = new List<string>();

            if (Directory.Exists(_folder))
            {
                foreach (string name in Sources.Keys)
                {
                    string path = FilePath(name);
                    if (!File.Exists(path))
                        continue;
                    try
                    {
                        IList<CountryRange> ranges;
                        using (var reader = new StreamReader(path))
                            ranges = DelegatedFileParser.Parse(reader, out _);
                        if (ranges.Count < MinimumRanges)
                        {
                            _logger.Dump($"Country data: {path} has only {ranges.Count} ranges and was skipped.", SeverityLevel.Warning);
                            continue;
                        }
                        registries.Add(ranges);
                        names.Add(name.ToUpperInvariant());
                    }
                    catch (Exception e)
                    {
                        // any broken file is skipped: the others still load, and nothing here may stop the service
                        _logger.Dump($"Country data: couldn't read {path}: {e.Message}", SeverityLevel.Warning);
                    }
                }
            }

            var database = new CountryDatabase(registries);
            lock (_syncObject)
            {
                _database = database;
                _loadedRegistries = names;
            }
            _logger.Dump(database.IsLoaded
                ? $"Country data loaded: {database.RangeCount} ranges from {string.Join(", ", names)}."
                : "Country data isn't available; rules with allowed countries use their normal limits.",
                database.IsLoaded ? SeverityLevel.Verbose : SeverityLevel.Warning);
        }

        /// <summary>Downloads every registry; each valid file replaces only its own registry's file.</summary>
        public void UpdateAll()
        {
            Update(Sources.Keys.ToList());
        }

        /// <summary>Downloads the given registries; each valid file replaces only its own registry's file.</summary>
        internal void Update(IList<string> registries)
        {
            var errors = new List<string>();
            int succeeded = 0;

            foreach (KeyValuePair<string, string> source in Sources.Where(s => registries.Contains(s.Key)))
            {
                string label = source.Key.ToUpperInvariant();
                try
                {
                    Directory.CreateDirectory(_folder);
                    string text = _downloader.Download(source.Value);
                    IList<CountryRange> ranges;
                    using (var reader = new StringReader(text ?? ""))
                        ranges = DelegatedFileParser.Parse(reader, out _);
                    if (ranges.Count < MinimumRanges)
                        throw new InvalidDataException($"only {ranges.Count} ranges");

                    string final = FilePath(source.Key), tmp = final + ".tmp";
                    File.WriteAllText(tmp, text);
                    File.Copy(tmp, final, true);
                    File.Delete(tmp);
                    succeeded++;
                }
                catch (Exception e)
                {
                    // whatever goes wrong stays with this registry: the others still update, and the status names it
                    errors.Add($"{label}: {e.Message}");
                    _logger.Dump($"Country data: {label} update failed, keeping the previous file: {e.Message}", SeverityLevel.Warning);
                }
            }

            Load();
            lock (_syncObject)
            {
                if (succeeded > 0)
                    _updatedUtc = _utcNow();
                _lastError = errors.Count == 0 ? null : string.Join("; ", errors);
            }
        }

        /// <summary>Loads the data and, when <paramref name="autoUpdate"/>, checks every few hours whether a weekly refresh is due.</summary>
        public void Start(bool autoUpdate)
        {
            Load();
            SetAutoUpdate(autoUpdate);
        }

        public void SetAutoUpdate(bool enabled)
        {
            lock (_syncObject)
            {
                _timer?.Dispose();
                _timer = enabled ? new Timer(_ => Tick(), null, TimeSpan.FromSeconds(30), CheckEvery) : null;
            }
        }

        /// <summary>Starts an update in the background; ignored while one is running.</summary>
        public void UpdateNowAsync()
        {
            ThreadPool.QueueUserWorkItem(_ => RunUpdate());
        }

        public CountryDataStatus GetStatus()
        {
            lock (_syncObject)
            {
                // stale files are reported even after a restart (when the last error is gone)
                DateTime now = _utcNow();
                List<string> problems = new List<string>();
                if (!string.IsNullOrEmpty(_lastError))
                    problems.Add(_lastError);
                foreach (string name in Sources.Keys)
                {
                    string path = FilePath(name);
                    if (!File.Exists(path))
                        continue;
                    int days = (int)(now - File.GetLastWriteTimeUtc(path)).TotalDays;
                    if (days > StaleDays)
                        problems.Add($"{name.ToUpperInvariant()} data is {days} days old");
                }

                return new CountryDataStatus
                {
                    Loaded = _database.IsLoaded,
                    RangeCount = _database.RangeCount,
                    UpdatedUtc = _updatedUtc ?? NewestFileUtc(),
                    LastError = problems.Count == 0 ? null : string.Join("; ", problems),
                    Registries = _loadedRegistries.ToList()
                };
            }
        }

        public void Dispose()
        {
            lock (_syncObject)
            {
                _timer?.Dispose();
                _timer = null;
            }
        }

        #endregion

        #region private operations

        /// <summary>The timer's check (also callable from tests).</summary>
        internal void Tick()
        {
            try
            {
                IList<string> due = DueRegistries();
                if (due.Count > 0)
                    RunUpdate(due);
            }
            catch (Exception e)
            {
                // an exception on a timer thread would end the whole service process
                _logger.Dump(e, SeverityLevel.Warning);
            }
        }

        private void RunUpdate(IList<string> registries = null)
        {
            if (Interlocked.Exchange(ref _updating, 1) == 1)
                return;
            try
            {
                Update(registries ?? Sources.Keys.ToList());
            }
            catch (Exception e)
            {
                _logger.Dump(e, SeverityLevel.Warning);
            }
            finally
            {
                Interlocked.Exchange(ref _updating, 0);
            }
        }

        private string FilePath(string registry) => Path.Combine(_folder, "delegated-" + registry + ".txt");

        private DateTime? NewestFileUtc()
        {
            if (!Directory.Exists(_folder))
                return null;
            DateTime[] times = Sources.Keys.Select(FilePath).Where(File.Exists).Select(File.GetLastWriteTimeUtc).ToArray();
            return times.Length == 0 ? (DateTime?)null : times.Max();
        }

        #endregion
    }
}
