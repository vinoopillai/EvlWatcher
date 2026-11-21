using EvlWatcher.Config;
using EvlWatcher.DTOs;
using EvlWatcher.Geo;
using EvlWatcher.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace EvlWatcher.Tasks
{
    internal class GenericIPBlockingTask : IPBlockingLogTask
    {
        #region static

        internal static GenericIPBlockingTask FromConfiguration(IPersistentTaskConfiguration configuration, ILogger logger)
        {
            return FromConfiguration(configuration, logger, CountryDatabase.Empty);
        }

        internal static GenericIPBlockingTask FromConfiguration(IPersistentTaskConfiguration configuration, ILogger logger, ICountryLookup countries)
        {
            GenericIPBlockingTask t = new GenericIPBlockingTask(logger)
            {
                Countries = countries ?? CountryDatabase.Empty,
                AllowedCountries = new HashSet<string>((configuration.AllowedCountries ?? new List<string>()).Select(c => c.Trim().ToUpperInvariant()).Where(c => c.Length > 0)),
                Name = configuration.TaskName,
                Description = configuration.Description,
                LockTime = configuration.LockTime,
                OnlyNew = configuration.OnlyNewEvents,
                EventAge = configuration.EventAge,
                TriggerCount = configuration.TriggerCount,
                PermaBanCount = configuration.PermaBanCount,
                EventPath = configuration.EventPath.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries),
                Boosters = configuration.RegexBoosters.ToList(),
                Regex = new Regex(configuration.Regex, RegexOptions.Compiled),
                Active = configuration.Active
            };

            return t;
        }

        #endregion

        #region private members

        private readonly object _syncObject = new object();
        private readonly Dictionary<IPAddress, DateTime> _blockedIPsToDate = new Dictionary<IPAddress, DateTime>();
        private readonly Dictionary<IPAddress, DateTime> _forgetIPsToDate = new Dictionary<IPAddress, DateTime>();
        private readonly Dictionary<IPAddress, int> _bannedCount = new Dictionary<IPAddress, int>();
        private readonly ILogger _logger;

        #endregion

        #region internal .ctor

        internal GenericIPBlockingTask(ILogger logger)
        {
            _logger = logger;
        }

        #endregion

        #region public properties

        public int LockTime { get; set; } = 3600;
        public List<string> Boosters { get; set; } = new List<string>();
        public int PermaBanCount { get; set; } = 3;
        public int TriggerCount { get; set; } = 5;
        public Regex Regex { get; set; } = null;

        /// <summary>Countries with the normal trigger count; other known countries are banned on their first attempt. Empty = off.</summary>
        public ISet<string> AllowedCountries { get; set; } = new HashSet<string>();

        internal ICountryLookup Countries { get; set; } = CountryDatabase.Empty;

        #endregion

        #region internal operations

        /// <summary>
        /// Copies temporary bans, strike counts and "forgotten" IPs from a previous instance of the same rule,
        /// so a rule reload does not lose in-memory state (and re-ban IPs an admin un-banned).
        /// </summary>
        internal void CarryOverStateFrom(GenericIPBlockingTask previous)
        {
            if (previous == null)
                throw new ArgumentNullException(nameof(previous));
            if (ReferenceEquals(previous, this))
                return;

            lock (previous._syncObject)
            {
                lock (_syncObject)
                {
                    Copy(previous._blockedIPsToDate, _blockedIPsToDate);
                    Copy(previous._bannedCount, _bannedCount);
                    Copy(previous._forgetIPsToDate, _forgetIPsToDate);
                }
            }
        }

        private static void Copy<TValue>(Dictionary<IPAddress, TValue> source, Dictionary<IPAddress, TValue> target)
        {
            target.Clear();
            foreach (KeyValuePair<IPAddress, TValue> kvp in source)
                target[kvp.Key] = kvp.Value;
        }

        #endregion

        #region public operations
        public override List<IPAddress> GetTempBanVictims()
        {
            lock (_syncObject)
            {
                List<IPAddress> ipsToRemove = new List<IPAddress>();
                List<IPAddress> ipsToBlock = new List<IPAddress>();

                //also remove IPS from ban list when they have been blocked "long enough"
                foreach (KeyValuePair<IPAddress, DateTime> kvp in _blockedIPsToDate)
                {
                    if (kvp.Value.Add(new TimeSpan(0, 0, LockTime)) < DateTime.Now)
                    {
                        ipsToRemove.Add(kvp.Key);
                    }
                    else
                    {
                        ipsToBlock.Add(kvp.Key);
                    }
                }

                //also remove forgotten IPs when its been a while
                List<IPAddress> removeFromForgottenList = _forgetIPsToDate.Where(p => DateTime.Now.AddHours(-1) > p.Value).Select(p => p.Key).ToList();
                foreach (var ip in removeFromForgottenList)
                    _forgetIPsToDate.Remove(ip);

                foreach (IPAddress ipToRemove in ipsToRemove)
                    _blockedIPsToDate.Remove(ipToRemove);

                return ipsToBlock;
            }
        }

        public override List<IPAddress> GetPermaBanVictims()
        {
            lock (_syncObject)
            {
                List<IPAddress> permaList = new List<IPAddress>();
                if (PermaBanCount >= 0)
                {
                    foreach (KeyValuePair<IPAddress, int> kvp in _bannedCount.Where(p => p.Value >= PermaBanCount))
                    {
                        permaList.Add(kvp.Key);
                        _logger.Dump($"Permanently banned {kvp.Value} (strike count was over {PermaBanCount}) ", SeverityLevel.Info);
                    }
                    foreach (IPAddress ip in permaList)
                        _bannedCount.Remove(ip);
                }

                return permaList;
            }
        }

        protected override void OnComputeEvents(List<ExtractedEventRecord> events)
        {
            lock (_syncObject)
            {

                Dictionary<IPAddress, int> sourceToCount = new Dictionary<IPAddress, int>();
                foreach (ExtractedEventRecord e in events)
                {
                    _logger.Dump($"{Name}: Processing Event with timestamp {e.TimeCreated}", SeverityLevel.Debug);

                    string xml = e.Xml;

                    _logger.Dump($"Checking XML {xml} against boosters..", SeverityLevel.Debug);

                    bool abort = false;
                    foreach (string b in Boosters)
                    {
                        _logger.Dump($"Booster: {b}", SeverityLevel.Debug);
                        if (!xml.Contains(b))
                        {
                            _logger.Dump($"Booster not in XML, aborting.", SeverityLevel.Debug);
                            abort = true;
                            break;
                        }
                    }
                    if (abort)
                        continue;


                    _logger.Dump($"Checking XML against Regex {Regex} now..", SeverityLevel.Debug);
                    Match m = Regex.Match(xml);

                    if (m.Success)
                    {
                        if (m.Groups.Count == 2 && IPAddress.TryParse(m.Groups[1].Value, out IPAddress ipAddress))
                        {
                            if (_forgetIPsToDate.ContainsKey(ipAddress) && _forgetIPsToDate[ipAddress] > e.TimeCreated)
                            {
                                _logger.Dump($"{Name}: found {ipAddress} but ignored it (was recently removed from autoban list)", SeverityLevel.Info);
                                continue;
                            }

                            if (!sourceToCount.ContainsKey(ipAddress))
                                sourceToCount.Add(ipAddress, 1);
                            else
                                sourceToCount[ipAddress]++;

                            _logger.Dump($"{Name}: found {ipAddress}, trigger count is {sourceToCount[ipAddress]}", SeverityLevel.Verbose);
                        }
                    }
                }

                foreach (KeyValuePair<IPAddress, int> kvp in sourceToCount)
                {
                    if (_blockedIPsToDate.ContainsKey(kvp.Key))
                        continue;

                    if (kvp.Value >= TriggerCount)
                    {
                        _blockedIPsToDate.Add(kvp.Key, DateTime.Now);
                        if (!_bannedCount.ContainsKey(kvp.Key))
                            _bannedCount[kvp.Key] = 1;
                        else
                            _bannedCount[kvp.Key] += 1;

                        _logger.Dump($"Temporarily banning {kvp.Key}, this is strike {_bannedCount[kvp.Key]}", SeverityLevel.Info);
                    }
                    else if (IsCountryBlocked(kvp.Key, out string country))
                    {
                        // first-attempt country ban: temporary only, never a strike towards a permanent ban
                        _blockedIPsToDate.Add(kvp.Key, DateTime.Now);
                        _logger.Dump($"{Name}: banning {kvp.Key} on first attempt (country {country}, rule allows only {string.Join(", ", AllowedCountries)})", SeverityLevel.Info);
                    }
                }
            }
        }

        /// <summary>
        /// True when the rule allows only some countries, the country data is loaded, the address is public and not this
        /// machine's, and its registered country is known and not allowed.
        /// </summary>
        private bool IsCountryBlocked(IPAddress ip, out string country)
        {
            country = null;
            if (AllowedCountries.Count == 0 || !Countries.IsLoaded)
                return false;
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();
            if (IsPrivateOrLocal(ip))
                return false;
            country = Countries.GetCountry(ip);
            return country != null && !AllowedCountries.Contains(country);
        }

        private static readonly Lazy<HashSet<IPAddress>> OwnAddresses = new Lazy<HashSet<IPAddress>>(() =>
        {
            try
            {
                return new HashSet<IPAddress>(Dns.GetHostAddresses(Dns.GetHostName()));
            }
            catch (System.Net.Sockets.SocketException)
            {
                return new HashSet<IPAddress>();
            }
        });

        /// <summary>Loopback, unspecified, private (10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10) or this machine.</summary>
        internal static bool IsPrivateOrLocal(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || OwnAddresses.Value.Contains(ip))
                return true;
            byte[] b = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
            return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);
        }

        public override void Forget(IPAddress address)
        {
            lock (_syncObject)
            {
                _blockedIPsToDate.Remove(address);

                if (!_forgetIPsToDate.ContainsKey(address))
                    _forgetIPsToDate.Add(address, DateTime.Now);
                else
                    _forgetIPsToDate[address] = DateTime.Now;

                _bannedCount.Remove(address);
            }
        }

        #endregion
    }
}
