using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace EvlWatcher.Geo
{
    /// <summary>Sorted country ranges with binary-search lookup. Immutable once built, so it can be swapped atomically.</summary>
    public sealed class CountryDatabase : ICountryLookup
    {
        #region private members

        private readonly CountryRange[] _v4;
        private readonly CountryRange[] _v6;

        #endregion

        #region constructor

        public static readonly CountryDatabase Empty = new CountryDatabase(new IList<CountryRange>[0]);

        public CountryDatabase(IEnumerable<IList<CountryRange>> registries)
        {
            List<CountryRange> all = registries.SelectMany(r => r).ToList();
            _v4 = all.Where(r => !r.IsV6).OrderBy(r => r.StartLo).ToArray();
            _v6 = all.Where(r => r.IsV6).OrderBy(r => r.StartHi).ThenBy(r => r.StartLo).ToArray();
            RangeCount = _v4.Length + _v6.Length;
        }

        #endregion

        #region public properties

        public bool IsLoaded => RangeCount > 0;

        public int RangeCount { get; }

        #endregion

        #region public operations

        public string GetCountry(IPAddress ip)
        {
            if (ip == null || !IsLoaded)
                return null;
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();

            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return Find(_v4, 0, DelegatedFileParser.ToV4(ip));

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                DelegatedFileParser.ToV6(ip, out ulong hi, out ulong lo);
                return Find(_v6, hi, lo);
            }
            return null;
        }

        #endregion

        #region private operations

        /// <summary>The last range starting at or before the address, if it also ends at or after it.</summary>
        private static string Find(CountryRange[] ranges, ulong hi, ulong lo)
        {
            int left = 0, right = ranges.Length - 1, found = -1;
            while (left <= right)
            {
                int mid = left + (right - left) / 2;
                if (Compare(ranges[mid].StartHi, ranges[mid].StartLo, hi, lo) <= 0)
                {
                    found = mid;
                    left = mid + 1;
                }
                else
                {
                    right = mid - 1;
                }
            }
            if (found < 0)
                return null;
            CountryRange r = ranges[found];
            return Compare(r.EndHi, r.EndLo, hi, lo) >= 0 ? r.Country : null;
        }

        private static int Compare(ulong aHi, ulong aLo, ulong bHi, ulong bLo)
        {
            if (aHi != bHi)
                return aHi < bHi ? -1 : 1;
            if (aLo != bLo)
                return aLo < bLo ? -1 : 1;
            return 0;
        }

        #endregion
    }
}
