using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace EvlWatcher.Geo
{
    /// <summary>One block of addresses registered to a country. IPv4 uses only the low halves.</summary>
    public struct CountryRange
    {
        public string Country;
        public bool IsV6;
        public ulong StartHi, StartLo, EndHi, EndLo;
    }

    /// <summary>
    /// Reads the registries' "delegated" statistics files:
    /// registry|cc|type|start|value|date|status, where value is the address count (ipv4) or the prefix length (ipv6).
    /// Only allocated/assigned ipv4/ipv6 lines with a country are used; everything else is skipped.
    /// </summary>
    public static class DelegatedFileParser
    {
        #region public operations

        public static IList<CountryRange> Parse(TextReader reader, out string registry)
        {
            registry = null;
            var ranges = new List<CountryRange>();
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.Length == 0 || line[0] == '#')
                    continue;

                string[] f = line.Split('|');
                if (f.Length < 7)
                    continue;
                if (char.IsDigit(f[0], 0) && f.Length >= 2 && registry == null)
                {
                    registry = f[1]; // version header: 2|apnic|...
                    continue;
                }
                if (f[1] == "*")
                    continue;

                string status = f[6].Trim();
                if (status != "allocated" && status != "assigned")
                    continue;
                string cc = f[1].Trim().ToUpperInvariant();
                if (cc.Length != 2)
                    continue;

                if (registry == null)
                    registry = f[0];

                if (TryParseRange(f[2], f[3], f[4], cc, out CountryRange range))
                    ranges.Add(range);
            }
            return ranges;
        }

        #endregion

        #region private operations

        private static bool TryParseRange(string type, string start, string value, string cc, out CountryRange range)
        {
            range = default(CountryRange);
            if (!IPAddress.TryParse(start, out IPAddress ip))
                return false;

            if (type == "ipv4" && ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong count) || count == 0)
                    return false;
                ulong first = ToV4(ip);
                range = new CountryRange { Country = cc, StartLo = first, EndLo = Math.Min(first + count - 1, uint.MaxValue) };
                return true;
            }

            if (type == "ipv6" && ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) || prefix < 0 || prefix > 128)
                    return false;
                ToV6(ip, out ulong hi, out ulong lo);
                Mask(prefix, out ulong maskHi, out ulong maskLo);
                range = new CountryRange
                {
                    Country = cc,
                    IsV6 = true,
                    StartHi = hi & maskHi,
                    StartLo = lo & maskLo,
                    EndHi = (hi & maskHi) | ~maskHi,
                    EndLo = (lo & maskLo) | ~maskLo
                };
                return true;
            }
            return false;
        }

        internal static ulong ToV4(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return ((ulong)b[0] << 24) | ((ulong)b[1] << 16) | ((ulong)b[2] << 8) | b[3];
        }

        internal static void ToV6(IPAddress ip, out ulong hi, out ulong lo)
        {
            byte[] b = ip.GetAddressBytes();
            hi = 0;
            lo = 0;
            for (int i = 0; i < 8; i++)
                hi = (hi << 8) | b[i];
            for (int i = 8; i < 16; i++)
                lo = (lo << 8) | b[i];
        }

        private static void Mask(int prefix, out ulong hi, out ulong lo)
        {
            hi = prefix >= 64 ? ulong.MaxValue : (prefix == 0 ? 0UL : ulong.MaxValue << (64 - prefix));
            int rest = prefix - 64;
            lo = rest <= 0 ? 0UL : (rest >= 64 ? ulong.MaxValue : ulong.MaxValue << (64 - rest));
        }

        #endregion
    }
}
