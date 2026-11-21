using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>Parsing and classifying the IP addresses found in events.</summary>
    public static class AddressClassifier
    {
        #region public operations

        /// <summary>Accepts a.b.c.d, IPv6, a.b.c.d:port and [v6]:port. Rejects "-", empty and bare numbers.</summary>
        public static bool TryParse(string value, out IPAddress ip)
        {
            ip = null;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            string s = value.Trim();
            if (s.StartsWith("[", StringComparison.Ordinal))
            {
                int close = s.IndexOf(']');
                if (close < 0)
                    return false;
                s = s.Substring(1, close - 1);
            }
            else if (s.Count(c => c == ':') == 1)
            {
                s = s.Substring(0, s.IndexOf(':'));
            }

            if (!IPAddress.TryParse(s, out IPAddress parsed))
                return false;
            if (parsed.AddressFamily == AddressFamily.InterNetwork && s.Count(c => c == '.') != 3)
                return false;
            if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && s.IndexOf(':') < 0)
                return false;

            ip = parsed;
            return true;
        }

        public static bool IsLocal(IPAddress ip, ISet<string> localAddresses)
        {
            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
                return true;
            return localAddresses != null && localAddresses.Contains(ip.ToString());
        }

        /// <summary>10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10.</summary>
        public static bool IsPrivate(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                return b[0] == 10
                    || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                    || (b[0] == 192 && b[1] == 168)
                    || (b[0] == 169 && b[1] == 254);
            }
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);
            return false;
        }

        /// <summary>Same semantics as the service: '*' and '?' wildcards, whole-string match.</summary>
        public static bool IsWhitelisted(string ip, IEnumerable<string> patterns)
        {
            if (ip == null || patterns == null)
                return false;
            foreach (string pattern in patterns)
            {
                if (string.IsNullOrWhiteSpace(pattern))
                    continue;
                string regex = "^" + Regex.Escape(pattern.Trim()).Replace("\\*", ".*").Replace("\\?", ".") + "$";
                if (Regex.IsMatch(ip, regex))
                    return true;
            }
            return false;
        }

        /// <summary>This machine's own addresses plus the loopbacks.</summary>
        public static ISet<string> GetLocalAddresses()
        {
            var result = new HashSet<string> { IPAddress.Loopback.ToString(), IPAddress.IPv6Loopback.ToString() };
            try
            {
                foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
                    result.Add(a.ToString());
            }
            catch (SocketException)
            {
            }
            catch (ArgumentException)
            {
            }
            return result;
        }

        #endregion
    }
}
