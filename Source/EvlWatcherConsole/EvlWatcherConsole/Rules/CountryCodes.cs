using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace EvlWatcherConsole.Rules
{
    /// <summary>Two-letter country codes (as the internet registries use them) and their English names.</summary>
    public static class CountryCodes
    {
        /// <summary>True for a two-letter code Windows knows, with its English name ("IN" → "India").</summary>
        public static bool TryGetName(string code, out string englishName)
        {
            englishName = null;
            code = (code ?? "").Trim().ToUpperInvariant();
            if (code.Length != 2 || !code.All(c => c >= 'A' && c <= 'Z'))
                return false;
            try
            {
                englishName = new RegionInfo(code).EnglishName;
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        /// <summary>Splits "in, ae" into upper-case codes, without empties or duplicates.</summary>
        public static List<string> Parse(string text) =>
            (text ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(c => c.Trim().ToUpperInvariant()).Where(c => c.Length > 0).Distinct().ToList();
    }
}
