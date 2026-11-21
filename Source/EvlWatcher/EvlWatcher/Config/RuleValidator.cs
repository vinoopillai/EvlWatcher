using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using EvlWatcher.WCF.DTO;

namespace EvlWatcher.Config
{
    /// <summary>
    /// Validates a rule coming from the console. Returns human-readable messages; an empty list means valid.
    /// </summary>
    internal static class RuleValidator
    {
        internal const int MaxNameLength = 64;

        private static bool IsSavable(string s)
        {
            if (s == null) return true;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (char.IsHighSurrogate(c))
                {
                    if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { i++; continue; }
                    return false;
                }
                if (!XmlConvert.IsXmlChar(c)) return false; // also rejects lone low surrogates
            }
            return true;
        }

        private static string Unsavable(string field)
        {
            return field + " contains a character that can't be saved.";
        }

        internal static IList<string> Validate(GenericIPBlockingTaskDTO rule, bool isNew, ICollection<string> existingNames, Func<string, bool> eventLogExists)
        {
            var messages = new List<string>();

            #region name
            var name = (rule.TaskName ?? string.Empty).Trim();
            if (name.Length == 0)
            {
                messages.Add("Rule name must not be empty.");
            }
            else if (name.Length > MaxNameLength)
            {
                messages.Add("Rule name must be at most " + MaxNameLength + " characters.");
            }
            else
            {
                var exists = existingNames != null && existingNames.Any(n => string.Equals((n ?? string.Empty).Trim(), name, StringComparison.Ordinal));
                if (isNew && exists)
                    messages.Add("A rule named '" + name + "' already exists.");
                else if (!isNew && !exists)
                    messages.Add("The rule '" + name + "' does not exist.");
            }
            #endregion

            #region thresholds
            if (rule.TriggerCount < 1)
                messages.Add("Attempts must be at least 1.");
            if (rule.EventAge < 10)
                messages.Add("Time window must be at least 10 seconds.");
            if (rule.LockTime < 60)
                messages.Add("Ban length must be at least 1 minute.");
            if (rule.PermaBanCount == 0)
                messages.Add("Permanent ban after must be at least 1, or negative for never.");

            if (rule.AllowedCountries != null && rule.AllowedCountries.Any(c => !IsCountryCode((c ?? string.Empty).Trim().ToUpperInvariant())))
                messages.Add("Country codes must be two letters, e.g. IN.");
            #endregion

            #region regex
            if (string.IsNullOrWhiteSpace(rule.Regex))
            {
                messages.Add("Regex must not be empty.");
            }
            else
            {
                try
                {
                    var groups = new Regex(rule.Regex).GetGroupNumbers().Length - 1;
                    if (groups != 1)
                        messages.Add("Regex must have exactly one capture group (found " + groups + ").");
                }
                catch (ArgumentException e)
                {
                    messages.Add("Regex is not valid: " + e.Message);
                }
            }
            #endregion

            #region event logs
            var logs = (rule.EventPath ?? new List<string>())
                .Select(p => (p ?? string.Empty).Trim())
                .Where(p => p.Length > 0)
                .ToList();
            if (logs.Count == 0)
            {
                messages.Add("Event log: at least one is required.");
            }
            else if (isNew)
            {
                var missing = logs.Where(l => !eventLogExists(l)).ToList();
                if (missing.Count > 0)
                    messages.Add("Event log not found: " + string.Join(", ", missing) + ".");
            }
            #endregion

            #region boosters
            var boosters = rule.RegexBoosters ?? new List<string>();
            if (boosters.Count == 0)
                messages.Add("Booster words: at least one is required.");
            else if (boosters.Any(string.IsNullOrWhiteSpace))
                messages.Add("Booster words must not be empty.");
            #endregion

            #region unsavable characters
            if (!IsSavable(rule.TaskName)) messages.Add(Unsavable("Rule name"));
            if (!IsSavable(rule.Description)) messages.Add(Unsavable("Description"));
            if (!IsSavable(rule.Regex)) messages.Add(Unsavable("Regex"));
            if ((rule.EventPath ?? new List<string>()).Any(p => !IsSavable(p))) messages.Add(Unsavable("Event log"));
            if (boosters.Any(b => !IsSavable(b))) messages.Add(Unsavable("Booster words"));
            #endregion

            return messages;
        }

        /// <summary>Two letters A–Z (an ISO 3166 code as the registries use them).</summary>
        private static bool IsCountryCode(string code) =>
            code.Length == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z';
    }
}
