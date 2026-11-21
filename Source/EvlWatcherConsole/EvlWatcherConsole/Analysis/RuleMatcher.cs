using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>
    /// RuleBuilder.Match with the regex compiled once per rule, for matching whole logs: every booster contained
    /// (ordinal), then the regex, exactly one group that parses as an IP.
    /// </summary>
    public sealed class RuleMatcher
    {
        #region private members

        private readonly string[] _boosters;
        private readonly Regex _regex;

        #endregion

        #region constructor

        public RuleMatcher(GenericIPBlockingTaskDTO rule)
        {
            Rule = rule;
            _boosters = (rule.RegexBoosters ?? new List<string>()).ToArray();
            try
            {
                _regex = string.IsNullOrEmpty(rule.Regex) ? null : new Regex(rule.Regex);
            }
            catch (ArgumentException)
            {
                _regex = null;
            }
        }

        #endregion

        #region public properties

        public GenericIPBlockingTaskDTO Rule { get; }

        #endregion

        #region public operations

        public IPAddress Match(string xml)
        {
            if (_regex == null || xml == null)
                return null;
            foreach (string b in _boosters)
            {
                if (xml.IndexOf(b, StringComparison.Ordinal) < 0)
                    return null;
            }
            System.Text.RegularExpressions.Match m = _regex.Match(xml);
            return m.Success && m.Groups.Count == 2 && IPAddress.TryParse(m.Groups[1].Value, out IPAddress ip) ? ip : null;
        }

        #endregion
    }

    /// <summary>One attempt a rule counted: what the attack checks need from a rule's log.</summary>
    public struct RuleHit
    {
        public RuleHit(string ruleName, IPAddress ip, DateTime timeUtc)
        {
            RuleName = ruleName;
            Ip = ip;
            TimeUtc = timeUtc;
        }

        public string RuleName { get; }

        public IPAddress Ip { get; }

        public DateTime TimeUtc { get; }
    }
}
