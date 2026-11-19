using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.Rules
{
    /// <summary>
    /// Pure logic behind the "new rule" wizard: parse a pasted event, find IP candidates,
    /// generate a rule and self-test it the way the service would match it. No WPF/WCF dependencies.
    /// </summary>
    public static class RuleBuilder
    {
        public const string ParseErrorMessage = "That doesn't look like an event's XML. Make sure you copied it from the XML View.";

        public const string IncompleteEventMessage = "This event is missing its source, ID or log name, so EvlWatcher can't build a rule from it.";

        private const string ProviderPrefix = "Microsoft-Windows-";

        private static readonly Regex EventViewerCollapseMarker = new Regex(@"(?m)^([ \t]*)-[ \t]+(?=<)", RegexOptions.Compiled);

        public static bool TryParse(string text, out ParsedEvent ev, out string error)
        {
            ev = null;
            error = ParseErrorMessage;
            if (string.IsNullOrWhiteSpace(text))
                return false;

            // Event Viewer's XML View prefixes expandable elements with "- " when copied; only a "- " at the start of a line
            // that is directly followed by a tag is removed, so text inside values is never changed.
            text = EventViewerCollapseMarker.Replace(text, "$1");

            XDocument doc;
            try
            {
                doc = XDocument.Parse(text.Trim().TrimStart('﻿').Trim());
            }
            catch (XmlException)
            {
                return false;
            }

            XElement root = doc.Root;
            if (root == null || root.Name.LocalName != "Event")
                return false;

            XElement system = root.Elements().FirstOrDefault(e => e.Name.LocalName == "System");
            string provider = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "Provider")
                ?.Attributes().FirstOrDefault(a => a.Name.LocalName == "Name")?.Value ?? "";
            string eventId = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value.Trim() ?? "";
            string channel = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "Channel")?.Value.Trim() ?? "";

            if (provider.Length == 0 || eventId.Length == 0 || channel.Length == 0)
            {
                error = IncompleteEventMessage;
                return false;
            }

            ev = new ParsedEvent
            {
                Provider = provider,
                EventId = eventId,
                Channel = channel,
                Candidates = FindCandidates(root),
                PastedText = text,
                CompactXml = ToCompact(root)
            };
            error = null;
            return true;
        }

        private static List<IpCandidate> FindCandidates(XElement root)
        {
            var result = new List<IpCandidate>();
            foreach (XElement el in root.Descendants())
            {
                if (el.HasElements)
                    continue;
                if (!el.Ancestors().Any(a => a.Name.LocalName == "EventData" || a.Name.LocalName == "UserData"))
                    continue;

                string value = el.Value.Trim();
                if (!TryParseIp(value, out IPAddress ip))
                    continue;

                string dataName = el.Name.LocalName == "Data"
                    ? el.Attributes().FirstOrDefault(a => a.Name.LocalName == "Name")?.Value
                    : null;
                bool named = !string.IsNullOrEmpty(dataName);

                result.Add(new IpCandidate
                {
                    FieldLabel = named ? dataName : el.Name.LocalName,
                    ElementName = QualifiedName(el.Name, el),
                    IsNamedData = named,
                    Address = ip,
                    IsLocal = IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)
                });
            }
            return result;
        }

        // IPAddress.TryParse accepts "4625" (as 0.0.18.17) and the like; only accept real dotted quads and colon forms.
        private static bool TryParseIp(string value, out IPAddress ip)
        {
            ip = null;
            if (value.Length == 0 || value.Length > 45)
                return false;
            if (!IPAddress.TryParse(value, out IPAddress parsed))
                return false;
            if (parsed.AddressFamily == AddressFamily.InterNetwork && value.Count(c => c == '.') != 3)
                return false;
            if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && !value.Contains(':'))
                return false;
            ip = parsed;
            return true;
        }

        public static GenericIPBlockingTaskDTO BuildRule(ParsedEvent ev, IpCandidate chosen, ICollection<string> existingNames)
        {
            string baseName = $"{ShortProviderName(ev.Provider)} {ev.EventId}";
            string name = baseName;
            for (int i = 2; existingNames != null && existingNames.Contains(name); i++)
                name = $"{baseName} ({i})";

            string element = Regex.Escape(chosen.ElementName);
            string regex = chosen.IsNamedData
                ? $"<{element} Name=.{Regex.Escape(chosen.FieldLabel)}.>([0-9A-Fa-f:.]+)</{element}>"
                : $"<{element}(?:\\s[^>]*)?>([0-9A-Fa-f:.]+)</{element}>";

            return new GenericIPBlockingTaskDTO
            {
                TaskName = name,
                Description = $"Bans IPs found in {chosen.FieldLabel} of event {ev.EventId} from {ev.Provider}.",
                Active = true,
                OnlyNewEvents = false,
                TriggerCount = 5,
                EventAge = 120,
                LockTime = 3600,
                PermaBanCount = 3,
                EventPath = new List<string> { ev.Channel },
                RegexBoosters = new List<string> { ev.Provider, $">{ev.EventId}</EventID>" },
                Regex = regex
            };
        }

        /// <summary>Mirrors GenericIPBlockingTask: every booster contained (ordinal), then regex, one group that parses as an IP.</summary>
        public static IPAddress Match(GenericIPBlockingTaskDTO rule, string eventXml)
        {
            if (rule == null || eventXml == null || string.IsNullOrEmpty(rule.Regex))
                return null;

            if (rule.RegexBoosters != null)
            {
                foreach (string b in rule.RegexBoosters)
                {
                    if (eventXml.IndexOf(b, StringComparison.Ordinal) < 0)
                        return null;
                }
            }

            Match m;
            try
            {
                m = new Regex(rule.Regex).Match(eventXml);
            }
            catch (ArgumentException)
            {
                return null;
            }

            if (m.Success && m.Groups.Count == 2 && IPAddress.TryParse(m.Groups[1].Value, out IPAddress ip))
                return ip;
            return null;
        }

        public static bool SelfTest(GenericIPBlockingTaskDTO rule, ParsedEvent ev, IPAddress expected)
        {
            return expected != null
                && expected.Equals(Match(rule, ev.PastedText))
                && expected.Equals(Match(rule, ev.CompactXml));
        }

        public static string FindCoveringRule(IEnumerable<GenericIPBlockingTaskDTO> rules, ParsedEvent ev)
        {
            foreach (GenericIPBlockingTaskDTO rule in rules)
            {
                if (rule.Active && (Match(rule, ev.PastedText) != null || Match(rule, ev.CompactXml) != null))
                    return rule.TaskName;
            }
            return null;
        }

        public static string ShortProviderName(string provider)
        {
            if (provider != null && provider.StartsWith(ProviderPrefix, StringComparison.Ordinal))
                return provider.Substring(ProviderPrefix.Length);
            return provider;
        }

        #region compact form

        private static string ToCompact(XElement root)
        {
            var sb = new StringBuilder();
            WriteElement(sb, root);
            return sb.ToString();
        }

        private static void WriteElement(StringBuilder sb, XElement el)
        {
            string name = QualifiedName(el.Name, el);
            sb.Append('<').Append(name);
            foreach (XAttribute a in el.Attributes())
            {
                sb.Append(' ').Append(QualifiedName(a.Name, el)).Append("='")
                  .Append(Escape(a.Value, attribute: true)).Append('\'');
            }

            if (!el.Nodes().Any())
            {
                sb.Append("/>");
                return;
            }

            sb.Append('>');
            foreach (XNode node in el.Nodes())
            {
                if (node is XElement child)
                    WriteElement(sb, child);
                else if (node is XText t && (!el.HasElements || !string.IsNullOrWhiteSpace(t.Value)))
                    sb.Append(Escape(t.Value, attribute: false));
            }
            sb.Append("</").Append(name).Append('>');
        }

        private static string QualifiedName(XName name, XElement context)
        {
            if (name.Namespace == XNamespace.None)
                return name.LocalName;
            string prefix = context.GetPrefixOfNamespace(name.Namespace);
            return string.IsNullOrEmpty(prefix) ? name.LocalName : prefix + ":" + name.LocalName;
        }

        private static string Escape(string s, bool attribute)
        {
            s = s.Replace("&", "&amp;").Replace("<", "&lt;");
            return attribute
                ? s.Replace("'", "&apos;").Replace("\r", "&#xD;").Replace("\n", "&#xA;")
                : s.Replace(">", "&gt;");
        }

        #endregion
    }
}
