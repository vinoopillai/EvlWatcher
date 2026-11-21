using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Xml.Linq;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>
    /// One event-log record as the analyzer sees it: the System fields plus the data fields, parsed from the
    /// record's XML (EventLogRecord.ToXml). Namespace-agnostic, so test samples and real records parse alike.
    /// </summary>
    public sealed class AnalyzedEvent
    {
        #region private members

        private static readonly IReadOnlyDictionary<string, string> NoData = new Dictionary<string, string>();

        #endregion

        #region public properties

        public string LogName { get; private set; }

        public string Provider { get; private set; }

        public int EventId { get; private set; }

        public long RecordId { get; private set; }

        /// <summary>0 LogAlways, 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose.</summary>
        public int Level { get; private set; }

        public DateTime TimeUtc { get; private set; }

        public string Xml { get; private set; }

        /// <summary>
        /// Leaf values under EventData (keyed by the Data element's Name, or #1, #2, … when unnamed) and under
        /// UserData (keyed by element name). Values are trimmed.
        /// </summary>
        public IReadOnlyDictionary<string, string> Data { get; private set; }

        #endregion

        #region public operations

        public string Get(string key)
        {
            return key != null && Data.TryGetValue(key, out string value) ? value : null;
        }

        public static AnalyzedEvent FromXml(string logName, string xml)
        {
            XElement root = XDocument.Parse(xml).Root;
            XElement system = Child(root, "System");

            XElement provider = Child(system, "Provider");
            string providerName = Attr(provider, "Name");
            if (string.IsNullOrEmpty(providerName))
                providerName = Attr(provider, "EventSourceName") ?? "";

            int.TryParse(Child(system, "EventID")?.Value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int id);
            long.TryParse(Child(system, "EventRecordID")?.Value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long record);
            int.TryParse(Child(system, "Level")?.Value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int level);

            DateTime time = DateTime.MinValue;
            string systemTime = Attr(Child(system, "TimeCreated"), "SystemTime");
            if (systemTime != null)
            {
                DateTime.TryParse(systemTime, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out time);
                time = DateTime.SpecifyKind(time, DateTimeKind.Utc);
            }

            return new AnalyzedEvent
            {
                LogName = logName,
                Provider = providerName,
                EventId = id,
                RecordId = record,
                Level = level,
                TimeUtc = time,
                Xml = xml,
                Data = ReadData(root)
            };
        }

        #endregion

        #region private operations

        private static IReadOnlyDictionary<string, string> ReadData(XElement root)
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            XElement eventData = Child(root, "EventData");
            if (eventData != null)
            {
                int unnamed = 0;
                foreach (XElement d in eventData.Elements().Where(e => e.Name.LocalName == "Data"))
                {
                    string name = Attr(d, "Name");
                    if (string.IsNullOrEmpty(name))
                        name = "#" + (++unnamed).ToString(CultureInfo.InvariantCulture);
                    data[name] = d.Value.Trim();
                }
            }

            XElement userData = Child(root, "UserData");
            if (userData != null)
            {
                foreach (XElement leaf in userData.Descendants().Where(e => !e.HasElements))
                    data[leaf.Name.LocalName] = leaf.Value.Trim();
            }

            return data.Count == 0 ? NoData : data;
        }

        private static XElement Child(XElement parent, string localName) =>
            parent?.Elements().FirstOrDefault(e => e.Name.LocalName == localName);

        private static string Attr(XElement element, string localName) =>
            element?.Attributes().FirstOrDefault(a => a.Name.LocalName == localName)?.Value;

        #endregion
    }
}
