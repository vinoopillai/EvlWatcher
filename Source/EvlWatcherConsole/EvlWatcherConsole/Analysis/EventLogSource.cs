using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Threading;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>
    /// Reads this machine's event logs. The XPath filter limits the read to the time range and event IDs, so Windows
    /// only hands over the events the checks need.
    /// </summary>
    public sealed class EventLogSource : IEventSource
    {
        #region public operations

        public bool LogExists(string logName)
        {
            try
            {
                return EventLogSession.GlobalSession.GetLogNames().Any(n => string.Equals(n, logName, StringComparison.OrdinalIgnoreCase));
            }
            catch (EventLogException)
            {
                return false;
            }
        }

        public IEnumerable<AnalyzedEvent> Read(string logName, IReadOnlyCollection<int> eventIds, DateTime fromUtc, CancellationToken ct)
        {
            var query = new EventLogQuery(logName, PathType.LogName, BuildXPath(eventIds, fromUtc));
            EventLogReader reader;
            try
            {
                reader = new EventLogReader(query);
            }
            catch (EventLogNotFoundException)
            {
                return Enumerable.Empty<AnalyzedEvent>();
            }
            return ReadAll(reader, logName, ct);
        }

        #endregion

        #region private operations

        internal static string BuildXPath(IReadOnlyCollection<int> eventIds, DateTime fromUtc)
        {
            long ms = Math.Max(0, (long)(DateTime.UtcNow - fromUtc).TotalMilliseconds);
            string time = "TimeCreated[timediff(@SystemTime) <= " + ms.ToString(CultureInfo.InvariantCulture) + "]";
            if (eventIds == null || eventIds.Count == 0)
                return "*[System[" + time + "]]";
            string ids = string.Join(" or ", eventIds.Distinct().Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture)));
            return "*[System[(" + ids + ") and " + time + "]]";
        }

        private static IEnumerable<AnalyzedEvent> ReadAll(EventLogReader reader, string logName, CancellationToken ct)
        {
            using (reader)
            using (ct.Register(reader.CancelReading)) // ReadEvent can block while the filter scans a large log
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    EventRecord record;
                    try
                    {
                        record = reader.ReadEvent();
                    }
                    catch (EventLogNotFoundException)
                    {
                        yield break;
                    }
                    catch (OperationCanceledException)
                    {
                        ct.ThrowIfCancellationRequested();
                        throw;
                    }
                    if (record == null)
                    {
                        ct.ThrowIfCancellationRequested(); // CancelReading ends the read like the end of the log
                        yield break;
                    }

                    AnalyzedEvent ev;
                    bool parsed;
                    using (record)
                    {
                        parsed = AnalyzedEvent.TryFromXml(logName, record.ToXml(), out ev);
                    }
                    if (parsed) // a single malformed record must not fail the whole scan
                        yield return ev;
                }
            }
        }

        #endregion
    }
}
