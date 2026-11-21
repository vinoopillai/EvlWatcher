using System;
using System.Collections.Generic;
using System.Threading;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>Where the analyzer gets its events from: the real event logs, or test data.</summary>
    public interface IEventSource
    {
        bool LogExists(string logName);

        /// <summary>
        /// Events of <paramref name="logName"/> created at or after <paramref name="fromUtc"/>, limited to
        /// <paramref name="eventIds"/> (null = all). Throws UnauthorizedAccessException when the log can't be read.
        /// </summary>
        IEnumerable<AnalyzedEvent> Read(string logName, IReadOnlyCollection<int> eventIds, DateTime fromUtc, CancellationToken ct);
    }
}
