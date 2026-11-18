using System.Collections.Generic;

namespace EvlWatcherConsole.Rules
{
    /// <summary>
    /// The facts the rule wizard needs from a pasted Event Viewer XML.
    /// </summary>
    public class ParsedEvent
    {
        public string Provider { get; set; }
        public string EventId { get; set; }
        public string Channel { get; set; }
        public IReadOnlyList<IpCandidate> Candidates { get; set; }

        /// <summary>The text exactly as the user pasted it (untrimmed).</summary>
        public string PastedText { get; set; }

        /// <summary>One line, single-quoted attributes: mimics EventRecord.ToXml(), which is what the service matches.</summary>
        public string CompactXml { get; set; }
    }
}
