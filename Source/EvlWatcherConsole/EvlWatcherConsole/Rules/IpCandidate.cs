using System.Net;

namespace EvlWatcherConsole.Rules
{
    /// <summary>
    /// A leaf element of a pasted event whose whole value is an IP address.
    /// </summary>
    public class IpCandidate
    {
        /// <summary>The Name attribute for &lt;Data Name="..."&gt;, otherwise the element name.</summary>
        public string FieldLabel { get; set; }

        /// <summary>The element name as written in the paste (including a namespace prefix, if any).</summary>
        public string ElementName { get; set; }

        /// <summary>True for &lt;Data Name="..."&gt; elements.</summary>
        public bool IsNamedData { get; set; }

        public IPAddress Address { get; set; }

        /// <summary>Loopback, 0.0.0.0 or :: - the machine itself, not an attacker.</summary>
        public bool IsLocal { get; set; }
    }
}
