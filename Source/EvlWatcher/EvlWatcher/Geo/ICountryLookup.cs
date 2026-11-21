using System.Net;

namespace EvlWatcher.Geo
{
    /// <summary>The country an IP address is registered in, according to the internet registries.</summary>
    public interface ICountryLookup
    {
        /// <summary>False when no country data could be loaded; country filters are then inactive.</summary>
        bool IsLoaded { get; }

        /// <summary>Upper-case ISO 3166 code (e.g. "IN"), or null when the address isn't in any registry file.</summary>
        string GetCountry(IPAddress ip);
    }
}
