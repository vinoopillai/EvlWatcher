using System;

namespace EvlWatcher.WCF.DTO
{
    /// <summary>The state of the service's country data (from the internet registries).</summary>
    public class CountryDataStatusDTO
    {
        /// <summary>false: no country data could be loaded, country filters are inactive</summary>
        public bool Loaded { get; set; }

        /// <summary>when the data was last refreshed (UTC), if known</summary>
        public DateTime? UpdatedUtc { get; set; }

        public int RangeCount { get; set; }

        /// <summary>problems of the last update, e.g. "LACNIC: download failed"; null when there were none</summary>
        public string LastError { get; set; }

        /// <summary>the registries whose data is loaded, e.g. APNIC, RIPENCC</summary>
        public string[] Registries { get; set; }

        /// <summary>whether the service refreshes the data weekly by itself</summary>
        public bool AutoUpdate { get; set; }
    }
}
