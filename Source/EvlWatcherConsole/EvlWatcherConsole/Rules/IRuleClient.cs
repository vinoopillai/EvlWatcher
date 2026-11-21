using System;
using System.Collections.Generic;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.Rules
{
    /// <summary>
    /// The rule operations of the EvlWatcher service as seen by the view models.
    /// </summary>
    public interface IRuleClient
    {
        IList<GenericIPBlockingTaskDTO> GetRules();

        void SaveRule(GenericIPBlockingTaskDTO rule, bool isNew);

        void SetRuleActive(string name, bool active);

        /// <summary>State of the service's country data (used by the rules' country option and the Settings tab).</summary>
        CountryDataStatusDTO GetCountryDataStatus();

        /// <summary>Starts a refresh of the country data in the service; returns at once.</summary>
        void UpdateCountryDataNow();

        void SetCountryDataAutoUpdate(bool enabled);
    }

    /// <summary>
    /// A failure talking to the service. The message is human-readable and can be shown verbatim.
    /// </summary>
    public class RuleClientException : Exception
    {
        public RuleClientException(string message) : base(message)
        {
        }
    }
}
