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
