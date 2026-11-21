using System.Collections.Generic;
using EvlWatcher.WCF.DTO;

namespace EvlWatcherConsole.Analysis
{
    /// <summary>
    /// The service operations the Analyzer tab needs. Failures throw <see cref="Rules.RuleClientException"/> with a
    /// message that can be shown as-is.
    /// </summary>
    public interface IAnalyzerClient
    {
        IList<GenericIPBlockingTaskDTO> GetRules();

        IList<string> GetWhiteListPatterns();

        IList<string> GetTemporarilyBannedIPs();

        IList<string> GetPermanentlyBannedIPs();

        /// <summary>Adds all addresses to the permanent ban list in one call.</summary>
        void BanPermanently(IList<string> addresses);

        /// <summary>Saves an existing rule.</summary>
        void SaveRule(GenericIPBlockingTaskDTO rule);
    }

    /// <summary>Asks the admin before an action changes anything.</summary>
    public interface IConfirmer
    {
        bool Confirm(string title, string message);
    }
}
