using System.Collections.Generic;
using System.ServiceModel;
using EvlWatcher.WCF.DTO;

namespace EvlWatcher.WCF
{
    [ServiceContract]
    public interface IEvlWatcherService
    {
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        GlobalConfigDTO GetGlobalConfig();
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        bool GetIsRunning();
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetTemporarilyBannedIPs();
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetPermanentlyBannedIPs();
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SetPermanentBan(string address);
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SetPermanentBans(string[] addresses);
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void ClearPermanentBan(string address);
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void AddWhiteListEntry(string filter);
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void RemoveWhiteListEntry(string filter);
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetWhiteListEntries();
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        IList<LogEntryDTO> GetConsoleHistory();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SaveGlobalConfig(SeverityLevelDTO logLevel, int consoleBackLog, int checkInterval);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void RemoveTemporaryBan(string address);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        GenericIPBlockingTaskDTO[] GetRules();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SaveRule(GenericIPBlockingTaskDTO rule, bool isNew);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SetRuleActive(string taskName, bool active);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        CountryDataStatusDTO GetCountryDataStatus();

        /// <summary>starts a refresh of the country data in the background and returns at once</summary>
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void UpdateCountryDataNow();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SetCountryDataAutoUpdate(bool enabled);
    }
}
