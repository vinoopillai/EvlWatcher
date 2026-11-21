using EvlWatcher.WCF;
using EvlWatcher.WCF.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.ServiceModel;

namespace EvlWatcherConsole.Model
{
    public class EvlWatcherModel : EvlWatcherConsole.Rules.IRuleClient, EvlWatcherConsole.Analysis.IAnalyzerClient
    {
        #region private members

        private readonly object _syncObject = new object();
        private readonly System.ServiceModel.Channels.Binding _binding;
        private readonly EndpointAddress _address;

        /// <summary>
        /// one factory for the lifetime of the model (creating one per call is expensive); guarded by <see cref="_syncObject"/>
        /// </summary>
        private ChannelFactory<IEvlWatcherService> _factory;

        #endregion

        #region public constructors

        public EvlWatcherModel()
            : this(new NetNamedPipeBinding() { MaxReceivedMessageSize = Int32.MaxValue /* big console logs */ },
                   new EndpointAddress("net.pipe://localhost/EvlWatcher"))
        {
        }

        /// <summary>
        /// for tests/diagnostics: talk to the service over another binding or address
        /// </summary>
        public EvlWatcherModel(System.ServiceModel.Channels.Binding binding, EndpointAddress address)
        {
            _binding = binding;
            _address = address;
        }

        #endregion

        #region public properties

        public IReadOnlyList<SeverityLevelDTO> ConsoleLevels
        {
            get
            {
                return new List<SeverityLevelDTO>()
                    { SeverityLevelDTO.Off,
                    SeverityLevelDTO.Debug,
                    SeverityLevelDTO.Verbose,
                    SeverityLevelDTO.Info,
                    SeverityLevelDTO.Warning,
                    SeverityLevelDTO.Error,
                    SeverityLevelDTO.Critical }.AsReadOnly();
            }
        }

        public GlobalConfigDTO GetGlobalConfig()
        {
            return Call(s => s.GetGlobalConfig());
        }

        public bool IsServiceResponding
        {
            get
            {
                return Call(s => s.GetIsRunning());
            }
        }
        #endregion

        #region public operations

        public IQueryable<IPAddress> GetTemporarilyBannedIPs()
        {
            return Call(s => s.GetTemporarilyBannedIPs()).Select(IPAddress.Parse).ToList().AsQueryable();
        }

        public IQueryable<IPAddress> GetPermanentlyBannedIPs()
        {
            return Call(s => s.GetPermanentlyBannedIPs()).Select(IPAddress.Parse).ToList().AsQueryable();
        }

        public IQueryable<string> GetWhiteListPatterns()
        {
            return Call(s => s.GetWhiteListEntries()).AsQueryable();
        }

        public IQueryable<LogEntryDTO> GetConsoleHistory(SeverityLevelDTO severityLevel)
        {
            if (severityLevel == SeverityLevelDTO.Off)
            {
                return new List<LogEntryDTO>().AsQueryable();
            }
            else
            {
                return Call(s => s.GetConsoleHistory()).Where(entry => entry.Severity >= severityLevel).AsQueryable();
            }
        }

        public void AddWhiteListEntry(string s)
        {
            Call(service => service.AddWhiteListEntry(s));
        }

        public void RemoveWhiteListEntry(string s)
        {
            Call(service => service.RemoveWhiteListEntry(s));
        }

        public void AddPermanentIPBan(IPAddress a)
        {
            Call(service => service.SetPermanentBan(a.ToString()));
        }

        public void RemovePermanentIPBan(IPAddress a)
        {
            Call(service => service.ClearPermanentBan(a.ToString()));
        }
        #endregion


        #region IRuleClient

        IList<GenericIPBlockingTaskDTO> EvlWatcherConsole.Rules.IRuleClient.GetRules()
        {
            GenericIPBlockingTaskDTO[] rules = null;
            CallRuleService(() => rules = Call(s => s.GetRules()));
            return rules ?? new GenericIPBlockingTaskDTO[0];
        }

        void EvlWatcherConsole.Rules.IRuleClient.SaveRule(GenericIPBlockingTaskDTO rule, bool isNew)
        {
            CallRuleService(() => Call(s => s.SaveRule(rule, isNew)));
        }

        void EvlWatcherConsole.Rules.IRuleClient.SetRuleActive(string name, bool active)
        {
            CallRuleService(() => Call(s => s.SetRuleActive(name, active)));
        }

        CountryDataStatusDTO EvlWatcherConsole.Rules.IRuleClient.GetCountryDataStatus()
        {
            CountryDataStatusDTO status = null;
            CallRuleService(() => status = Call(s => s.GetCountryDataStatus()));
            return status ?? new CountryDataStatusDTO();
        }

        void EvlWatcherConsole.Rules.IRuleClient.UpdateCountryDataNow()
        {
            CallRuleService(() => Call(s => s.UpdateCountryDataNow()));
        }

        void EvlWatcherConsole.Rules.IRuleClient.SetCountryDataAutoUpdate(bool enabled)
        {
            CallRuleService(() => Call(s => s.SetCountryDataAutoUpdate(enabled)));
        }

        #endregion

        #region IAnalyzerClient

        IList<GenericIPBlockingTaskDTO> EvlWatcherConsole.Analysis.IAnalyzerClient.GetRules()
        {
            return ((EvlWatcherConsole.Rules.IRuleClient)this).GetRules();
        }

        IList<string> EvlWatcherConsole.Analysis.IAnalyzerClient.GetWhiteListPatterns()
        {
            string[] result = null;
            CallRuleService(() => result = Call(s => s.GetWhiteListEntries()));
            return result ?? new string[0];
        }

        IList<string> EvlWatcherConsole.Analysis.IAnalyzerClient.GetTemporarilyBannedIPs()
        {
            string[] result = null;
            CallRuleService(() => result = Call(s => s.GetTemporarilyBannedIPs()));
            return result ?? new string[0];
        }

        IList<string> EvlWatcherConsole.Analysis.IAnalyzerClient.GetPermanentlyBannedIPs()
        {
            string[] result = null;
            CallRuleService(() => result = Call(s => s.GetPermanentlyBannedIPs()));
            return result ?? new string[0];
        }

        void EvlWatcherConsole.Analysis.IAnalyzerClient.BanPermanently(IList<string> addresses)
        {
            string[] list = addresses.ToArray();
            CallRuleService(() => Call(s => s.SetPermanentBans(list)));
        }

        void EvlWatcherConsole.Analysis.IAnalyzerClient.SaveRule(GenericIPBlockingTaskDTO rule)
        {
            CallRuleService(() => Call(s => s.SaveRule(rule, false)));
        }

        int EvlWatcherConsole.Analysis.IAnalyzerClient.GetCheckIntervalSeconds()
        {
            int seconds = 30;
            CallRuleService(() => seconds = Call(s => s.GetGlobalConfig()).EventLogInterval);
            return seconds > 0 ? seconds : 30;
        }

        private static void CallRuleService(Action call)
        {
            try
            {
                call();
            }
            catch (FaultException<ServiceFaultDTO> ex)
            {
                throw new EvlWatcherConsole.Rules.RuleClientException(ex.Detail.Message);
            }
            catch (EndpointNotFoundException)
            {
                throw new EvlWatcherConsole.Rules.RuleClientException("EvlWatcher service is not responding.");
            }
            catch (CommunicationException)
            {
                throw new EvlWatcherConsole.Rules.RuleClientException("EvlWatcher service is not responding.");
            }
            catch (TimeoutException)
            {
                throw new EvlWatcherConsole.Rules.RuleClientException("EvlWatcher service is not responding.");
            }
        }

        #endregion
        #region private operations

        /// <summary>
        /// Runs one service operation on a fresh channel and always ends that channel: Close() on success, Abort() on any failure.
        /// Every open channel is a session on the service, which accepts only 100 sessions per CPU core (WCF default) and keeps an
        /// abandoned one for its 10 minute inactivity timeout. Leaking them made the service stop answering after 1-2 minutes.
        /// </summary>
        private T Call<T>(Func<IEvlWatcherService, T> operation)
        {
            IEvlWatcherService channel = Factory.CreateChannel();
            var clientChannel = (IClientChannel)channel;
            bool closed = false;
            try
            {
                T result = operation(channel);
                clientChannel.Close();
                closed = true;
                return result;
            }
            finally
            {
                if (!closed)
                    clientChannel.Abort();
            }
        }

        private void Call(Action<IEvlWatcherService> operation)
        {
            Call(s => { operation(s); return true; });
        }

        private ChannelFactory<IEvlWatcherService> Factory
        {
            get
            {
                lock (_syncObject)
                {
                    if (_factory == null || _factory.State == CommunicationState.Faulted || _factory.State == CommunicationState.Closed)
                    {
                        _factory?.Abort();
                        _factory = new ChannelFactory<IEvlWatcherService>(_binding, _address);
                    }
                    return _factory;
                }
            }
        }

        internal void SaveGlobalConfig(SeverityLevelDTO logLevel, int consoleBackLog, int checkInterval)
        {
            Call(s => s.SaveGlobalConfig(logLevel, consoleBackLog, checkInterval));
        }

        internal void RemoveTemporaryBan(IPAddress selectedTemporaryIP)
        {
            Call(s => s.RemoveTemporaryBan(selectedTemporaryIP.ToString()));
        }

        internal void AddPermanentIPBans(IPAddress[] iPAddresses)
        {
            Call(s => s.SetPermanentBans(iPAddresses.Select(ip => ip.ToString()).ToArray()));
        }

        #endregion
    }
}
