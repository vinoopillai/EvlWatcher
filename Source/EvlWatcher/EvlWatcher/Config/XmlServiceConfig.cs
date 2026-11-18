using EvlWatcher.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Xml.Linq;

namespace EvlWatcher.Config
{
    internal class XmlServiceConfiguration : IPersistentServiceConfiguration
    {
        #region private members

        private readonly object _syncObject = new object();

        private readonly IList<IPAddress> _blacklistAddresses = new List<IPAddress>();
        private readonly IList<string> _whiteListPatterns = new List<string>();
        private readonly IList<IPersistentTaskConfiguration> _taskConfigurations = new List<IPersistentTaskConfiguration>();

        private readonly ILogger _logger;
        private bool _inLoading = false;
        private int _consoleBacklog;
        private int _eventLogInterval;

        #endregion

        #region public constructor
        public XmlServiceConfiguration(ILogger logger)
        {
            _logger = logger;
        }

        #endregion

        #region public properties

        public int EventLogInterval
        {
            get
            {
                return _eventLogInterval;
            }
            set
            {
                if (_eventLogInterval != value)
                {
                    _eventLogInterval = value;
                    if (!_inLoading)
                        WriteGlobalConfig("CheckInterval", value.ToString());
                }
            }
        }

        public IQueryable<string> WhitelistPatterns => _whiteListPatterns.AsQueryable();

        public IQueryable<IPAddress> BlacklistAddresses => _blacklistAddresses.AsQueryable();

        public IQueryable<IPersistentTaskConfiguration> TaskConfigurations
        {
            get
            {
                return _taskConfigurations.AsQueryable();
            }
        }

        public SeverityLevel LogLevel
        {
            get
            {
                return _logger.LogLevel;
            }
            set
            {
                if (_logger.LogLevel != value)
                {
                    _logger.LogLevel = value;
                    if (!_inLoading)
                        WriteGlobalConfig("LogLevel", value.ToString());
                }
            }
        }

        public int ConsoleBackLog
        {
            get
            {
                return _consoleBacklog;
            }
            set
            {
                if(_consoleBacklog != value)
                {
                    _consoleBacklog = value;
                    _logger.SetConsoleHistoryMaxCount(_consoleBacklog);
                    if (!_inLoading)
                    {
                        WriteGlobalConfig("ConsoleBacklog", value.ToString());
                    }
                }
            }
        }

        #endregion

        #region public operations
        public bool AddWhiteListPattern(string pattern)
        {
            bool changed = false;

            if (pattern.Contains(";"))
                return changed;

            lock (_syncObject)
            {
                if (!_whiteListPatterns.Contains(pattern))
                {
                    _whiteListPatterns.Add(pattern);
                    changed = true;

                    string s = "";
                    foreach (string p in _whiteListPatterns)
                        s += p + ";";

                    WriteGlobalConfig("WhiteList", s);
                }
            }

            return changed;
        }

        public bool RemoveWhiteListPattern(string pattern)
        {
            bool changed = false;

            lock (_syncObject)
            {
                if (_whiteListPatterns.Contains(pattern))
                {
                    _whiteListPatterns.Remove(pattern);
                    changed = true;

                    string s = "";
                    foreach (string p in _whiteListPatterns)
                        s += p + ";";

                    WriteGlobalConfig("WhiteList", s);
                }
            }

            return changed;
        }

        public bool AddBlackListAddress(IPAddress address)
        {
            bool changed = false;

            lock (_syncObject)
            {
                if (!_blacklistAddresses.Contains(address))
                {
                    _blacklistAddresses.Add(address);
                    changed = true;

                    string s = "";
                    foreach (IPAddress ip in _blacklistAddresses)
                        s += ip.ToString() + ";";
                   
                    WriteGlobalConfig("Banlist", s);
                }
            }

            return changed;
        }

        public bool RemoveBlackListAddress(IPAddress address)
        {
            bool changed = false;

            lock (_syncObject)
            {
                if (_blacklistAddresses.Contains(address))
                {
                    _blacklistAddresses.Remove(address);
                    changed = true;

                    string s = "";
                    foreach (IPAddress ip in _blacklistAddresses)
                        s += ip.ToString() + ";";

                    WriteGlobalConfig("Banlist", s);
                }
            }

            return changed;
        }

        public IPersistentTaskConfiguration AddTask(string taskName)
        {
            lock (_syncObject)
            {
                XDocument d = XDocument.Load(ConfigFile.Path);

                if (d.Descendants("Task").Any(t => t.Attribute("Name") != null && t.Attribute("Name").Value.Trim() == taskName.Trim()))
                    throw new InvalidOperationException($"A task named \"{taskName}\" already exists");

                XElement tasks = d.Root.Element("Tasks");
                if (tasks == null)
                {
                    tasks = new XElement("Tasks");
                    d.Root.Add(tasks);
                }

                var taskEl = new XElement("Task",
                    new XAttribute("Name", taskName),
                    new XAttribute("Active", "false"),
                    new XElement("Description", ""),
                    new XElement("LockTime", "3600"),
                    new XElement("OnlyNew", "False"),
                    new XElement("EventAge", "120"),
                    new XElement("TriggerCount", "5"),
                    new XElement("PermaBanCount", "3"),
                    new XElement("EventPath", ""),
                    new XElement("RegexBoosters"),
                    new XElement("Regex", ""));
                tasks.Add(taskEl);
                ConfigFile.Save(d);

                var loadedTask = XmlTaskConfig.FromXmlElement(taskEl, _syncObject, _logger);
                _taskConfigurations.Add(loadedTask);
                _logger.Dump($"added configuration for generic task \"{taskName}\"", SeverityLevel.Debug);
                return loadedTask;
            }
        }

        public bool RemoveTask(string taskName)
        {
            lock (_syncObject)
            {
                XDocument d = XDocument.Load(ConfigFile.Path);
                XElement taskEl = d.Descendants("Task")
                    .FirstOrDefault(t => t.Attribute("Name") != null && t.Attribute("Name").Value.Trim() == (taskName ?? string.Empty).Trim());
                if (taskEl == null)
                    return false;

                taskEl.Remove();
                ConfigFile.Save(d);

                foreach (var t in _taskConfigurations.Where(c => (c.TaskName ?? string.Empty).Trim() == taskName.Trim()).ToList())
                    _taskConfigurations.Remove(t);
                _logger.Dump($"removed configuration for generic task \"{taskName}\"", SeverityLevel.Debug);
                return true;
            }
        }

        #endregion

        #region private operations

        private void WriteGlobalConfig(string property, string value)
        {
            lock (_syncObject)
            {
                _logger.Dump($"Writing global config for: {property} = {value}", SeverityLevel.Verbose);

                XDocument d = XDocument.Load(ConfigFile.Path);
                XElement taskEl = d.Root.Element("Global");
                if (taskEl == null)
                {
                    taskEl = new XElement("Global");
                    d.Root.Add(taskEl);
                }
                if (taskEl != null)
                {
                    XElement val = taskEl.Element(property);
                    if (val == null)
                    {
                        val = new XElement(property);
                        taskEl.Add(val);
                    }
                    if (val != null)
                    {
                        val.Value = value.ToString();
                    }

                }
                ConfigFile.Save(d);
            }
        }

        /// <summary>
        /// Loads atomically: everything is parsed into locals first, the live state is only replaced once all of it parsed.
        /// If anything throws, the previously loaded state stays untouched.
        /// </summary>
        private void LoadConfiguration()
        {
            lock (_syncObject)
            {
                try
                {
                    _inLoading = true;
                    XDocument d = XDocument.Load(ConfigFile.Path);

                    //this line probably wont get displayed, unless debug is default before loading the config.
                    _logger.Dump($"now loading global settings", SeverityLevel.Debug);

                    XElement globalConfig = d.Root.Element("Global");
                    if (globalConfig == null)
                    {
                        _logger.Dump("Global Service config could not be loaded", SeverityLevel.Critical);
                        throw new FormatException();
                    }

                    SeverityLevel? logLevel = null;
                    XElement logLevelElement = globalConfig.Element("LogLevel");
                    if (logLevelElement != null)
                        logLevel = GetLogLevelFromString(logLevelElement.Value);

                    int? checkInterval = null;
                    XElement checkIntervalElement = globalConfig.Element("CheckInterval");
                    if (checkIntervalElement != null)
                        checkInterval = int.Parse(checkIntervalElement.Value);

                    List<IPAddress> newBlacklist = null;
                    XElement banlist = globalConfig.Element("Banlist");
                    if (banlist != null)
                    {
                        newBlacklist = new List<IPAddress>();
                        foreach (string ip in banlist.Value.Split(new string[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                            newBlacklist.Add(IPAddress.Parse(ip));
                    }

                    // a missing <Banlist>/<WhiteList> element deliberately keeps the previously loaded list (null = untouched)
                    List<string> newWhitelist = null;
                    XElement whitelist = globalConfig.Element("WhiteList");
                    if (whitelist != null)
                        newWhitelist = whitelist.Value.Split(new string[] { ";" }, StringSplitOptions.RemoveEmptyEntries).ToList();

                    int? consoleBacklog = null;
                    XElement consoleBacklogElement = globalConfig.Element("ConsoleBacklog");
                    if (consoleBacklogElement != null)
                        consoleBacklog = int.Parse(consoleBacklogElement.Value);

                    var newTasks = new List<IPersistentTaskConfiguration>();
                    foreach (var taskNode in d.Descendants("Task").Where(t => t.Attribute("Name") != null))
                    {
                        try
                        {
                            //TODO: Dependency Injection
                            newTasks.Add(XmlTaskConfig.FromXmlElement(taskNode, _syncObject, _logger));
                        }
                        catch (Exception ex)
                        {
                            _logger.Dump(ex);
                            throw;
                        }
                    }

                    //everything parsed: from here on nothing throws on its own, swap the state in
                    if (logLevel.HasValue)
                        LogLevel = logLevel.Value;
                    //from now on, the log/output levels should work.
                    _logger.Dump($"Log level is set to : {LogLevel} ", SeverityLevel.Verbose);

                    if (checkInterval.HasValue)
                    {
                        EventLogInterval = checkInterval.Value;
                        _logger.Dump($"Check interval is set to : {EventLogInterval} s", SeverityLevel.Verbose);
                    }

                    if (newBlacklist != null)
                    {
                        //replace, do not append: a reload would otherwise duplicate the entries
                        _blacklistAddresses.Clear();
                        foreach (IPAddress ip in newBlacklist)
                            _blacklistAddresses.Add(ip);
                        _logger.Dump($"Loaded permabanlist: {banlist.Value}", SeverityLevel.Verbose);
                    }

                    if (newWhitelist != null)
                    {
                        _whiteListPatterns.Clear();
                        foreach (string pattern in newWhitelist)
                            _whiteListPatterns.Add(pattern);
                        _logger.Dump($"Loaded whitelist: {whitelist.Value}", SeverityLevel.Verbose);
                    }

                    if (consoleBacklog.HasValue)
                    {
                        _consoleBacklog = consoleBacklog.Value;
                        _logger.Dump($"Console backlog is set to {_consoleBacklog}", SeverityLevel.Verbose);
                    }

                    _logger.Dump($"finished loading global settings", SeverityLevel.Debug);
                    _logger.Dump($"now loading generic tasks", SeverityLevel.Debug);

                    _taskConfigurations.Clear();
                    foreach (var loadedTask in newTasks)
                    {
                        _taskConfigurations.Add(loadedTask);
                        _logger.Dump($"loaded configuration for generic task \"{loadedTask.TaskName}\"({(loadedTask.Active ? "active" : "inactive")})", SeverityLevel.Debug);
                    }
                    _logger.Dump($"finished loading generic tasks", SeverityLevel.Debug);
                }
                finally
                {
                    _inLoading = false;
                }
            }
        }

        private SeverityLevel GetLogLevelFromString(string value)
        {
            return (SeverityLevel)Enum.Parse(typeof(SeverityLevel), value);
        }

        public void Load()
        {
            LoadConfiguration();
        }

        #endregion
    }
}
