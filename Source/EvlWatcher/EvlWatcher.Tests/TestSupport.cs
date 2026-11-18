using System;
using System.Collections.Generic;
using System.IO;
using EvlWatcher.Config;
using EvlWatcher.Logging;

namespace EvlWatcher.Tests
{
    internal class NullLogger : ILogger
    {
        public SeverityLevel LogLevel { get; set; } = SeverityLevel.Off;

        public void Dump(string message, SeverityLevel severity) { }

        public void Dump(Exception e, SeverityLevel severity = SeverityLevel.Error) { }

        public int GetConsoleHistoryMaxCount() => 0;

        public void SetConsoleHistoryMaxCount(int count) { }

        public IList<LogEntry> GetConsoleHistory() => new List<LogEntry>();
    }

    /// <summary>
    /// Copies a minimal config to a temp file and points ConfigFile.Path at it, so tests never touch the real config.xml.
    /// </summary>
    internal sealed class TempConfig : IDisposable
    {
        private const string MinimalConfig = @"<?xml version=""1.0"" encoding=""utf-8""?>
<Config>
  <Global>
    <LogLevel>Info</LogLevel>
    <ConsoleBacklog>100</ConsoleBacklog>
    <CheckInterval>30</CheckInterval>
    <WhiteList>127.0.0.1;</WhiteList>
    <Banlist></Banlist>
  </Global>
  <Tasks>
    <Task Name=""Sample"" Active=""true"">
      <Description>Sample rule</Description>
      <LockTime>3600</LockTime>
      <OnlyNew>False</OnlyNew>
      <EventAge>120</EventAge>
      <TriggerCount>5</TriggerCount>
      <PermaBanCount>3</PermaBanCount>
      <EventPath>Security</EventPath>
      <RegexBoosters>
        <Booster>Sample</Booster>
      </RegexBoosters>
      <Regex>&lt;Data Name=.IpAddress.&gt;(\d+)&lt;/Data&gt;</Regex>
    </Task>
  </Tasks>
</Config>";

        private readonly string _previousPath;
        private readonly string _directory;

        public TempConfig()
        {
            _previousPath = ConfigFile.Path;
            _directory = Path.Combine(Path.GetTempPath(), "EvlWatcher.Tests." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            FilePath = Path.Combine(_directory, "config.xml");
            File.WriteAllText(FilePath, MinimalConfig);
            ConfigFile.Path = FilePath;
        }

        public string FilePath { get; }

        public void Dispose()
        {
            ConfigFile.Path = _previousPath;
            try { Directory.Delete(_directory, true); } catch (IOException) { }
        }
    }
}
