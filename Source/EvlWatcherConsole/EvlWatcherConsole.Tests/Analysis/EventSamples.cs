using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security;
using System.Threading;
using EvlWatcherConsole.Analysis;

namespace EvlWatcherConsole.Tests.Analysis
{
    /// <summary>
    /// Builds event XML in the shape Windows renders it (EventLogRecord.ToXml), for the analyzer tests.
    /// Field names follow the real event schemas; the computer is SERVER01 and the domain CORP.
    /// </summary>
    internal static class EventSamples
    {
        public const string Security = "Security";
        public const string System = "System";
        public const string Application = "Application";
        public const string RdpCore = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

        private const string SecurityProvider = "Microsoft-Windows-Security-Auditing";
        private static long _recordId = 1000;

        public static DateTime Utc(string isoUtc) =>
            DateTime.Parse(isoUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

        public static AnalyzedEvent Failed4625(string ip, DateTime utc, string user = "administrator") =>
            Make(Security, SecurityProvider, 4625, utc, Data(
                ("SubjectUserSid", "S-1-0-0"), ("SubjectUserName", "-"), ("SubjectDomainName", "-"), ("SubjectLogonId", "0x0"),
                ("TargetUserSid", "S-1-0-0"), ("TargetUserName", user), ("TargetDomainName", ""), ("Status", "0xc000006d"),
                ("FailureReason", "%%2313"), ("SubStatus", "0xc000006a"), ("LogonType", "3"), ("LogonProcessName", "NtLmSsp "),
                ("AuthenticationPackageName", "NTLM"), ("WorkstationName", "-"), ("TransmittedServices", "-"), ("LmPackageName", "-"),
                ("KeyLength", "0"), ("ProcessId", "0x0"), ("ProcessName", "-"), ("IpAddress", ip), ("IpPort", "0")));

        public static AnalyzedEvent Logon4624(string ip, DateTime utc, string user = "administrator", int logonType = 3) =>
            Make(Security, SecurityProvider, 4624, utc, Data(
                ("SubjectUserSid", "S-1-0-0"), ("SubjectUserName", "-"), ("SubjectDomainName", "-"), ("SubjectLogonId", "0x0"),
                ("TargetUserSid", "S-1-5-21-1-2-3-500"), ("TargetUserName", user), ("TargetDomainName", "SERVER01"),
                ("TargetLogonId", "0x1234"), ("LogonType", logonType.ToString(CultureInfo.InvariantCulture)),
                ("LogonProcessName", "NtLmSsp "), ("AuthenticationPackageName", "NTLM"), ("WorkstationName", "-"),
                ("IpAddress", ip), ("IpPort", "0")));

        public static AnalyzedEvent Lockout4740(string user, DateTime utc) =>
            Make(Security, SecurityProvider, 4740, utc, Data(
                ("TargetUserName", user), ("TargetDomainName", "SERVER01"), ("TargetSid", "S-1-5-21-1-2-3-500"),
                ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", "SERVER01$"), ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x3e7")));

        public static AnalyzedEvent LogCleared1102(DateTime utc, string user = "admin2") =>
            MakeUserData(Security, "Microsoft-Windows-Eventlog", 1102, utc,
                "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>" +
                "<SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>" + SecurityElement.Escape(user) + "</SubjectUserName>" +
                "<SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x1f00</SubjectLogonId></LogFileCleared>");

        public static AnalyzedEvent SecurityLogFull1104(DateTime utc) =>
            MakeUserData(Security, "Microsoft-Windows-Eventlog", 1104, utc,
                "<FileIsFull xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'/>");

        public static AnalyzedEvent ServiceInstalled7045(string name, string path, DateTime utc) =>
            Make(System, "Service Control Manager", 7045, utc, Data(
                ("ServiceName", name), ("ImagePath", path), ("ServiceType", "user mode service"), ("StartType", "auto start"), ("AccountName", "LocalSystem")));

        public static AnalyzedEvent GroupAdd4732(string group, string member, DateTime utc) =>
            Make(Security, SecurityProvider, 4732, utc, Data(
                ("MemberName", member), ("MemberSid", "S-1-5-21-1-2-3-1005"), ("TargetUserName", group), ("TargetDomainName", "Builtin"),
                ("TargetSid", "S-1-5-32-544"), ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", "administrator"),
                ("SubjectDomainName", "SERVER01"), ("SubjectLogonId", "0x1234"), ("PrivilegeList", "-")));

        public static AnalyzedEvent UserCreated4720(string user, DateTime utc) =>
            Make(Security, SecurityProvider, 4720, utc, Data(
                ("TargetUserName", user), ("TargetDomainName", "SERVER01"), ("TargetSid", "S-1-5-21-1-2-3-1006"),
                ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", "administrator"), ("SubjectDomainName", "SERVER01")));

        public static AnalyzedEvent TaskCreated4698(string task, DateTime utc) =>
            Make(Security, SecurityProvider, 4698, utc, Data(
                ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", "administrator"), ("SubjectDomainName", "SERVER01"),
                ("TaskName", task), ("TaskContent", "...")));

        public static AnalyzedEvent ServiceCrash7031(string service, DateTime utc) =>
            Make(System, "Service Control Manager", 7031, utc, Data(
                ("param1", service), ("param2", "1"), ("param3", "60000"), ("param4", "1"), ("param5", "Restart the service")));

        public static AnalyzedEvent AppCrash1000(string app, DateTime utc) =>
            Make(Application, "Application Error", 1000, utc, Data(
                ("AppName", app), ("AppVersion", "1.0.0.0"), ("AppTimeStamp", "5f000000"), ("ModuleName", "ntdll.dll"),
                ("ExceptionCode", "c0000005")));

        public static AnalyzedEvent Disk7(DateTime utc) =>
            Make(System, "disk", 7, utc, Unnamed("\\Device\\Harddisk0\\DR0"));

        public static AnalyzedEvent KernelPower41(DateTime utc) =>
            Make(System, "Microsoft-Windows-Kernel-Power", 41, utc, Data(("BugcheckCode", "0"), ("SleepInProgress", "0")));

        public static AnalyzedEvent RdpConnection131(string clientIp, DateTime utc) =>
            MakeEventData(RdpCore, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", 131, utc,
                "<Data Name='ConnType'>TCP</Data><Data Name='ClientIP'>" + SecurityElement.Escape(clientIp) + "</Data>");

        /// <summary>Any event, for "same ID, other provider" cases.</summary>
        public static AnalyzedEvent Other(string log, string provider, int id, DateTime utc) =>
            Make(log, provider, id, utc, Data(("param1", "x")));

        /// <summary>Ntfs 98 as Windows logs it after a healthy check: Information level ("Volume C: is healthy").</summary>
        public static AnalyzedEvent NtfsVolumeHealthy98(DateTime utc) =>
            AnalyzedEvent.FromXml(System, Envelope(System, "Microsoft-Windows-Ntfs", 98, utc,
                "<EventData><Data Name='DriveName'>C:</Data><Data Name='DeviceName'>\\Device\\HarddiskVolume3</Data></EventData>", level: 4));

        /// <summary>Ntfs 55 as an Error: corruption found.</summary>
        public static AnalyzedEvent NtfsCorruption55(DateTime utc) =>
            AnalyzedEvent.FromXml(System, Envelope(System, "Ntfs", 55, utc,
                "<EventData><Data Name='DriveName'>D:</Data></EventData>", level: 2));

        #region building

        private static string Data(params (string name, string value)[] fields) =>
            string.Concat(fields.Select(f => "<Data Name='" + f.name + "'>" + SecurityElement.Escape(f.value) + "</Data>"));

        private static string Unnamed(params string[] values) =>
            string.Concat(values.Select(v => "<Data>" + SecurityElement.Escape(v) + "</Data>"));

        private static AnalyzedEvent Make(string log, string provider, int id, DateTime utc, string data) =>
            MakeEventData(log, provider, id, utc, data);

        private static AnalyzedEvent MakeEventData(string log, string provider, int id, DateTime utc, string data) =>
            AnalyzedEvent.FromXml(log, Envelope(log, provider, id, utc, "<EventData>" + data + "</EventData>"));

        private static AnalyzedEvent MakeUserData(string log, string provider, int id, DateTime utc, string userData) =>
            AnalyzedEvent.FromXml(log, Envelope(log, provider, id, utc, "<UserData>" + userData + "</UserData>"));

        private static string Envelope(string log, string provider, int id, DateTime utc, string body, int level = 0)
        {
            long record = Interlocked.Increment(ref _recordId);
            return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
                   "<Provider Name='" + provider + "'/><EventID>" + id + "</EventID><Version>0</Version><Level>" + level + "</Level>" +
                   "<TimeCreated SystemTime='" + utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture) + "'/>" +
                   "<EventRecordID>" + record + "</EventRecordID><Channel>" + log + "</Channel><Computer>SERVER01.corp.local</Computer>" +
                   "<Security/></System>" + body + "</Event>";
        }

        #endregion
    }
}
