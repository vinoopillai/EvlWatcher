# Event Log Analyzer Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an **Analyzer** tab to EvlWatcherConsole. It scans this server's event logs for the last 24 hours, 7 days or 30 days, lists attack, security-change and server-health findings, and offers confirmed one-click fixes. Released as v3.2.0.

**Architecture:**
- **Analysis code:** a pure `EvlWatcherConsole/Analysis/` namespace turns events plus service state into `Finding`s. It has no WPF and no WCF, the same pattern as `RuleBuilder`.
- **Event source:** a thin `EventLogSource` reads logs with time- and ID-filtered XPath.
- **View model:** `AnalyzerViewModel` runs the scan on a background task, supports cancel, and executes actions through `IAnalyzerClient`, which `EvlWatcherModel` implements over the existing WCF operations.
- **Service:** unchanged.

**Tech Stack:** WPF on .NET Framework 4.7.2, C# 7.3, `System.Diagnostics.Eventing.Reader`, MSTest 4.

**Spec:** `docs/superpowers/specs/2026-11-21-event-log-analyzer-design.md`. Read it for the check tables, screen sketch and anti-goals.

## Global Constraints

- **Code style:** follow the console's conventions in AGENTS.md "Console UI" and "Code conventions":
  - C# 7.3, block namespaces, `_camelCase` fields.
  - Theme brushes through `DynamicResource`.
  - Vector icons only.
  - Icon-only buttons need a `ToolTip` and `AutomationProperties.Name`.
- **No service changes:** no change to the service, the WCF contract or `config.xml`.
- **Range options:** `Last 24 hours` (default), `Last 7 days`, `Last 30 days`.
- **Actions:** run only after a Yes/No confirmation that states the exact change, and only through `EvlWatcherModel.Call(...)`.
- **Widen rule window:**
  - Allowed windows are 1 h, 6 h and 24 h. Never more than 24 h.
  - Set `LockTime = max(LockTime, newWindow)`.
- **Never offer a ban** for whitelisted, local (loopback, unspecified, this machine's own addresses) or private addresses.
- **Severity:** Critical is reserved for the cases the spec marks Critical.
- **Test data:** test samples use `SERVER01` / `CORP` in place of the real server and domain names.
- **Version:** 3.2.0.

## Review Focus

1. **Huge logs on a busy server, 30-day scan.**
   - Expected: Cancel stops the scan within about a second and the tab is usable again.
   - Test: Task 6 `CancelStopsScanAndShowsCancelled`.
2. **Service not responding when Scan is clicked.**
   - Expected: attack checks are skipped with a notice, and the security and health checks still show.
   - Test: Task 6 `ServiceDownStillShowsOtherGroups`.
3. **Service goes down between scan and click.**
   - Expected: the action shows the error on that finding and is not marked Done.
   - Test: Task 6 `FailedActionShowsErrorAndStaysOpen`.
4. **Odd IP fields:**
   - `IpAddress` of `-`, empty or `::1` must be ignored.
   - An RdpCoreTS `ClientIP` with a port (`1.2.3.4:51234`, `[2001:db8::1]:3389`) must be parsed.
   - Test: Task 2 `IgnoresMissingAndLocalAddresses` and `ParsesClientIpWithPort`.
5. **A log the console can't read** (access denied).
   - Expected: it is listed as "couldn't read", with no crash.
   - Test: Task 5 `UnreadableLogIsListedNotThrown`.

---

### Task 1: Analysis model, address helpers and test event factory

**Files:**
- Create in `Source/EvlWatcherConsole/EvlWatcherConsole/Analysis/`:
  - `AnalyzedEvent.cs`
  - `Finding.cs` (`Finding`, `FindingAction`, enums)
  - `AnalysisRange.cs`
  - `AnalyzerInput.cs`
  - `AnalysisResult.cs`
  - `AnalyzerThresholds.cs`
  - `AddressClassifier.cs`
- Create tests in `Source/EvlWatcherConsole/EvlWatcherConsole.Tests/`:
  - `Analysis/EventSamples.cs` (factory)
  - `Analysis/AddressClassifierTests.cs`
  - `Analysis/AnalyzedEventTests.cs`

**Interfaces (Produces), namespace `EvlWatcherConsole.Analysis`:**
- **Enums:**
  - `enum FindingSeverity { Info = 0, Warning = 1, Critical = 2 }`
  - `enum FindingCategory { Attack, SecurityChange, ServerHealth }`
  - `enum FindingActionKind { BanPermanently, BanAll, WidenRuleWindow }`
  - `enum AnalysisRange { Last24Hours, Last7Days, Last30Days }`
- **`AnalysisRanges` (static class):**
  - `TimeSpan ToTimeSpan(this AnalysisRange r)`: 24 h, 7 d, 30 d.
  - `string Label(this AnalysisRange r)`: "Last 24 hours", "Last 7 days", "Last 30 days".
- **`AnalyzedEvent`:**
  - Properties: `string LogName`, `string Provider`, `int EventId`, `long RecordId`, `DateTime TimeUtc`, `string Xml`, `IReadOnlyDictionary<string,string> Data`.
  - `Data` holds the leaf elements under `EventData` (keyed by the `Name` attribute, or `#1`, `#2`, … for unnamed `Data`) and under `UserData` (keyed by local element name). Values are trimmed.
  - `static AnalyzedEvent FromXml(string logName, string xml)` parses the System fields with `XDocument`, namespace-agnostic. `Provider` comes from `Provider/@Name`; when absent, use `@EventSourceName`.
  - `string Get(string key)` returns null when the key is missing.
- **`FindingAction`:**
  - Properties: `FindingActionKind Kind`, `IReadOnlyList<string> Addresses`, `string RuleName`, `int NewEventAgeSeconds`, `int NewLockTimeSeconds`, `string Label`, `string ConfirmationText`.
- **`Finding`:**
  - Properties: `FindingSeverity Severity`, `FindingCategory Category`, `string Title`, `string Details`, `string Advice`, `string Address` (nullable), `DateTime LastSeenUtc`, `IList<FindingAction> Actions`.
- **`AnalyzerInput`:**
  - Properties: `DateTime NowUtc`, `AnalysisRange Range`, `IList<GenericIPBlockingTaskDTO> Rules` (null when the service didn't answer), `IList<string> WhitelistPatterns`, `ISet<string> TemporarilyBanned`, `ISet<string> PermanentlyBanned`, `ISet<string> LocalAddresses`.
  - `DateTime FromUtc => NowUtc - Range.ToTimeSpan()`.
- **`AnalysisResult`:**
  - Properties: `IList<Finding> Findings` (sorted), `IList<string> LogsChecked`, `IList<string> LogsMissing`, `IList<string> LogsUnreadable`, `int EventsRead`, `TimeSpan Duration`, `string Notice`, `FindingAction BanAllAction` (null when there's nothing to ban).
- **`AnalyzerThresholds` (constants):**

  | Constant | Value |
  |---|---|
  | `HeavyAttackerAttempts` | 20 |
  | `RdpFloodConnections` | 50 |
  | `FailuresBeforeLogon` | 3 |
  | `LockoutWarningCount` | 3 |
  | `ServiceCrashWarningCount` | 2 |
  | `AppCrashWarningCount` | 3 |
  | `WidenWindowSteps` | `{ 3600, 21600, 86400 }` |

- **`AddressClassifier` (static class):**
  - `bool TryParse(string value, out IPAddress ip)`:
    - Accepts `a.b.c.d`, IPv6, and the forms `a.b.c.d:port` and `[v6]:port`.
    - Rejects `-`, empty, and digit-only strings.
  - `bool IsLocal(IPAddress ip, ISet<string> localAddresses)`: loopback, `0.0.0.0`, `::`, or listed in `localAddresses`.
  - `bool IsPrivate(IPAddress ip)`: 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10.
  - `bool IsWhitelisted(string ip, IEnumerable<string> patterns)`: same semantics as the service, a `*`/`?` wildcard turned into an anchored regex (`^` + escaped pattern + `$`).
  - `ISet<string> GetLocalAddresses()`: this machine's addresses from `Dns.GetHostAddresses(Dns.GetHostName())`, plus loopbacks. On error, loopbacks only.
- **`EventSamples` (test helper):** static factory methods returning `AnalyzedEvent` built from XML templates, using the real Windows schemas, `SERVER01` and `CORP`:
  - `Failed4625(ip, utc, user)`
  - `Logon4624(ip, utc, user, logonType)`
  - `Lockout4740(user, utc)`
  - `LogCleared1102(utc, user)`
  - `ServiceInstalled7045(name, path, utc)`
  - `GroupAdd4732(group, member, utc)`
  - `UserCreated4720(user, utc)`
  - `TaskCreated4698(task, utc)`
  - `ServiceCrash7031(service, utc)`
  - `AppCrash1000(app, utc)`
  - `Disk7(utc)`
  - `KernelPower41(utc)`
  - `RdpConnection131(clientIp, utc)`

  Each sets the right `LogName`, provider and channel. `RecordId` is unique.

- [ ] **Step 1: Write the failing tests.**
  - `AddressClassifierTests`:
    - `TryParse` accepts `1.2.3.4`, `1.2.3.4:51234`, `[2001:db8::1]:3389` and `2001:db8::1`, and rejects `-`, `""` and `4625`.
    - `IsPrivate` is true for `10.0.0.5`, `172.20.1.1`, `192.168.1.50`, `fe80::1` and false for `5.175.140.23`.
    - `IsWhitelisted("192.168.1.50", {"192.168.*"})` is true.
    - `IsWhitelisted("10.0.0.15", {"10.0.0.1"})` is false.
    - `IsLocal(127.0.0.1)` is true.
  - `AnalyzedEventTests`:
    - `EventSamples.Failed4625("5.175.140.23", t, "administrator")` round-trips through `FromXml`: `EventId == 4625`, `Provider == "Microsoft-Windows-Security-Auditing"`, `Get("IpAddress") == "5.175.140.23"`, `TimeUtc == t`.
    - A `UserData` event (`LogCleared1102`) exposes `Get("SubjectUserName")`.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Run: `dotnet test Source\EvlWatcherConsole\EvlWatcherConsole.Tests -c Release --filter "FullyQualifiedName~Analysis"`
  - Expected: build FAIL (the types don't exist yet).
- [ ] **Step 3: Implement the types above.**
- [ ] **Step 4: Run the full console suite.**
  - Run: `dotnet test Source\EvlWatcherConsole\EvlWatcherConsole.Tests -c Release`
  - Expected: all pass.
- [ ] **Step 5: Commit** with the message "Analyzer: model types, address helpers".

### Task 2: Attack checks (group 1)

**Files:**
- Create: `Analysis/AttackChecks.cs`
- Test: `EvlWatcherConsole.Tests/Analysis/AttackChecksTests.cs`

**Interfaces:**
- Consumes: Task 1 types, plus `RuleBuilder.Match(GenericIPBlockingTaskDTO, string xml) → IPAddress`.
- Produces: `static class AttackChecks { static IList<Finding> Run(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input); static FindingAction BuildBanAll(IEnumerable<Finding> findings); }`

**What it does:**
- **Matching:** for each active rule, for each log in `rule.EventPath`, an event counts when `RuleBuilder.Match(rule, ev.Xml)` returns an IP.
- **Skipped addresses:** whitelisted, local and private IPs produce no attack findings.
- **"Banned":** the IP is in `TemporarilyBanned` or `PermanentlyBanned`.
- **Evading (Warning)**, per rule and IP:
  - Condition: total ≥ `TriggerCount`, the IP is not banned, and the most attempts inside any `EventAge` window is less than `TriggerCount`.
  - "Needed span": the minimum, over consecutive runs of `TriggerCount` attempts, of (last − first) + 1 s.
- **Heavy (Warning):** not evading, not banned, total ≥ 20.
- **One finding per (rule, IP):**
  - Title example: `5.175.140.23 tried 15 times in 6 h (every ~24 min) — too slow for rule X (5 within 60 min)`.
  - Action: `BanPermanently`.
- **Widen action:**
  - Added once per rule, attached to every evading finding of that rule.
  - New window: the smallest step in `WidenWindowSteps` that is ≥ the largest needed span of that rule's evading IPs. If none is that large, use 86400, but only if 86400 is at least one IP's needed span.
  - Only offered when the new window is greater than `rule.EventAge`.
  - `NewLockTimeSeconds = max(rule.LockTime, newWindow)`.
  - Confirmation text follows the spec example exactly in shape: window old → new minutes, ban length old → new, "Any address with N failed logons within H hours will be banned for … Make sure your own addresses are whitelisted."
- **RDP flood (Warning):**
  - Condition: RdpCoreTS 131 `ClientIP` (log `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`) count ≥ 50, no Security 4624 from that IP, not banned. Skips the same addresses as above.
- **`BuildBanAll`:** distinct addresses of all `BanPermanently` actions on Warning attack findings, as one `BanAll` action. The confirmation lists the addresses.

- [ ] **Step 1: Write the failing tests** with rule `R` = active, `TriggerCount 5`, `EventAge 3600`, `LockTime 3600`, `EventPath {"Security"}`, boosters `{"4625","IpAddress"}`, regex `<Data Name=.IpAddress.>(\d*.\d*.\d*.\d*)` (the shipped rule). Times are UTC on 2026-11-20.
  - `SlowAttackerIsEvadingAndGetsSixHourWiden`:
    - Input: 5.175.140.23 at 18:36:28, 19:00:47, 19:25:03, 19:49:16, 20:13:36, 20:37:53, 21:04:53, 21:31:15, 21:56:51, 22:21:43, 22:46:24, 23:11:02, 23:35:24, 23:59:48, and 00:24:20 the next day.
    - Expect one Warning with `Address == "5.175.140.23"`.
    - Expect a `WidenRuleWindow` action with `NewEventAgeSeconds == 21600` and `NewLockTimeSeconds == 21600`.
    - Expect a `BanPermanently` action.
  - `WidenKeepsLongerLockTime`: same input with `LockTime 86400`. Expect `NewLockTimeSeconds == 86400`.
  - `BannedBurstAttackerHasNoFinding`: 37.98.153.123 with 5 attempts within 3 minutes, listed in `TemporarilyBanned`. Expect no finding.
  - `HeavyUnbannedAttackerIsWarning`: 25 attempts within 1 minute from 88.214.25.121, not banned. Expect a Warning with only a `BanPermanently` action.
  - `WhitelistedAndPrivateGetNothing`: 30 attempts each from 192.168.1.50 (whitelist `192.168.*`) and 10.1.1.1. Expect no findings.
  - `IgnoresMissingAndLocalAddresses`: 30 events each with `IpAddress` `-`, `::1` and `127.0.0.1`. Expect no findings.
  - `ParsesClientIpWithPort`: 60 RdpCoreTS 131 events from `203.0.113.9:51234`. Expect a Warning (flood) for `203.0.113.9`.
  - `BanAllListsDistinctAddresses`: two evading IPs plus one heavy IP. Expect `BanAll.Addresses.Count == 3`.
  - `InactiveRuleIsIgnored`: the slow-attacker input with `Active = false`. Expect no findings.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Run: `dotnet test ... --filter "FullyQualifiedName~AttackChecks"`
  - Expected: FAIL.
- [ ] **Step 3: Implement `AttackChecks`.**
- [ ] **Step 4: Run the full console suite.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Analyzer: attack checks".

### Task 3: Security-change checks (group 2)

**Files:**
- Create: `Analysis/SecurityChecks.cs`
- Test: `Analysis/SecurityChecksTests.cs`

**Interfaces:**
- Produces: `static class SecurityChecks { static IList<Finding> Run(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input); static readonly int[] SecurityEventIds; static readonly int[] SystemEventIds; }`
- `SecurityEventIds = { 4624, 4625, 4740, 1102, 4720, 4728, 4732, 4756, 4698 }`; `SystemEventIds = { 7045 }`.

**Checks** (per the spec table, matching on provider and ID):

| Check | Severity | Action / details |
|---|---|---|
| Logon after failures: 4624 with `LogonType` 3 or 10 from an IP with ≥ 3 earlier 4625s (by `IpAddress`) in the range | Critical when the IP is public (not whitelisted, local or private) **and** the 4624 `TargetUserName` equals (ignoring case) one that failed from that IP. Otherwise Warning | One finding per (IP, account). `BanPermanently` only when public and not whitelisted. Its confirmation warns: "This may be a real user who mistyped their password." |
| 1102 (provider `Microsoft-Windows-Eventlog`) | Critical | Details name `SubjectUserName` |
| 7045 (`Service Control Manager`, System log) | Warning | Details give `ServiceName` and `ImagePath` |
| 4732 / 4728 / 4756 where `TargetUserName` is `Administrators`, `Remote Desktop Users`, `Domain Admins` or `Enterprise Admins` | Warning | Other groups are ignored |
| 4720 | Warning | |
| 4740, grouped by `TargetUserName` | Warning when count ≥ 3, else Info | Details list the IPs that have 4625 failures for that account. No action |
| 4698 | Info | |

- [ ] **Step 1: Write the failing tests:**
  - `LogonAfterFailuresFromPublicIpSameAccountIsCritical`: 5 × 4625 from 5.175.140.23 for `administrator`, then 4624 type 3 for `Administrator`. Expect Critical with a `BanPermanently` action.
  - `LogonAfterFailuresDifferentAccountIsWarning`.
  - `LogonAfterFailuresFromPrivateIpIsWarningWithoutBan`: 192.168.1.20.
  - `TwoFailuresThenLogonIsNotReported`.
  - `LogClearedIsCritical`.
  - `ServiceInstalledIsWarning`.
  - `AdminGroupAddIsWarningOtherGroupIgnored`.
  - `LockoutsGroupedAndListCallerIps`: 3 × 4740 for `administrator` plus 4625s from 2 IPs. Expect one Warning whose `Details` contain both IPs and that has no actions.
  - `SingleLockoutIsInfo`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement `SecurityChecks`.**
- [ ] **Step 4: Run the full suite.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Analyzer: security-change checks".

### Task 4: Server-health checks (group 3)

**Files:**
- Create: `Analysis/HealthChecks.cs`
- Test: `Analysis/HealthChecksTests.cs`

**Interfaces:**
- Produces: `static class HealthChecks { static IList<Finding> Run(IReadOnlyDictionary<string, IList<AnalyzedEvent>> eventsByLog, AnalyzerInput input); static readonly int[] SystemEventIds; static readonly int[] ApplicationEventIds; static readonly int[] SecurityEventIds; }`
- `SystemEventIds = { 7, 11, 51, 153, 55, 98, 1001, 41, 6008, 2004, 2013, 7031, 7034, 20 }`; `ApplicationEventIds = { 1000, 1002, 833, 701 }`; `SecurityEventIds = { 1104 }`.

**Checks.** Providers are matched case-insensitively. A finding is only produced when both the provider and the ID match:

| Provider(s) | IDs | Severity | Grouped by | Advice |
|---|---|---|---|---|
| `disk` | 7, 11, 51, 153 | Critical | provider | "Back up now and check the disk; these errors often come before a disk fails." |
| `Ntfs` or `Microsoft-Windows-Ntfs` | 55, 98 | Critical | provider | "Run chkdsk on the volume during a maintenance window." |
| `Microsoft-Windows-WER-SystemErrorReporting` or `BugCheck` | 1001 | Critical | — | "The server crashed (blue screen). Check drivers and recent updates." |
| `Microsoft-Windows-Kernel-Power` 41, `EventLog` 6008 | 41, 6008 | Warning | — | "Find out why the server restarted: power, crash or someone holding the power button." |
| `Microsoft-Windows-Resource-Exhaustion-Detector` | 2004 | Warning | — | "Memory ran low. Check which programs use most memory, or add RAM." |
| `srv` | 2013 | Warning | — | "A disk is almost full. Free space or extend the volume." |
| `Microsoft-Windows-Eventlog` | 1104 (Security log) | Critical | — | "The Security log is full and has stopped recording, so EvlWatcher can't see attacks. Set it to overwrite old events or archive it." |
| `Service Control Manager` | 7031, 7034 | Warning if ≥ 2 for one service, else Info | `param1` | |
| `Application Error` 1000, `Application Hang` 1002 | 1000, 1002 | Warning if ≥ 3 for one app, else Info | `AppName` or `#1` | |
| `MSSQLSERVER` or `MSSQL$*` | 833, 701 | Warning | — | |
| `Microsoft-Windows-WindowsUpdateClient` | 20 | Info | — | |

Write short advice in the same tone for the rows without one.

- [ ] **Step 1: Write the failing tests:**
  - `DiskErrorIsCritical`.
  - `UnexpectedRestartIsWarning`.
  - `TwoCrashesOfOneServiceIsWarningOneIsInfo`.
  - `SingleAppCrashIsInfo`.
  - `SameIdOtherProviderIsIgnored`: event ID 7 from provider `Foo` produces no finding.
  - `SecurityLogFullIsCritical`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement `HealthChecks`.**
- [ ] **Step 4: Run the full suite.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Analyzer: server-health checks".

### Task 5: Analyzer orchestration and the real event source

**Files:**
- Create: `Analysis/IEventSource.cs`, `Analysis/EventLogSource.cs`, `Analysis/Analyzer.cs`
- Test: `Analysis/AnalyzerTests.cs`, `Analysis/EventLogSourceTests.cs`

**Interfaces:**
- **`IEventSource`:**
  - `bool LogExists(string logName)`
  - `IEnumerable<AnalyzedEvent> Read(string logName, IReadOnlyCollection<int> eventIds /* null = all */, DateTime fromUtc, CancellationToken ct)`
  - Throws `UnauthorizedAccessException` when access is denied.
- **`EventLogSource : IEventSource`:**
  - XPath: `*[System[(EventID=a or EventID=b …) and TimeCreated[timediff(@SystemTime) <= N]]]`, where `N` is the milliseconds from `fromUtc` to now. Leave out the EventID clause when `eventIds` is null.
  - Reads with `EventLogReader`, using `PathType.LogName`.
  - Checks `ct` for every event.
  - `LogExists` uses `EventLogSession.GlobalSession.GetLogNames()`, case-insensitive.
- **`Analyzer`:**
  - Constructor: `Analyzer(IEventSource source)`.
  - Method: `AnalysisResult Analyze(AnalyzerInput input, IProgress<string> progress, CancellationToken ct)`.
  - Log plan:
    - Every log in an active rule's `EventPath`: read all events.
    - Security: `SecurityChecks.SecurityEventIds` ∪ `HealthChecks.SecurityEventIds`.
    - System: `SecurityChecks.SystemEventIds` ∪ `HealthChecks.SystemEventIds`.
    - Application: `HealthChecks.ApplicationEventIds`.
    - RdpCoreTS operational: `{131}`.
    - If a log is both a rule log and a fixed-ID log, read all events once.
  - Missing logs go to `LogsMissing`. An `UnauthorizedAccessException` adds the log to `LogsUnreadable`.
  - Progress text per log: `"Reading Security log…"`.
  - Runs the three check groups. When `input.Rules == null`, it skips `AttackChecks` and sets `Notice = "The EvlWatcher service isn't responding, so attacks couldn't be checked against your rules."`
  - Sorts by severity (descending), then `LastSeenUtc` (descending). Sets `BanAllAction = AttackChecks.BuildBanAll(...)`, `EventsRead` and `Duration`.
  - `OperationCanceledException` propagates.

- [ ] **Step 1: Write the failing tests:**
  - `AnalyzerTests` (fake `IEventSource` serving `EventSamples`):
    - `ReadsRuleLogsFullyAndOthersByIds`: assert the requested IDs per log.
    - `MissingLogIsListed`: MSSQL rule log absent.
    - `UnreadableLogIsListedNotThrown`.
    - `NoRulesSkipsAttacksWithNotice`.
    - `FindingsSortedCriticalFirst`.
    - `CancellationPropagates`.
  - `EventLogSourceTests` (real log, no admin needed):
    - `ApplicationLogExistsAndReads`: `LogExists("Application")`, then `Read("Application", null, now-1d, ct)` enumerates without throwing.
    - `UnknownLogDoesNotExist`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement `IEventSource`, `EventLogSource` and `Analyzer`.**
- [ ] **Step 4: Run the full suite.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Analyzer: orchestration and event log source".

### Task 6: Client, confirmation and view model

**Files:**
- Create: `Analysis/IAnalyzerClient.cs`, `Analysis/IConfirmer.cs`, `ViewModel/AnalyzerViewModel.cs`, `ViewModel/FindingViewModel.cs`, `View/MessageBoxConfirmer.cs`
- Modify: `Model/EvlWatcherModel.cs` (implement `IAnalyzerClient`)
- Test: `AnalyzerViewModelTests.cs`

**Interfaces:**
- **`IAnalyzerClient`:**
  - `IList<GenericIPBlockingTaskDTO> GetRules()`
  - `IList<string> GetWhiteListPatterns()`
  - `IList<string> GetTemporarilyBannedIPs()`
  - `IList<string> GetPermanentlyBannedIPs()`
  - `void BanPermanently(IList<string> addresses)` (one `SetPermanentBans` call)
  - `void SaveRule(GenericIPBlockingTaskDTO rule)` (calls `SaveRule(rule, false)`)
  - Failures throw `RuleClientException` with a readable message.
- **`IConfirmer`:** `bool Confirm(string title, string message)`. `MessageBoxConfirmer` shows a Yes/No dialog with a warning icon.
- **`AnalyzerViewModel : GuiObject`:**
  - Constructor: `AnalyzerViewModel(IAnalyzerClient client, IEventSource source, IConfirmer confirmer, Func<DateTime> utcNow, Func<ISet<string>> localAddresses)`.
  - Properties: `IList<AnalysisRange> Ranges`, `AnalysisRange SelectedRange` (default `Last24Hours`), `bool IsScanning`, `string ProgressText`, `string SummaryText`, `string NoticeText`, `string LogsText`, `ObservableCollection<FindingViewModel> Findings`, `bool HasScanned`.
  - Commands: `ICommand ScanCommand`, `ICommand CancelCommand`, `ICommand BanAllCommand`.
  - Method: `Task ScanAsync()`.
- **`FindingViewModel`:**
  - Wraps `Finding`.
  - Properties: `SeverityText`, `CategoryText`, `Title`, `Details`, `Advice`, `IList<ActionViewModel> Actions`, `bool IsDone`, `string Error`.
  - `ActionViewModel { string Label; ICommand Command; }`

**Scan behaviour:**
- Fetches service state first, with `GetRules` and the rest in try/catch. On failure, `Rules` is null, and the whitelist and bans are empty.
- Runs `new Analyzer(source).Analyze` on `Task.Run`, with a `CancellationTokenSource` and progress marshalled to `ProgressText`.
- Cancel sets `ProgressText = "Scan cancelled."` and keeps the previous findings.
- `SummaryText` example: `"2 critical · 4 warnings · 3 info — Last 24 hours, 1,612 events in 4 logs, 2.1 s"`.

**Action behaviour:**
- Shows `Confirm(Label, ConfirmationText)` and calls nothing on No.
- **BanPermanently / BanAll:** `client.BanPermanently(addresses)`, then marks every finding with one of those addresses Done.
- **WidenRuleWindow:** re-reads the rule by name with `GetRules()`, sets `EventAge` and `LockTime`, calls `SaveRule`, then marks the widen action Done on all findings of that rule.
- **On `RuleClientException`:** sets `Error` on the finding and leaves it not Done.

- [ ] **Step 1: Write the failing tests** (fake client, source and confirmer; `async Task` tests):
  - `DefaultRangeIs24Hours`.
  - `ScanFillsFindingsAndSummary`.
  - `CancelStopsScanAndShowsCancelled`: the source yields forever; call `CancelCommand` and await `ScanAsync` within 2 s. Expect `IsScanning == false` and `ProgressText == "Scan cancelled."`.
  - `ServiceDownStillShowsOtherGroups`: the client throws from `GetRules`. Expect `NoticeText` set and the health findings present.
  - `ActionNotRunWhenNotConfirmed`.
  - `BanAllSendsOneCall`.
  - `WidenUpdatesRuleWindowAndLockTime`: `SaveRule` receives `EventAge 21600` and `LockTime 21600`.
  - `FailedActionShowsErrorAndStaysOpen`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement** the interfaces, the view models, `MessageBoxConfirmer`, and the `EvlWatcherModel` members, each through `Call(...)`.
- [ ] **Step 4: Run the full suite.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Analyzer: view model and service actions".

### Task 7: Analyzer tab UI

**Files:**
- Create: `View/AnalyzerView.xaml` (+ `.cs`)
- Modify: `View/MainWindow.xaml` (new TabItem after Rules, before Settings), `ViewModel/MainWindowViewModel.cs` (property `AnalyzerViewModel Analyzer`, created with `EvlWatcherModel`, `EventLogSource`, `MessageBoxConfirmer`, `() => DateTime.UtcNow` and `AddressClassifier.GetLocalAddresses`), `Themes/Icons.xaml` (`AnalyzeIcon`, a magnifier on the 16×16 grid)
- Test: `ThemeResourceTests.cs` (add `AnalyzeIcon` to `IconsAreGeometries`)

**Layout** (following the spec sketch):
- **Top row:** a range ComboBox bound to `Ranges` / `SelectedRange` showing `Label()`, an accent **Scan** button, `ProgressText`, and a **Cancel** button visible only while scanning.
- **Summary card:** `SummaryText`, `NoticeText`, and a **Ban all unbanned attackers** button bound to `BanAllCommand`. Hidden until `HasScanned`.
- **Findings:** a scrolling list of cards (`CardStyle`) with a severity pill (Critical uses `SystemFillColorCriticalBrush`; add `SystemFillColorCautionBrush #9A6700` to `Light.xaml` for Warning; Info uses `TextFillColorSecondaryBrush`), category, title (BodyStrong), details, advice (`HintTextStyle`), action buttons, a "Done" label when `IsDone`, and `Error` in `ErrorTextStyle`.
- **Footer:** `LogsText`.
- **Empty states:** before the first scan, "Click Scan to check the last 24 hours" (following the selected range). After a scan with no findings, "No risks found in the last 24 hours".

- [ ] **Step 1:** Add `"AnalyzeIcon"` to the key list in `IconsAreGeometries`.
  - Run: `dotnet test ... --filter ThemeResourceTests`
  - Expected: FAIL (missing icon).
- [ ] **Step 2:** Add the icon, the Caution brush, the view, the tab and the view-model wiring.
- [ ] **Step 3: Run the full suite.**
  - Expected: all pass, including `EveryReferencedKeyExists`, which now also covers `AnalyzerView.xaml`.
- [ ] **Step 4: Visual check.**
  - Extend the scratchpad `render.ps1` approach to select the Analyzer tab.
  - Render it before and after a scan of the real logs on this machine. Reading Security needs admin, so if the session isn't elevated, expect it in "couldn't read".
  - Expected: matches the sketch, cards readable, nothing clipped.
- [ ] **Step 5: Commit** with the message "Analyzer: tab UI".

### Task 8: Release 3.2.0 docs and version

**Files:**
- Version 3.2.0 in:
  - `Source/EvlWatcher/EvlWatcher/Properties/AssemblyInfo.cs`
  - `Source/EvlWatcher/EvlWatcher.WCF/Properties/AssemblyInfo.cs`
  - `Source/EvlWatcherConsole/EvlWatcherConsole/Properties/AssemblyInfo.cs`
  - the `MainWindow.xaml` title
  - `make.nsi` `OutFile`
  - the `README.md` link
- `NEWS.md`: add an entry.
- `Versions/v3/EvlWatcher-v3.2.0 release notes.txt` (follow the 3.1.0 format).
- `Source/AGENTS.md`:
  - Console UI section: the Analyzer tab, logic in `Analysis/` with no WPF/WCF, thresholds in `AnalyzerThresholds`, the "widen also raises LockTime" rule and why.
  - Releasing section: bump the version in `EvlWatcher.WCF` too.

- [ ] **Step 1:** Make the edits.
  - Run: `git grep -n "3\.1\.0" -- Source README.md`
  - Expected: only history entries remain.
- [ ] **Step 2:** Rebuild both solutions (service with MSBuild, console with `dotnet`) and run the console tests.
  - Expected: 0 warnings, all pass, and all three binaries at 3.2.0.0.
- [ ] **Step 3:** Commit with the message "Release prep v3.2.0: docs and version".
- [ ] **Step 4:** Build the installer (makensis, per AGENTS.md), leave it unsigned, and report its SHA-256.
- [ ] **Step 5:** Run a whole-branch review with superpowers:requesting-code-review, then superpowers:finishing-a-development-branch.
