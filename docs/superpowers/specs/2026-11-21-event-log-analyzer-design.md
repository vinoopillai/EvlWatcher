# Event log analyzer tab

Date: 2026-11-21 · Target release: v3.2.0

## Intent

The maintainer has been exporting Security logs by hand and asking for an analysis: which attackers got
banned, which slipped through (slow attackers that stay under a rule's window), what to change. The
**Analyzer** tab does that inside the console: it scans the server's event logs for the last 24 hours
(default), 7 days or 30 days, lists the risks it finds in plain language, and offers a one-click fix where
there is one. It also flags security changes and server-health problems that can slow or break the server.

## Goals

- New console tab **Analyzer** with a range picker (Last 24 hours · Last 7 days · Last 30 days) and a
  **Scan** button. The scan runs in the background with progress and **Cancel**; the console stays usable.
- Three groups of findings (all three in v1):
  1. **Attacks** (per IP, bannable) — with one-click actions.
  2. **Security changes / possible break-in** — alerts with advice.
  3. **Server health** (things that slow or degrade the server) — alerts with advice.
- Every finding: severity (Critical / Warning / Info), a plain-language title, what was seen (counts,
  first/last time, accounts, sample event IDs), and what to do.
- Group 1 actions run **only after a confirmation** that states exactly what will change
  (e.g. "Add 5.175.140.23 to the permanent ban list", "Change rule BlockRDPBrutersBySecurity4625:
  window 60 → 1440 minutes").
- Works with no service change: reading logs happens in the console (it already runs elevated on the
  server); actions use the existing WCF operations (`SetPermanentBan(s)`, `SaveRule`, `GetRules`,
  `GetWhiteListEntries`, `GetTemporarilyBannedIPs`, `GetPermanentlyBannedIPs`).

## Non-goals

- Live performance monitoring (CPU / RAM / disk counters, busiest processes, open connections) —
  Resource Monitor / Performance Monitor do that.
- Scanning other machines, scheduled scans, e-mail alerts, exporting a report.
- Changing the service, the WCF contract or the shipped rules.
- Automatic actions without a click and a confirmation.

## Anti-goals

- An action that bans a whitelisted address or the local machine (127.0.0.1, ::1, 0.0.0.0, own
  addresses): such findings show advice only, no ban button.
- A scan that freezes the console or can't be stopped.
- Noise: routine events (DCOM 10016, single app crashes, Windows Update info) must not bury real risks.
  Thresholds below keep one-off events at Info or out of the list.
- Wrong "Critical" for normal admin work. Critical is reserved for the cases marked Critical below.

## Constraints

- Console is .NET Framework 4.7.2 / C# 7.3, own light theme, vector icons (see AGENTS.md "Console UI").
- Logs are read with `System.Diagnostics.Eventing.Reader.EventLogReader`. Group 2 and 3 queries use an
  XPath filter on EventID and `TimeCreated[timediff(@SystemTime) <= N]`, so only matching events are read.
- Group 1 must judge attacks **the way the service does**: an event belongs to a rule when all its booster
  words are in the event XML and its regex yields an IP (`RuleBuilder.Match` already mirrors this). It
  therefore reads every event of each active rule's `EventPath` logs within the range (time-filtered XPath),
  once per log.
- Logs that don't exist on the machine (e.g. no SQL Server, no OpenSSH) are skipped without an error;
  the result lists which logs were checked and which were missing.

## Approaches considered

1. **Console scans the logs locally (chosen).** Pure analysis class, unit-tested; actions via existing WCF
   calls. No service update; scan cost stays out of the service that does the banning. Limited to the
   local machine, which is already true for the whole console.
2. Service scans, console displays. Would allow a remote console later, but needs a contract change on both
   sides and a long-running WCF call (timeouts), and adds load to the banning service. Rejected.
3. Separate report tool / scheduled job. Outside the console the admin uses. Rejected.

## Design (decided)

### Screen

```
Analyzer
 [Last 24 hours ▾]  [ Scan ]   Reading Security log… 1,240 events            [ Cancel ]

 ⓘ 2 critical · 4 warnings · 3 info — Last 24 hours, 1,612 events in 4 logs, 2.1 s
   [ Ban all 6 unbanned attackers ]

 ┌ CRITICAL · Possible break-in ───────────────────────────────────────────────┐
 │ Successful logon from 5.175.140.23 after 15 failed attempts                 │
 │ Account "administrator", logon type 3 (network) at 20:41. Check the account,│
 │ change its password, review what it did.            [ Ban permanently ]     │
 └─────────────────────────────────────────────────────────────────────────────┘
 ┌ WARNING · Attack not banned ────────────────────────────────────────────────┐
 │ 5.175.140.23 tried 15 times in 6 h (every ~24 min) — too slow for rule       │
 │ BlockRDPBrutersBySecurity4625 (5 within 60 min).                             │
 │ [ Ban permanently ]  [ Widen rule window to 6 hours ]                        │
 └─────────────────────────────────────────────────────────────────────────────┘
 ...
 Logs checked: Security, System, Application, RdpCoreTS/Operational · Not on this server: MSSQL, OpenSSH
```

- Findings sorted Critical → Warning → Info, then newest first. Each card shows the category, title,
  details, advice and its action buttons. A finding whose action ran shows "Done" and disables its buttons.
- Empty states: "No risks found in the last 24 hours" (with counts of what was checked); "Click Scan to
  check the last 24 hours" before the first scan.
- Tab position: after **Rules**, before **Settings**. Icon: a new `AnalyzeIcon` (magnifier) in
  `Themes/Icons.xaml`.

### Checks

Thresholds are constants in one place (`AnalyzerThresholds`), so they can be tuned later.

**Group 1 — Attacks (per IP).** For every active rule (from `GetRules()`), match events in its logs as the
service does and count, per IP, every attempt with its time. Skip whitelisted IPs and local addresses.

| Check | Condition | Severity | Actions |
|---|---|---|---|
| Evading the rule window | IP has ≥ rule.TriggerCount attempts in the range, is **not** currently banned (temp or permanent), and never had TriggerCount attempts inside one EventAge window | Warning | Ban permanently; **Widen rule window** (see below) |
| Heavy attacker not banned | IP not currently banned and ≥ 20 attempts in the range (any pattern) | Warning | Ban permanently |
| RDP connection flood | RdpCoreTS 131 connections from an IP ≥ 50 in the range with no successful logon from it | Warning | Ban permanently |

**Widen rule window** *(calls settled after review)*: offered per rule, once, on that rule's evading findings.
- New window = the smallest of 1 h / 6 h / 24 h that would have caught **every** evading IP of that rule in
  the range; only offered if larger than the rule's current window. **Capped at 24 h** (no 7-day option):
  the service re-reads the whole window every scan, and a longer window costs more each cycle.
- The action also raises **LockTime to at least the new window**. Otherwise the service re-bans the same IP
  as soon as the ban lifts (its old failures are still inside the window), and 3 such re-bans make it
  permanent within hours.
- The confirmation states all of it, for example: "Rule BlockRDPBrutersBySecurity4625: window 60 → 360
  minutes, ban length 60 → 360 minutes. Any address with 5 failed logons within 6 hours will be banned for
  6 hours. Make sure your own addresses are whitelisted."
- Example from the 6-hour log in this conversation: 5.175.140.23 (every ~24 min) needs about 98 minutes for
  5 attempts, so the action offers **6 hours**.

*"Banned, still active" was dropped:* the console only sees current temp bans, not past bans or strike
counts, so it can't be computed reliably.

Summary button **"Ban all N unbanned attackers"** bans every IP from the Warning attack findings in one
`SetPermanentBans` call after one confirmation listing them.

**Group 2 — Security changes / possible break-in** (Security log unless noted).

| Check | Events | Severity | Advice / action |
|---|---|---|---|
| Logon after failures | 4624 with LogonType 3 or 10 from an IP that has ≥ 3 failed logons (raw Security 4625 with that IpAddress, regardless of rules) earlier in the range. **Critical** when the IP is public (not whitelisted, not loopback, not private 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10) **and** the successful logon is for an account that also failed from that IP. Otherwise **Warning** (private address, or a different account) | Critical / Warning | Check the account, change its password; action: Ban permanently, public IPs only (confirmation warns it may be a real user) |
| Security log cleared | 1102 | Critical | Find out who cleared it (account in the event) |
| New service installed | System 7045 | Warning | Verify the service name and path are expected |
| Account added to a privileged group | 4732 / 4728 / 4756 where the group is Administrators, Remote Desktop Users, Domain Admins | Warning | Verify the change was intended |
| New user account | 4720 | Warning | Verify the account was intended |
| Account locked out | 4740 | Warning (Info if 1–2) | Grouped by account; advice only (4740 has no source IP). The details list the IPs with failed 4625 logons for that account in the range, so the admin can see who caused it; consider renaming Administrator |
| Scheduled task created | 4698 | Info | Verify the task |

Audit events that the server doesn't log (auditing off) simply produce nothing.

**Group 3 — Server health** (System / Application unless noted; grouped by source and object).

| Check | Events | Severity |
|---|---|---|
| Disk / file-system errors | disk 7, 11, 51, 153; Ntfs 55, 98 | Critical |
| Blue screen | BugCheck 1001 | Critical |
| Unexpected restart | Kernel-Power 41; EventLog 6008 | Warning |
| Low memory | Resource-Exhaustion-Detector 2004 | Warning |
| Low disk space | srv 2013 | Warning |
| Security log full / not recording | EventLog 1104 (Security) | Critical — EvlWatcher can't see attacks |
| Services crashing | Service Control Manager 7031 / 7034, grouped by service | Warning if ≥ 2 for one service, else Info |
| Apps crashing or hanging | Application Error 1000, Application Hang 1002, grouped by app | Warning if ≥ 3 for one app, else Info |
| SQL Server slow disk / memory pressure | MSSQLSERVER/MSSQL$* 833, 701 | Warning |
| Windows Update failing | WindowsUpdateClient 20 | Info |

Each has fixed plain-language advice (e.g. disk errors: "Back up now and check the disk; these errors often
come before a disk fails.").

### Code structure (console)

- `EvlWatcherConsole/Analysis/` — pure, no WPF/WCF:
  - `AnalyzedEvent` (log name, provider, event ID, time, XML, plus parsed data fields when needed).
  - `IEventSource` — `IEnumerable<AnalyzedEvent> Read(string logName, int[] eventIds /* null = all */,
    DateTime fromUtc, CancellationToken)`; plus `bool LogExists(string logName)`.
  - `AnalyzerInput` — events by log, active rules, whitelist patterns, temp/perm banned IPs, local addresses,
    range.
  - `Analyzer.Analyze(AnalyzerInput) → AnalysisResult` (findings + logs checked/missing + counts).
  - `Finding` (severity, category, title, details, advice, IP / account / service, `FindingAction[]`).
  - `FindingAction` (kind: BanPermanently / BanAll / WidenRuleWindow; parameters; confirmation text).
  - `AnalyzerThresholds`.
- `EvlWatcherConsole/Analysis/EventLogSource.cs` — the real `IEventSource` (EventLogReader + XPath).
- `ViewModel/AnalyzerViewModel.cs` — range, Scan/Cancel commands, progress text, findings list, running
  actions through an `IAnalyzerClient` (ban, ban all, save rule, get rules/whitelist/bans) implemented by
  `EvlWatcherModel` (same pattern as `IRuleClient`; every call through `Call(...)`).
- `View/AnalyzerView.xaml` (UserControl), hosted in a new TabItem in `MainWindow.xaml`.
- Whitelist matching reuses the service's wildcard semantics (`192.168.*`); the console gets a small copy of
  that converter in `Analysis/` (the service's lives in `converter/`) with tests.

### Tests (`EvlWatcherConsole.Tests`)

- `AnalyzerTests` with event samples: 4625 sequences taken from the Security logs the maintainer shared in
  this conversation (the implementer writes them into `Samples/`; the attacker IPs stay, **the server and
  domain names are replaced** by `SERVER01` / `CORP`), and synthetic events modelled on the real Windows
  schemas for the rest (4624, 4740, 1102, 7045, 7031/7034, 1000/1002, disk/Ntfs, RdpCoreTS 131). Covering:
  evading attacker (the 24-min one) → Warning + widen-to-6h action that also raises the ban length; burst attacker already banned → no finding; whitelisted IP → no finding; local
  address → no ban action; logon-after-failures → Critical; 1102 → Critical; grouped service crashes;
  single app crash → Info; missing log → listed as missing, no error.
- `AnalyzerViewModelTests` with a fake source and client: default range 24 h; Cancel stops and keeps the UI
  usable; an action asks for confirmation and calls the client only on "yes"; "Ban all" sends one call.

### Release

Version 3.2.0 (AssemblyInfo ×3, window title, `make.nsi`, README), NEWS, release notes, AGENTS.md
(Analyzer section: where checks live, thresholds, "logic in Analysis/, no WPF/WCF").

## Left to the builder

- Exact card layout and wording polish, within the theme.
- XPath construction details and batching; how progress is reported (per log / per N events).
- Rounding of "every ~N minutes" and other display formats.
