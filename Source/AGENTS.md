# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

EvlWatcher is a "fail2ban for Windows". A Windows Service reads the Windows Event Log, uses regex rules to pull attacker IPs out of failed-login events, and bans them by updating one Windows Firewall rule named `EvlWatcher`. A WPF management console talks to the service over WCF named pipes.

> The upstream project is **discontinued** (see `../README.md`). Treat this as maintenance work on legacy code: keep changes small and stay compatible with what already exists.

## Layout

There are two separate Visual Studio solutions under `Source/`:

```
Source/
├── EvlWatcher/EvlWatcher.sln                 # service solution
│   ├── EvlWatcher/                           # Windows Service (Exe, .NET Framework 4.7.2)
│   │   ├── EvlWatcher.cs                     # ServiceBase + IEvlWatcherService impl, main scan loop, Main()
│   │   ├── Installer.cs                      # ServiceInstaller (LocalSystem, auto start)
│   │   ├── Config/                           # IPersistent*Configuration + XML-backed implementations
│   │   ├── tasks/                            # LogTask -> IPBlockingLogTask -> GenericIPBlockingTask, factory
│   │   ├── systemapi/FirewallAPI.cs          # COM wrapper over HNetCfg FwPolicy2 (NetFwTypeLib)
│   │   ├── Logging/                          # ILogger, DefaultLogger (EventLog + in-memory console history)
│   │   ├── converter/, comparer/, DTOs/      # helpers (wildcard->regex, IP sorting, event records)
│   │   ├── config.xml                        # shipped default rules + global settings
│   │   └── NSIS/make.nsi                     # installer script
│   ├── EvlWatcher.WCF/                       # shared WCF contract (IEvlWatcherService) + DTOs, net472 library
│   └── EvlWatcher.Tests.Integration/         # MSTest, net10.0, x86 — real firewall integration tests
└── EvlWatcherConsole/EvlWatcherConsole.sln   # WPF admin GUI (WinExe, SDK-style, net472, MVVM)
    └── EvlWatcherConsole/
        ├── Model/EvlWatcherModel.cs          # WCF client (ChannelFactory per call)
        ├── ViewModel/MainWindowViewModel.cs
        ├── View/MainWindow.xaml
        └── MVVMBase/                         # GuiObject (INotifyPropertyChanged), RelayCommand
```

Folder names on disk are lowercase (`tasks`, `systemapi`, `converter`, `comparer`), but the `.csproj` uses PascalCase (`Tasks\...`). Windows doesn't care about case. Namespaces follow the PascalCase form (`EvlWatcher.Tasks`, `EvlWatcher.SystemAPI`).

## Architecture in brief

- **Startup** (`EvlWatcher.Main`): it builds `DefaultLogger`, `XmlServiceConfiguration` and `DefaultGenericTaskFactory` by hand (no DI container). If `Environment.UserInteractive` is true, it runs `OnStart` directly and sleeps instead of starting as a service. This is the debug path.
- **IPC**: the service hosts `IEvlWatcherService` at `net.pipe://localhost/EvlWatcher` (`NetNamedPipeBinding`, singleton instance = the service itself). The console connects to that same address. If you change the contract, rebuild **both** sides.
- **Always end client channels.** Every console call goes through `EvlWatcherModel.Call(...)`, which uses one shared `ChannelFactory` and `Close()`s each channel (or `Abort()`s it on failure). Never call `CreateChannel()` and walk away. Each open channel is a session on the service, WCF allows only **100 sessions per CPU core**, and an abandoned session lives for the 10-minute inactivity timeout. A leak made the service stop answering 1–2 minutes after the Rules tab opened (the console then showed it as not responding and the Rules tab stuck on "Loading").
- **One runtime on both sides of the pipe**: the service and the console both run on .NET Framework 4.7.2 (the console moved back from .NET 10 in v3.1 so it runs on older Windows). The console uses the framework's own `System.ServiceModel` and still compiles `IEvlWatcherService.cs` and `DTOs/*.cs` from `EvlWatcher.WCF` **from source**, so there is one contract definition and the two solutions stay independent. Keep the contract to primitives, strings, arrays and `[DataContract]` DTOs, so a future move of either side to modern .NET stays possible; that's why IPs cross the pipe as strings rather than `System.Net.IPAddress`.
- **Scan loop** (`EvlWatcher.Run`): it reloads `config.xml` and builds one task per `<Task>`. It groups tasks by `EventPath` so each log is read only once per cycle. Then every `CheckInterval` seconds it:
  1. Queries each log (`EventLogQuery`, reverse direction).
  2. Gives each task its events (all events in the time window, or only new ones when `OnlyNew` is set).
  3. Collects temp-ban and perma-ban victims and skips whitelisted IPs.
  4. Calls `FirewallAPI.AdjustIPBanList`.
- **Rule operations and live reload**: besides the global settings, the contract has `GetRules()` (all rules, including inactive ones, with `MissingEventLogs`), `SaveRule(rule, isNew)` (validated by `RuleValidator`; failures are a `ServiceFaultDTO` fault with `ServiceErorCode.invalidRule`) and `SetRuleActive(name, active)`. Each writes `config.xml` and calls `RequestReload()`, which sets `_reloadRequested` and signals the `_wakeWorker` AutoResetEvent that the worker waits on between cycles (never `Thread.Interrupt`). All `config.xml` writes go through `ConfigFile.Save` (temp file + replace), so a failed write can never truncate the live file. `Run()` then reloads the configuration and swaps the task set in place. **Ban state is carried over by rule name** (`CarryOverByName`, `GenericIPBlockingTask.CarryOverStateFrom`): temp bans, strike counts and forgotten IPs survive; a renamed or new rule starts empty. The reload path **never** calls `ClearIPBanList()` or touches permanent bans or the whitelist, only a service stop does. Keep it that way, and take `_syncObject` (or iterate a snapshot taken under it) for anything that touches `_logTasks`.
- **Rules** (`GenericIPBlockingTask`): it keeps only events that contain **all** `RegexBoosters` words (AND, not OR), then applies `Regex`. Capture group 1 is the IP. If an IP appears `TriggerCount` times within `EventAge` seconds, it gets a temp ban for `LockTime` seconds. After `PermaBanCount` temp bans the ban becomes permanent and goes into `<Banlist>`.
- **Country filter** (v3.3): a rule's optional `<AllowedCountries>IN,AE</AllowedCountries>` (DTO `AllowedCountries`; null from an older console = keep the current value) makes any address whose *registered* country is known and not listed get the rule's temp ban on its **first** matched event. Such a country-only ban **never adds a strike** (`_bannedCount`), so it can't become permanent on its own; addresses from allowed countries follow the normal rules. Unknown countries, private/loopback/own addresses and "country data not loaded" all fall back to the normal `TriggerCount`; the whitelist still wins. The data is the five internet registries' "delegated" files in `geo\` next to `config.xml` (`Geo\DelegatedFileParser`, `CountryDatabase`, `CountryDataService`): loaded at start, refreshed weekly **per registry** on a timer (a failing registry keeps its previous file; files under 1,000 ranges are rejected), never on the scan thread. `<CountryDataAutoUpdate>` in `<Global>` (default true) switches the refresh; the contract has `GetCountryDataStatus`, `UpdateCountryDataNow` and `SetCountryDataAutoUpdate`. Downloads need outbound HTTPS and force TLS 1.2. `EvlWatcher.Tests.Integration` has the country tests (no admin needed; `RealRegistryDataTests` runs only with `EVLWATCHER_GEO_DIR` set).
- **Firewall**: there is a single inbound block rule named `EvlWatcher`, covering all profiles and all protocols. IPv4 addresses are written as `a.b.c.d/255.255.255.255` and IPv6 addresses without a mask. The rule is **disabled** when no IPs are banned. That is expected behaviour, not a bug.
- **Persistence**: `config.xml` sits next to `EvlWatcher.exe`. Its path is found with `Assembly.Location.Replace("EvlWatcher.exe", "config.xml")`, so don't rename the assembly. Runtime changes (whitelist, banlist, log level, interval, backlog) are written back into `<Global>`.

## Building

The service and `EvlWatcher.WCF` are old-style (non-SDK) .NET Framework 4.7.2 projects. Build them with the **.NET Framework MSBuild** that ships with Visual Studio. `dotnet build` fails with `MSB4803` because `ResolveComReference` isn't supported, and that includes the test project, which references `EvlWatcher.csproj`. Build through the `.sln`: building `EvlWatcher.csproj` directly with `Platform=x86` fails, because `EvlWatcher.WCF` has no x86 configuration.

```powershell
# from a VS Developer PowerShell
msbuild Source\EvlWatcher\EvlWatcher.sln /p:Configuration=Release
dotnet build Source\EvlWatcherConsole\EvlWatcherConsole.sln -c Release   # console is SDK-style, targets net472
dotnet test  Source\EvlWatcherConsole\EvlWatcherConsole.Tests -c Release   # console unit tests, no admin needed
```

Things to know:
- The console no longer depends on `EvlWatcher.WCF.dll`, so the two solutions can be built in any order.
- `EvlWatcher.csproj` uses a COM reference to `NetFwTypeLib` (embedded interop types). It needs the Windows firewall type library, so it builds only on Windows.
- Platforms: the service defaults to `x86` (Release service is `AnyCPU`); the console is `AnyCPU`, so it runs on 32- and 64-bit Windows. The integration test project is `x86` and references the service exe directly.
- Every new `.cs` file must be added to its `.csproj` `<Compile Include=...>` list by hand, because these legacy projects don't use globbing.

## Testing

Run them from Visual Studio Test Explorer (VS started as admin). Without full VS, mix the two toolchains: build the service with .NET Framework MSBuild, then let `dotnet` build only the test project.

```powershell
# elevated shell
msbuild Source\EvlWatcher\EvlWatcher.sln -t:EvlWatcher -p:Configuration=Release "-p:Platform=Mixed Platforms"
dotnet build Source\EvlWatcher\EvlWatcher.Tests.Integration -c Release -p:BuildProjectReferences=false
dotnet test  Source\EvlWatcher\EvlWatcher.Tests.Integration -c Release --no-build
```

The test host is x86, so it needs the **x86** .NET 10 runtime. Without admin rights, every test fails with `E_ACCESSDENIED`.

- The tests in `FirewallApiTests` change the **real** Windows Firewall rule `EvlWatcher`. Run them **elevated** (as admin), and only on a dev machine or VM. They overwrite the rule's remote address list.
- Service tests run in `EvlWatcher.Tests.Integration`: the country-filter tests need no admin; only `FirewallApiTests` change the real firewall (exclude them with `--filter "FullyQualifiedName!~FirewallApiTests"`). Keep pure logic (regex matching, wildcard whitelist, ban counting, country lookup) separate from `EventLog` and COM so it stays testable.

## Running / debugging

- **As a console process**: run `EvlWatcher.exe` from an **elevated** terminal or debugger. Because the session is interactive, it takes the debug path in `Main`. Reading the Security log, creating the named pipe and editing the firewall all need admin rights.
- **As a service**: install it with `installutil EvlWatcher.exe` or the NSIS installer. It runs as LocalSystem with automatic start.
- Start `EvlWatcherConsole.exe` (its manifest requests elevation) once the service is running.
- Logs go to the Windows Event Log at the level set in `<LogLevel>`. They are also kept in memory up to `<ConsoleBacklog>` lines for the console's Live tab.

## Changing detection rules (`config.xml`)

Most changes people contribute are rule changes. Each `<Task Name="..." Active="true|false">` contains:
`Description`, `LockTime` (s), `OnlyNew`, `EventAge` (s), `TriggerCount`, `PermaBanCount`, `EventPath` (comma-separated log names), `RegexBoosters/Booster`*, and `Regex`.

- The regex runs against the event's **XML** representation. Capture group 1 must be the IP.
- Escape `<`/`>` as `&lt;`/`&gt;` inside the XML. Existing rules use `.` instead of a literal `"` around attribute values (for example `Data Name=.IpAddress.`).
- Always add at least one booster, since running the regex on every event is too expensive.
- Test new regexes with sample event XML in the console's **Advanced** tab.
- `<WhiteList>` takes `;`-separated wildcard patterns (`192.168.*`). `<Banlist>` takes `;`-separated IPs. A whitelist entry must not contain `;`.

## Console UI

- The console uses **its own light theme**, `Themes/Light.xaml`, merged in `App.xaml`. It looks the same on every Windows version; there is no dark mode. It defines the brushes (under Fluent-style names such as `TextFillColorSecondaryBrush`, `CardBackgroundFillColorDefaultBrush`, `AccentFillColorDefaultBrush`), `BodyStrongTextBlockStyle`, `CaptionTextBlockStyle`, `AccentButtonStyle` and implicit styles with templates for every control in use. App-level styles (`CardStyle`, `IconButtonStyle`, `HintTextStyle` and so on) live in `App.xaml`. Don't bring back `PresentationFramework.Fluent`: it needs .NET 9+.
- Use theme brushes through `DynamicResource`. Don't hard-code colours in views.
- If you add a control type the theme doesn't style yet, add an implicit style for it in `Themes/Light.xaml`; otherwise it shows the classic Windows look. Inline styles set `BasedOn="{StaticResource {x:Type Button}}"` (or whatever the control type is).
- Icons are vector outlines in `Themes/Icons.xaml` (`AddIcon`, `CancelIcon`, `LockIcon`, `UnlockIcon`, `SettingsIcon`, `PlayIcon`, ... on a 16×16 grid, stroked). Use them as `<Path Style="{StaticResource IconPathStyle}" Data="{StaticResource AddIcon}"/>` or `<Button Style="{StaticResource IconButtonStyle}" Tag="{StaticResource AddIcon}"/>`. The stroke follows the parent control's `Foreground`. **No icon fonts**: Windows 7 / 8.1 have neither Segoe MDL2 Assets nor Segoe Fluent Icons.
- `ThemeResourceTests` fail when a view references a resource the theme doesn't define, or when icon-font glyphs, `SymbolThemeFontFamily`, Fluent or Cascadia come back. Keep them green.
- Icon-only buttons need both a `ToolTip` and an `AutomationProperties.Name`.
- Tabs: Bans & Whitelist, Live, **Rules**, **Analyzer**, Settings and **Advanced** (the old Rule Tester, unchanged). The Rules tab (`RulesView`, `RulesViewModel`, `RuleEditorViewModel`) lists rules from `GetRules()` and edits them in plain language: minutes in the UI, seconds in the DTO. It talks to the service through `IRuleClient`, so view models stay testable. The periodic refresh is skipped while `RulesViewModel.IsBusyEditing` (unsaved edits or the wizard is open).
- The **Analyzer** tab (`AnalyzerView`, `AnalyzerViewModel`, `FindingViewModel`) scans this machine's event logs for the last 24 hours / 7 days / 30 days and lists findings in three groups: attacks (per IP, with Ban / Widen-rule-window / Ban-all actions), security changes (possible break-in, log cleared, new service/user/admin, lockouts) and server health (disk, crashes, restarts, low memory/disk, full Security log). Rules for it:
  - **All logic lives in `EvlWatcherConsole/Analysis/`** (`Analyzer`, `AttackChecks`, `SecurityChecks`, `HealthChecks`, `AddressClassifier`): pure, no WPF or WCF, unit-tested with `EventSamples` in `EvlWatcherConsole.Tests/Analysis`. Thresholds are in `AnalyzerThresholds`.
  - Attack checks match events exactly like the service (`RuleBuilder.Match`), reading each rule's logs in full for the range; other logs are read by event ID with an XPath time filter (`EventLogSource`).
  - Health checks match **provider and ID** and ignore Information/Verbose events: IDs are shared (Ntfs 98 is also "Volume is healthy").
  - Actions run only after an `IConfirmer` Yes and go through `IAnalyzerClient` (implemented by `EvlWatcherModel`, every call via `Call(...)`). **Widening a rule window also raises `LockTime` to at least the new window**: the service re-reads the whole window every cycle, so a shorter ban would re-ban the same IP as soon as it lifts and reach `PermaBanCount` within hours. Widening is capped at 24 h.
  - No ban is ever offered for whitelisted, local or private addresses.
- The **Bans & Whitelist** tab has one search box (`IpListSearch`) that filters all three lists through their default `CollectionView`s; the count badges and every command (including "Ban all permanently") still use the full lists. The **status bar** shows the service's latest Info-or-higher log entry and the IP country data's age (`StatusBarText`, pure and unit-tested; refreshed every 5 s / 5 min on every tab).
- **Country option** on each rule (`RuleEditorViewModel.RestrictCountries` / `AllowedCountriesText`, names via `Rules\CountryCodes` → `RegionInfo`), hidden in the wizard; the Settings tab has the **Country data** card (`CountryDataViewModel`: status, weekly update toggle, Update now).
- The **new-rule wizard** (`NewRuleWizardViewModel`, `NewRuleWizardView`) opens in place of the details pane: paste event XML, pick the IP, review and save. Step 3 reuses `RuleEditorViewModel` with `isNew: true`; the UI only exposes the wizard's `SaveCommand`, which stays disabled until the self-test passes.
- **Event-parsing logic belongs in `EvlWatcherConsole/Rules/RuleBuilder.cs`** (parse, IP candidates, rule generation, self-test, covering-rule check). It is pure (no WPF or WCF) and unit-tested in `EvlWatcherConsole.Tests` with real event samples. Don't put it in view models. Remember that a rule's booster words are **AND**ed: an event must contain all of them before the regex runs.

## Code conventions

- C# 7.x-era style: `#region` blocks (`private members`, `public properties`, `public operations` and so on), `_camelCase` private fields, PascalCase members, and block-scoped `namespace X { }` (not file-scoped `namespace X;`, which needs C# 10, newer than these net472 projects use by default).
- Shared state is guarded by `lock (_syncObject)`. The WCF service and the worker thread run at the same time, so take the existing lock whenever you touch ban lists, config or tasks.
- Log through `ILogger.Dump(message, SeverityLevel)` or `Dump(Exception)`. Don't use `Console.WriteLine`.
- WCF operations are marked `[FaultContract(typeof(ServiceFaultDTO))]`. New operations should follow that pattern, and new DTOs go in `EvlWatcher.WCF/DTOs` as `[DataContract]` types.
- Keep `EvlWatcher.WCF` free of service internals. Both executables reference it.

## Releasing

- Bump the version in `Properties/AssemblyInfo.cs` (service, `EvlWatcher.WCF` and console), in the console window title (`MainWindow.xaml`), in `OutFile` in `NSIS/make.nsi`, and in the README download link.
- `make.nsi` expects `EvlWatcher.exe`, `EvlWatcher.WCF.dll`, `config.xml` and `license.txt` from the service's `bin\Release`, `EvlWatcher.ico` (from `EvlWatcher\resources\`), plus `EvlWatcherConsole.exe` and `EvlWatcherConsole.exe.config` from the console's `bin\Release\net472\`, and a `geo\` folder with the registries' country data (run `fetch-geo.ps1` there first), all in its working directory. The header comment in the script has the details. Compile it with NSIS 3.x (a portable zip works, no admin needed). Put `nsSCM.dll` from https://nsis.sourceforge.io/NsSCM_plug-in in `<NSIS>\Plugins\x86-ansi`, because the script sets `Unicode false` (nsSCM is ANSI-only). Then run `makensis make.nsi`. Installers and release notes go to `../Versions/v<major>/` (v3 for 3.x). Earlier releases were Authenticode-signed; sign the setup.exe before publishing.
- Signing (no `signtool` needed). Use a code-signing cert from the Windows store, or `Get-PfxCertificate <file.pfx>`, then:
  ```powershell
  $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
  Set-AuthenticodeSignature ..\Versions\v3\EvlWatcher-v3.3.0-setup.exe -Certificate $cert `
      -HashAlgorithm SHA256 -TimestampServer http://timestamp.digicert.com
  Get-AuthenticodeSignature ..\Versions\v3\EvlWatcher-v3.3.0-setup.exe   # Status should be Valid
  ```
  The timestamp keeps the signature valid after the certificate expires. Sign the final setup.exe only: signing changes its hash, so publish the hash after signing.
- The console for the installer is the normal `dotnet build -c Release` output (`bin\Release\net472\`: exe plus `.exe.config`, AnyCPU). Service and console need **.NET Framework 4.7.2**; the installer checks `NDP\v4\Full\Release >= 461808`, and if it's missing it warns (mentioning KB4019990 for Server 2012 / Windows 7) and offers the download page but still installs, because silent `/S` rollouts must not stop there.
- On upgrade the installer **keeps the existing `config.xml`** and writes this version's defaults next to it as `config.default.xml`. New rules shipped in `config.xml` therefore only reach fresh installs automatically; mention them in the release notes.
- Deployment targets: Windows 8.1 / Server 2012 and later (32- or 64-bit) **with Desktop Experience**. WPF doesn't run on Server Core, so manage those machines from elsewhere or by editing `config.xml`. Windows 7 SP1 / Server 2008 R2 SP1 should work (nothing in the build excludes them) but are only announced once tested on a VM; their release notes must then mention KB4474419 (SHA-2 code signing), because the installer is signed with SHA-256 only.
- Upstream workflow (`../CONTRIBUTING.md`): open PRs against the next-version branch (for example `v2.1.x`), never `master`.

## Known quirks (don't "fix" by accident without intent)

- `XmlServiceConfiguration` reloads tasks on `Load()`, but `Run()` only builds workers once at startup. Rule changes need a service restart.
- `README.md` says the scan runs "every 30 seconds". That's only the default `CheckInterval`; the actual interval comes from config.

## Safety

This software edits firewall rules and runs as SYSTEM. Don't run it, or its integration tests, against a machine you depend on for remote access unless the whitelist covers your own IP. A bad regex that matches your own address can lock you out of RDP.
