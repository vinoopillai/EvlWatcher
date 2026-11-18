# Rules Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rules tab in EvlWatcherConsole. It lets a non-expert turn rules on or off, tune them in plain language, and add new rules by pasting an event. The running service picks changes up without a restart.

**Architecture:** Three new WCF operations (`GetRules`, `SaveRule`, `SetRuleActive`). The service validates in pure, unit-tested classes, persists through the existing XML config classes, and reloads its rules in-process, carrying each rule's ban state over by name. The console gets a pure, unit-tested `RuleBuilder` for the paste-an-event wizard, plus two view-models behind a small client interface so they're testable without the service.

**Tech Stack:** Service: C# / .NET Framework 4.7.2 (non-SDK csproj, .NET Framework MSBuild), WCF `NetNamedPipeBinding`. Console: WPF on `net10.0-windows`, Fluent theme, `System.ServiceModel.NetNamedPipe`. Tests: MSTest 4.5.3 on `net10.0` / `net10.0-windows`.

**Spec:** `docs/superpowers/specs/2026-11-18-rules-panel-design.md` (read it alongside this plan).

## Global Constraints

- The source tree is **not a git repository**, so there are no commit steps. Instead, each task ends with its full build and test run passing.
- Service projects build with the .NET Framework MSBuild. On this machine that's `"/c/Program Files/Microsoft SQL Server Management Studio 22/Release/MSBuild/Current/Bin/MSBuild.exe"`, called `$MSB` below.
  - Build service: `cd Source/EvlWatcher && "$MSB" EvlWatcher.sln -t:EvlWatcher -p:Configuration=Release "-p:Platform=Mixed Platforms" -nologo -v:minimal`
  - Service unit tests: `dotnet build EvlWatcher.Tests -c Release -p:BuildProjectReferences=false && dotnet test EvlWatcher.Tests -c Release --no-build`. Always rebuild the service first.
  - Console and its tests: `cd Source/EvlWatcherConsole && dotnet test EvlWatcherConsole.Tests -c Release`
- **Contract types:** primitives, strings, arrays, `IList<>` and plain DTOs only. **Never** `IPAddress` or other framework types (AGENTS.md).
- **Service code style:** C# 7.3 (net472), `#region` blocks, `_camelCase` fields, `lock (_syncObject)` around shared state, and every new `.cs` file added to `EvlWatcher.csproj` `<Compile Include>`.
- **Validation limits** (verbatim from the spec):
  - `TriggerCount ≥ 1`, `EventAge ≥ 10` s, `LockTime ≥ 60` s.
  - `PermaBanCount ≥ 1` or negative (= never); `0` is rejected.
  - Name non-empty and ≤ 64 characters, unique on create, must exist on update, no renaming.
  - Regex compiles with exactly one capture group.
  - ≥ 1 event log; all must exist **only when `isNew`**.
  - ≥ 1 booster, none empty.
- **Wizard defaults:** 5 attempts / 2 minutes / 60 minutes / permanent after 3.
- **Generated rules:**
  - Event log = `<System><Channel>`.
  - Boosters = provider name **and** `>{EventID}</EventID>`.
  - Regex: for `<Data Name="X">` it's `<Data Name=.X.>([0-9A-Fa-f:.]+)</Data>`. Otherwise `<E(?:\s[^>]*)?>([0-9A-Fa-f:.]+)</E>`. Names are `Regex.Escape`d.
- **Console UI:** Fluent theme, `DynamicResource` theme brushes, inline styles `BasedOn` the default, glyphs that exist in both Segoe Fluent Icons and Segoe MDL2 Assets, and icon-only buttons carry a `ToolTip` plus `AutomationProperties.Name` (AGENTS.md "Console UI").
- **Never** call `ClearIPBanList()` or touch permanent bans or the whitelist on the reload path.

## Review Focus

1. **Text that isn't XML in step 1 of the wizard.** This covers "Copy details as text" from Event Viewer, leading whitespace or a BOM, and an `<Event>` root without the namespace. The user should see the friendly parse error (or parse succeeds), never an exception. → Task 5 tests `TryParse_RejectsPlainText`, `TryParse_AcceptsLeadingWhitespaceAndNoNamespace`.
2. **The service is down when the user toggles or saves.** The error shows inline, the toggle snaps back to its previous state, and the console doesn't crash. → Task 6 test `ToggleActive_ServiceFails_RevertsAndShowsError`.
3. **Non-numeric or empty threshold input** ("", "abc", "-5" in a minutes box). This must give a field error with Save disabled, not a binding exception. → Task 6 test `NonNumericMinutes_DisablesSave`.
4. **Rule names and regexes containing `<`, `&`, `"`, `'`.** They must persist to `config.xml` and reload byte-identical. → Task 1 test `AddTask_RoundTripsXmlSpecialCharacters`.
5. **IPv4-mapped IPv6 (`::ffff:203.0.113.7`) and IPv6 values in event fields.** These are offered as candidates and matched by the generated rule. → Task 5 test `Candidates_IncludeIpv6AndMappedAddresses`.

---

### Task 1: Service test project and rule persistence (Active, boosters, new tasks)

**Files:**
- Create: `EvlWatcher/EvlWatcher.Tests/EvlWatcher.Tests.csproj` (copy of the Integration test csproj: `net10.0`, x86, MSTest 4.5.3, `Microsoft.NET.Test.Sdk` 18.12.0, references `..\EvlWatcher\EvlWatcher.csproj`). Add it to `EvlWatcher.sln` with `dotnet sln add`.
- Create: `EvlWatcher/EvlWatcher.Tests/TestSupport.cs`: `NullLogger : ILogger`, and `TempConfig` (an `IDisposable` that copies a minimal config to a temp file and points `ConfigFile.Path` at it).
- Create: `EvlWatcher/EvlWatcher/Config/ConfigFile.cs`
- Modify: `EvlWatcher/EvlWatcher/Properties/AssemblyInfo.cs`: add `[assembly: InternalsVisibleTo("EvlWatcher.Tests")]`
- Modify: `EvlWatcher/EvlWatcher/Config/IPersistentTaskConfiguration.cs`, `XmlTaskConfig.cs`, `IPersistentServiceConfiguration.cs`, `XmlServiceConfig.cs`, and `EvlWatcher.csproj` (Compile Include for `ConfigFile.cs`)
- Test: `EvlWatcher/EvlWatcher.Tests/XmlConfigPersistenceTests.cs`

**Interfaces:**
- Produces:
  - `internal static class ConfigFile { internal static string Path { get; set; } }`. It defaults to the current `Assembly.GetExecutingAssembly().Location.Replace("EvlWatcher.exe", "config.xml")`. All four existing `XDocument.Load/Save` call sites in `XmlServiceConfig.cs` and `XmlTaskConfig.cs` use it.
  - `IPersistentTaskConfiguration.Active { get; set; }`. The setter writes the `Active` **attribute** of the `<Task>` (not an element), except while loading.
  - `void IPersistentTaskConfiguration.SetRegexBoosters(IEnumerable<string> boosters)` replaces the in-memory list and rewrites `<RegexBoosters>` with one `<Booster>` per entry.
  - `IPersistentTaskConfiguration IPersistentServiceConfiguration.AddTask(string taskName)` appends `<Task Name=… Active="false">` under `<Tasks>`, with every child element the loader requires. It returns the loaded config, and the caller then sets properties. It throws `InvalidOperationException` if the name exists.
  - `NullLogger`, `TempConfig` (used by Tasks 2–4).

- [ ] **Step 1: Write failing tests** in `XmlConfigPersistenceTests` (each uses `TempConfig` and re-reads with a fresh `XmlServiceConfiguration(new NullLogger()).Load()`):
  - `SetActive_PersistsAttribute`: set `Active=false` on the first task; after reload, `Active == false` and the XML attribute is `"false"`.
  - `SetRegexBoosters_ReplacesBoosters`: set `{"a","b"}`; after reload, `RegexBoosters` is exactly `a,b`.
  - `AddTask_ThenSetProperties_ReloadsIdentically`: AddTask("New"), set every property; after reload all values are equal.
  - `AddTask_DuplicateName_Throws`.
  - `AddTask_RoundTripsXmlSpecialCharacters`: name `A<&"'>` and regex `<Data Name=.IpAddress.>(\d+)</Data>` reload byte-identical.
- [ ] **Step 2: Run the service tests.** Expected: compile FAIL (`ConfigFile`, `AddTask`, `SetRegexBoosters` and the `Active` setter don't exist).
- [ ] **Step 3: Implement** the Produces list. Write the `Active` attribute with `XElement.SetAttributeValue`. `AddTask` creates the element and calls `XmlTaskConfig.FromXmlElement`, under `_syncObject`.
- [ ] **Step 4: Build the service, then run the service tests.** Expected: 5 passed.

### Task 2: Rule validation and DTO mapping (pure)

**Files:**
- Create: `EvlWatcher/EvlWatcher/Config/RuleValidator.cs`, `EvlWatcher/EvlWatcher/Config/RuleMapper.cs` (+ Compile Include)
- Modify: `EvlWatcher/EvlWatcher.WCF/DTOs/GenericIPBlockingTaskDTO.cs`: add `public IList<string> MissingEventLogs { get; set; }`
- Modify: `EvlWatcher/EvlWatcher.WCF/DTOs/ServiceFaultDTO.cs`: `ServiceErorCode.invalidRule = 02`
- Test: `EvlWatcher/EvlWatcher.Tests/RuleValidatorTests.cs`, `RuleMapperTests.cs`

**Interfaces:**
- Consumes: Task 1's `IPersistentTaskConfiguration` (settable `Active`, `SetRegexBoosters`).
- Produces:
  - `internal static class RuleValidator { internal static IList<string> Validate(GenericIPBlockingTaskDTO rule, bool isNew, ICollection<string> existingNames, Func<string,bool> eventLogExists) }`. It returns human-readable messages; an empty list means valid. Messages name the field in plain words, for example "Ban length must be at least 1 minute."
  - `internal static class RuleMapper`:
    - `GenericIPBlockingTaskDTO ToDto(IPersistentTaskConfiguration c, Func<string,bool> eventLogExists)`. `EventPath` is split on `,`, trimmed, empties dropped. `MissingEventLogs` = paths where `!eventLogExists`.
    - `void Apply(GenericIPBlockingTaskDTO dto, IPersistentTaskConfiguration target)`. It sets everything except `TaskName`; `EventPath` is joined with `,`.

- [ ] **Step 1: Write failing tests**
  - `RuleValidatorTests`, one test per limit in Global Constraints, each asserting `Validate` returns exactly one message:
    - `TriggerCount 0`, `EventAge 9`, `LockTime 59`, `PermaBanCount 0`.
    - `PermaBanCount -1` is valid.
    - Empty name, 65-char name.
    - Duplicate name with `isNew`; unknown name with `!isNew`.
    - Regex `(` (doesn't compile); `(a)(b)` (two groups); `abc` (no group).
    - No event log; missing log with `isNew` → error; missing log with `!isNew` → valid.
    - No booster; `" "` booster.
    - A fully valid rule → empty.
  - `RuleMapperTests`:
    - `ToDto_SplitsEventPathAndFlagsMissingLogs` (`"Security, Foo/Bar"` with only `Security` existing → `MissingEventLogs = ["Foo/Bar"]`).
    - `Apply_JoinsEventPathAndSetsAllFields` (against a `TempConfig` task).
- [ ] **Step 2: Run the service tests.** Expected: compile FAIL.
- [ ] **Step 3: Implement `RuleValidator.Validate` and `RuleMapper`.** Count capture groups with `new Regex(p).GetGroupNumbers().Length - 1`.
- [ ] **Step 4: Build the service, run the service tests.** Expected: all pass.

### Task 3: Ban-state carry-over across reload

**Files:**
- Modify: `EvlWatcher/EvlWatcher/tasks/GenericIPBlockingTask.cs`
- Test: `EvlWatcher/EvlWatcher.Tests/GenericIPBlockingTaskTests.cs`

**Interfaces:**
- Consumes: `NullLogger`. Plus a test-local `FakeTaskConfig : IPersistentTaskConfiguration` with in-memory values: `TriggerCount=2`, `EventAge=120`, `LockTime=3600`, `PermaBanCount=3`, regex `ip=(\S+)`, booster `ip=`.
- Produces:
  - `internal void CarryOverStateFrom(GenericIPBlockingTask previous)`, which copies `_blockedIPsToDate`, `_bannedCount` and `_forgetIPsToDate` (entries, not references) under both tasks' locks.
  - `FromConfiguration` now sets `Active = configuration.Active`.

- [ ] **Step 1: Write failing tests.** Feed events by `ProvideEvents(new List<ExtractedEventRecord>{ new ExtractedEventRecord{ TimeCreated = DateTime.Now, Xml = "ip=203.0.113.7" }, … })`.
  - `CarryOver_KeepsTemporaryBan`: the old task bans the IP (2 events). The new task with carry-over and no events still has it in `GetTempBanVictims()`.
  - `CarryOver_KeepsStrikeCount`: after carry-over, one more ban cycle on the new task with `PermaBanCount=2` makes the IP appear in `GetPermaBanVictims()`.
  - `CarryOver_KeepsForgottenIp`: the old task gets `Forget(ip)`. The new task with carry-over, fed the same (older) events again, does **not** ban.
  - `WithoutCarryOver_ForgottenIpIsRebanned`: documents the bug the carry-over prevents.
  - `FromConfiguration_SetsActive`.
- [ ] **Step 2: Run the service tests.** Expected: FAIL (no `CarryOverStateFrom`; `Active` false).
- [ ] **Step 3: Implement** the Produces list.
- [ ] **Step 4: Build the service, run the service tests.** Expected: all pass.

### Task 4: Service operations and live reload

**Files:**
- Modify: `EvlWatcher/EvlWatcher.WCF/IEvlWatcherService.cs`, `EvlWatcher/EvlWatcher/EvlWatcher.cs`, `EvlWatcher/EvlWatcher/config.xml` (the booster comment becomes "**all** of these words must be contained…")
- Modify: `Source/AGENTS.md`: the new operations; reload carries ban state over by rule name; boosters are AND.
- Test: `EvlWatcher/EvlWatcher.Tests/TaskSetReloadTests.cs`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces (contract, each with `[OperationContract]` + `[FaultContract(typeof(ServiceFaultDTO))]`):
  - `GenericIPBlockingTaskDTO[] GetRules()`
  - `void SaveRule(GenericIPBlockingTaskDTO rule, bool isNew)`. On validation errors it throws `FaultException<ServiceFaultDTO>(new ServiceFaultDTO(ServiceErorCode.invalidRule, string.Join("\n", errors)), "invalid rule")`.
  - `void SetRuleActive(string taskName, bool active)`. An unknown name gives an `invalidRule` fault.
- Produces (internal):
  - `internal static void CarryOverByName(IEnumerable<LogTask> oldTasks, IEnumerable<LogTask> newTasks)`, a static in `EvlWatcher`. It matches `GenericIPBlockingTask` instances by `Name` and calls `CarryOverStateFrom`.
  - `private void RequestReload()`, which sets `_reloadRequested` under `_syncObject` and calls `_workerThread.Interrupt()`.

- [ ] **Step 1: Write failing tests**
  - `CarryOverByName_MatchesOnlySameNames`: old {A banned, B banned}, new {A, C}. After the call, A has the ban and C doesn't.
  - `CarryOverByName_IgnoresNonGenericTasks`: a stub `LogTask` subclass doesn't throw.
- [ ] **Step 2: Run the service tests.** Expected: compile FAIL.
- [ ] **Step 3: Implement the contract operations** in `EvlWatcher.cs`:
  - `EnsureClientPrivileges()` first in each.
  - The event log check is `EventLogSession.GlobalSession.GetLogNames()`, collected into a case-insensitive `HashSet`.
  - `SaveRule`: validate → `AddTask` when `isNew`, else find by name → `RuleMapper.Apply` → `RequestReload()`.
  - Also add the missing `EnsureClientPrivileges()` to `SaveGlobalConfig`.
- [ ] **Step 4: Restructure `Run()`** into an outer loop. The body runs: `_serviceconfiguration.Load()`; build new tasks via `InitWorkersFromConfig` into a fresh list; `CarryOverByName(old, new)`; swap `_logTasks` under `_syncObject`; rebuild the per-log dictionaries; inner scan loop. After the existing interruptible sleep, check under `_syncObject`:
  - `_stop` → the existing `ClearIPBanList()` exit.
  - `_reloadRequested` → clear the flag and `continue` the outer loop. **No** firewall call.
  
  `InitWorkersFromConfig` returns a `List<LogTask>` instead of appending to `_logTasks`.
- [ ] **Step 5: Build the service, run the service tests.** Expected: all pass.
- [ ] **Step 6: Manual check (admin shell, dev VM).** Run `EvlWatcher.exe` interactively. Temporarily ban a test IP by injecting events, or permanently ban one via the console. Call `SetRuleActive` on any rule from a PowerShell WCF client or the console after Task 6. Expected log lines, in order: "loaded configuration…" for every rule, then **no** "Removing … from firewall", and the firewall rule's remote addresses are unchanged.

### Task 5: Console `RuleBuilder` (pure) and console test project

**Files:**
- Create: `EvlWatcherConsole/EvlWatcherConsole/Rules/RuleBuilder.cs`, `Rules/ParsedEvent.cs`, `Rules/IpCandidate.cs`
- Create: `EvlWatcherConsole/EvlWatcherConsole.Tests/EvlWatcherConsole.Tests.csproj` (`net10.0-windows`, MSTest 4.5.3, references the console project), added to `EvlWatcherConsole.sln`
- Create: `EvlWatcherConsole/EvlWatcherConsole.Tests/Samples/*.xml` (copied to output) and `RuleBuilderTests.cs`

**Interfaces:**
- Consumes: `GenericIPBlockingTaskDTO` (compiled-in contract source; it now has `MissingEventLogs`).
- Produces (all `public`, namespace `EvlWatcherConsole.Rules`):
  - `IpCandidate { string FieldLabel; string ElementName; bool IsNamedData; IPAddress Address; bool IsLocal }`. `IsLocal` covers loopback, `IPAddress.Any` and `IPv6Any`.
  - `ParsedEvent { string Provider; string EventId; string Channel; IReadOnlyList<IpCandidate> Candidates; string PastedText; string CompactXml }`. `CompactXml` is one line with single-quoted attributes, mimicking `EventRecord.ToXml()`.
  - `static bool RuleBuilder.TryParse(string text, out ParsedEvent ev, out string error)`. `error` is the spec's verbatim message: "That doesn't look like an event's XML. Make sure you copied it from the XML View."
  - `static GenericIPBlockingTaskDTO RuleBuilder.BuildRule(ParsedEvent ev, IpCandidate chosen, ICollection<string> existingNames)`. It applies the defaults and naming from the spec, with `Active = true` and seconds for `EventAge` (120) and `LockTime` (3600).
  - `static IPAddress RuleBuilder.Match(GenericIPBlockingTaskDTO rule, string eventXml)`. All boosters must be contained, regex group 1 must `TryParse`, otherwise `null`. This mirrors `GenericIPBlockingTask.cs:134-153`.
  - `static bool RuleBuilder.SelfTest(GenericIPBlockingTaskDTO rule, ParsedEvent ev, IPAddress expected)`. Both `PastedText` and `CompactXml` must `Match` to `expected`.
  - `static string RuleBuilder.FindCoveringRule(IEnumerable<GenericIPBlockingTaskDTO> rules, ParsedEvent ev)`. It returns the first `Active` rule whose `Match` on either form is non-null, else `null`.
  - `static string RuleBuilder.ShortProviderName(string provider)`, which strips a leading `Microsoft-Windows-`.

Samples (realistic Event Viewer XML; implementer writes them):
- `security-4625-pretty.xml`: pretty-printed, double quotes, `xmlns`, `<EventID>4625</EventID>`, `<Data Name="IpAddress">203.0.113.7</Data>`, `<Data Name="WorkstationName">-</Data>`
- `security-4625-compact.xml`: the same event on one line, single quotes
- `qualifiers.xml`: `<EventID Qualifiers="0">18456</EventID>` (MSSQL), IP inside `<Data>` **without** a Name, as the whole value
- `userdata-rdpcore.xml`: `<UserData><EventXML><Address>198.51.100.4</Address>…`
- `ipv6.xml`: one IPv6 field and one `::ffff:203.0.113.9` field
- `freetext-only.xml`: IP only inside a sentence in `<Data>`
- `loopback.xml`: `IpAddress` = `127.0.0.1`

- [ ] **Step 1: Write failing tests** in `RuleBuilderTests`:
  - `TryParse_RejectsPlainText` ("Log Name: Security\r\nSource: …") returns false with the exact error text.
  - `TryParse_AcceptsLeadingWhitespaceAndNoNamespace`.
  - `TryParse_ReadsProviderEventIdChannel` (4625 pretty → `Microsoft-Windows-Security-Auditing`, `4625`, `Security`).
  - `Candidates_FindsNamedDataField`: label `IpAddress`. `-` isn't a candidate.
  - `Candidates_FindsUserDataElement`: label `Address`, `IsNamedData=false`.
  - `Candidates_IncludeIpv6AndMappedAddresses`.
  - `Candidates_MarksLoopbackLocal`.
  - `Candidates_FreeTextOnly_IsEmpty`.
  - `BuildRule_UsesSpecDefaultsAndPatterns`: name "Security-Auditing 4625", boosters `["Microsoft-Windows-Security-Auditing", ">4625</EventID>"]`, regex `<Data Name=.IpAddress.>([0-9A-Fa-f:.]+)</Data>`, `EventPath=["Security"]`, 5/120/3600/3.
  - `BuildRule_MakesNameUnique` (existing name → " (2)").
  - `SelfTest_PassesOnPrettyAndCompactForEverySample` (data-driven over the four samples with candidates).
  - `Match_QualifiersEventId_MatchesBooster`.
  - `FindCoveringRule_ReturnsExistingRuleName`, using the real `BlockRDPBrutersBySecurity4625` values copied from `config.xml` against the 4625 samples.
- [ ] **Step 2: Run** `dotnet test EvlWatcherConsole.Tests -c Release`. Expected: compile FAIL.
- [ ] **Step 3: Implement.** Parse with `XDocument.Parse(text.Trim())` inside try/catch, matching elements by `LocalName`. Candidates are leaf elements under `EventData`/`UserData` whose trimmed value `IPAddress.TryParse`s. `CompactXml` comes from `XElement.ToString(SaveOptions.DisableFormatting)` with `"` swapped for `'` in attribute values only (build it by walking elements; don't blindly replace).
- [ ] **Step 4: Run the console tests.** Expected: all pass.

### Task 6: Rules tab: list and plain-language settings

**Files:**
- Create: `EvlWatcherConsole/EvlWatcherConsole/Rules/IRuleClient.cs`, `ViewModel/RulesViewModel.cs`, `ViewModel/RuleEditorViewModel.cs`, `View/RulesView.xaml(.cs)` (a `UserControl`)
- Modify: `Model/EvlWatcherModel.cs` (implements `IRuleClient`), `ViewModel/MainWindowViewModel.cs` (exposes `Rules`; the old Rule Tester stays), `View/MainWindow.xaml`:
  - Tab order is Bans & Whitelist · Live · **Rules** · Settings · **Advanced**. That's the renamed Rule Tester, with a header glyph `&#xE943;` and the "Advanced" label; the Rules tab uses `&#xE8FD;` (BulletedList).
- Test: `EvlWatcherConsole.Tests/RulesViewModelTests.cs`, with a `FakeRuleClient`

**Interfaces:**
- Consumes: Task 4's contract operations.
- Produces:
  - `public interface IRuleClient { IList<GenericIPBlockingTaskDTO> GetRules(); void SaveRule(GenericIPBlockingTaskDTO rule, bool isNew); void SetRuleActive(string name, bool active); }`. The service's fault message reaches the VM as `RuleClientException(string message)`, thrown by `EvlWatcherModel` for `FaultException<ServiceFaultDTO>` (`Detail.Message`) and `CommunicationException`/`EndpointNotFoundException` ("EvlWatcher service is not responding.").
  - `RulesViewModel(IRuleClient client)`:
    - `ObservableCollection<RuleEditorViewModel> Rules`, `RuleEditorViewModel Selected`, `void Refresh()` (keeps the selection by name), `string StatusMessage`.
    - `bool IsBusyEditing` is true while any editor `IsDirty` or the wizard is open. `MainWindowViewModel`'s timer skips `Refresh()` when it's true.
  - `RuleEditorViewModel`:
    - Wraps a DTO copy. `string Name`, `string Description`, `bool IsActive` (setter calls `SetRuleActive` and reverts on failure), `bool HasMissingLogs`.
    - Text-bound `string AttemptsText`, `string WindowMinutesText`, `string BanMinutesText`, `string PermanentAfterText`, `bool NeverPermanent`.
    - Advanced: `string EventLogsText`, `string BoostersText` (one per line), `string Regex`, `bool OnlyNewEvents`.
    - `bool IsDirty`, `string FieldError`, `string SaveError`, `ICommand SaveCommand` (enabled when dirty and no `FieldError`), `ICommand DiscardCommand`.
  - **Minutes conversion:** seconds = minutes × 60. The window shows `EventAge/60.0`, formatted without trailing zeros. Non-integer seconds in existing rules display as decimals and are accepted as decimal minutes, rounded to whole seconds.

- [ ] **Step 1: Write failing tests**
  - `Refresh_ListsDisabledRulesToo`.
  - `ToggleActive_CallsClientAndUpdatesStatus`: `StatusMessage == "Rule applied. EvlWatcher reloaded its rules."`.
  - `ToggleActive_ServiceFails_RevertsAndShowsError`.
  - `EditMinutes_ConvertsToSecondsOnSave` (`WindowMinutesText="2"` → saved `EventAge=120`; `BanMinutesText="60"` → `LockTime=3600`).
  - `NeverPermanent_SavesMinusOne`.
  - `NonNumericMinutes_DisablesSave` ("", "abc", "-5" each set `FieldError` and make `SaveCommand.CanExecute` false).
  - `SaveFault_ShowsServiceMessageVerbatim`.
  - `Refresh_KeepsSelectionByName`.
  - `Refresh_SkippedWhileDirty` (via `IsBusyEditing`).
- [ ] **Step 2: Run the console tests.** Expected: compile FAIL.
- [ ] **Step 3: Implement** the VMs, `IRuleClient` on `EvlWatcherModel`, and `RulesView.xaml` per the spec's sketch:
  - Two-column `Grid`: list `ListView` with an item template (dot + name + subtitle + "log not on this machine" caption), and details in `CardStyle`.
  - The sentence layout around the number `TextBox`es; the `CheckBox` "Never ban permanently"; an `Expander` "Advanced" collapsed.
  - Save as `AccentButtonStyle`, Discard as default, both visible only when `IsDirty`.
  - `SaveError`/`FieldError` in `SystemFillColorCriticalBrush` text.
  - Rename the tab and wire it in `MainWindow.xaml`.
- [ ] **Step 4: Run the console tests and build.** Expected: all pass, 0 warnings.
- [ ] **Step 5: Visual check.** Build the non-elevated copy into the scratchpad (`-p:ApplicationManifest=`), launch it, and screenshot the Rules tab with the service stopped. Expected: the empty list shows "EvlWatcher service is not responding." in the status line, with no crash.

### Task 7: New-rule wizard

**Files:**
- Create: `ViewModel/NewRuleWizardViewModel.cs`, `View/NewRuleWizardView.xaml(.cs)`
- Modify: `ViewModel/RulesViewModel.cs` (`ICommand NewRuleCommand`, `NewRuleWizardViewModel Wizard`; the details pane shows the wizard while it's non-null), `View/RulesView.xaml`
- Modify: `Source/AGENTS.md` ("Console UI": the Rules tab and wizard; `RuleBuilder` is the place for event-parsing logic), `../README.md` (Console section: the Rules tab and the wizard, Rule Tester renamed Advanced)
- Test: `EvlWatcherConsole.Tests/NewRuleWizardViewModelTests.cs`

**Interfaces:**
- Consumes: `RuleBuilder` (Task 5), `IRuleClient` and `RulesViewModel` (Task 6).
- Produces: `NewRuleWizardViewModel(IRuleClient client, IList<GenericIPBlockingTaskDTO> existingRules, Action<string> onSaved, Action onCancel)`, with:
  - `int Step` (1–3) and `string PastedText`.
  - `string ParseError`, `IReadOnlyList<IpCandidate> Candidates`, `IpCandidate SelectedCandidate`, `string CoveredByRule`, `bool NoUsableCandidate`.
  - `RuleEditorViewModel Draft`: step 3 reuses Task 6's editor. Its Save calls `SaveRule(isNew:true)` instead.
  - `bool SelfTestPassed`, `string SelfTestMessage` ("✓ This rule finds {ip} in your event.").
  - `ICommand NextCommand`, `BackCommand`, `CancelCommand`, `SaveCommand`, `GoToRuleCommand`, `ContinueAnywayCommand`.

- [ ] **Step 1: Write failing tests**
  - `Step1_NextDisabledUntilParses`.
  - `Step1_InvalidText_ShowsParseError`.
  - `Step2_PreselectsSingleUsableCandidate`.
  - `Step2_FreeTextOnly_NoUsableCandidateAndNextDisabled`.
  - `Step2_CoveredByExistingRule_SetsCoveredByRule`.
  - `Step3_EditingRegexToNonMatching_FailsSelfTestAndDisablesSave`.
  - `Save_CallsSaveRuleIsNewAndInvokesOnSavedWithName`. `RulesViewModel`'s `onSaved` handler refreshes, selects the new rule and sets `StatusMessage == "Rule added and active."`. Assert that in `RulesViewModelTests.NewRuleSaved_SelectsItAndSetsStatus`.
  - `Save_ServiceFault_StaysOnStep3WithMessage`.
  - `Cancel_InvokesOnCancel`.
- [ ] **Step 2: Run the console tests.** Expected: compile FAIL.
- [ ] **Step 3: Implement** the VM and `NewRuleWizardView.xaml`:
  - A step indicator ("1 Paste · 2 Pick IP · 3 Review").
  - Step 1: the monospace `TextBox` and the Event Viewer hint copy from the spec.
  - Step 2: a radio list "**{ip}** found in *{field}*", local candidates disabled with the spec's "this is your own machine" caption. The "Already covered by rule X" `InfoBar`-style card has Continue anyway and Go to rule. The no-candidate message is verbatim from the spec.
  - Step 3: the `RuleEditorViewModel` editor plus the self-test line.
  - **Re-run the self-test** whenever `Draft` changes.
- [ ] **Step 4: Run all console tests and build.** Expected: all pass, 0 warnings.
- [ ] **Step 5: Visual check.** Use the same non-elevated build. Paste `security-4625-pretty.xml` and walk all three steps; screenshot each. Expected: the candidate `203.0.113.7` is preselected and the self-test shows ✓. Save then shows the "service is not responding" error, since the service isn't running.
- [ ] **Step 6: End-to-end (admin shell, dev VM).** Run the service interactively and the console elevated. Add a rule from a real 4625 event. Expected:
  - The rule appears in `config.xml` and in the list as active.
  - The Live tab logs the rule loading.
  - Existing temporary and permanent bans in the firewall rule are unchanged.
