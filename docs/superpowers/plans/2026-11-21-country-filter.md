# Country Filter per Rule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each EvlWatcher rule can allow only addresses from listed countries (e.g. `IN`). Other countries get a temporary ban, which never counts towards a permanent ban, on their first matched attempt. Country data comes from the five internet registries, refreshed weekly. Released as v3.3.0.

**Architecture:**
- **Service:**
  - A new `Geo` area holds `DelegatedFileParser`, `CountryDatabase : ICountryLookup` and `CountryDataService`. The service loads the data, refreshes it per registry and reports status.
  - `GenericIPBlockingTask` gets an `ICountryLookup` and lowers the trigger to 1 for foreign addresses on rules with `AllowedCountries`, without adding a strike.
  - Contract: a new `[DataMember]` on the rule DTO and three new operations.
- **Console:** a country row in the rule details and a country-data card on the Settings tab.

**Tech Stack:** .NET Framework 4.7.2 service (old-style csproj, MSBuild), WCF, WPF console (net472, SDK-style), MSTest. Service tests go in `EvlWatcher.Tests.Integration` (net10.0, x86).

**Spec:** `docs/superpowers/specs/2026-11-21-country-filter-design.md`. It covers sources, behaviour, the anti-goals and the decisions settled after review.

## Global Constraints

- **Service conventions** (AGENTS.md):
  - New service `.cs` files must be added to `EvlWatcher.csproj` `<Compile Include>` by hand.
  - Use `lock (_syncObject)` for shared state, `ILogger.Dump` for logging, and `ConfigFile.Save` for config writes.
  - Keep `EvlWatcher.WCF` free of service internals.
- **Contract changes:** additive only. New operations carry `[FaultContract(typeof(ServiceFaultDTO))]`. Both solutions are rebuilt.
- **Data sources:** the five URLs listed in the spec. Use lines of type `ipv4` and `ipv6` with status `allocated` or `assigned` only.
- **Data folder:** `<dir of EvlWatcher.exe>\geo\`, one file per registry: `delegated-<registry>.txt` with registry = `apnic`, `ripencc`, `arin`, `lacnic`, `afrinic`.
- **Validity:** a file counts as valid when it has at least 1,000 ranges.
- **Refresh:** weekly (7 days), per registry. A failure keeps that registry's previous file.
- **Downloads:** enable TLS 1.2 (`ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12`).
- **Filter applies only when all of these hold:** the rule has `AllowedCountries`, `ICountryLookup.IsLoaded`, the address is not private, loopback or this machine's own, its country is known, and that country is not in the list. Otherwise the normal `TriggerCount` applies.
- **Strikes:** a ban caused only by the country filter never increments `_bannedCount`.
- **Whitelist:** unchanged. It always wins.
- **Country codes:** two letters A–Z, stored upper case and comma-separated in `<AllowedCountries>`.
- **Version:** 3.3.0.
- **Builds and tests**, run from `Source\`:
  - **Service:** `"C:\Program Files\Microsoft SQL Server Management Studio 22\Release\MSBuild\Current\Bin\MSBuild.exe" EvlWatcher\EvlWatcher.sln -t:EvlWatcher -p:Configuration=Release "-p:Platform=Mixed Platforms"`
  - **Service tests:** `dotnet build EvlWatcher\EvlWatcher.Tests.Integration -c Release -p:BuildProjectReferences=false`, then `dotnet test EvlWatcher\EvlWatcher.Tests.Integration -c Release --no-build --filter "FullyQualifiedName!~FirewallApiTests"`. The firewall tests need admin and are excluded.
  - **Console:** `dotnet build EvlWatcherConsole\EvlWatcherConsole.sln -c Release` and `dotnet test EvlWatcherConsole\EvlWatcherConsole.Tests -c Release`

## Review Focus

1. **A registry unreachable for weeks, or changing its file format.**
   - Expected: the other registries keep updating, the old file for that registry stays, and the status names the failing registry.
   - Test: Task 2 `FailingRegistryKeepsItsFileOthersUpdate`.
2. **An address on the whitelist, or in the server's own LAN, from a "foreign" country.**
   - Expected: never banned.
   - Test: Task 3 `PrivateAddressUsesNormalTrigger`. The whitelist check is existing service code and stays unchanged.
3. **A rule with `AllowedCountries` saved by an older console** whose DTO lacks the field.
   - Expected: the setting must not be wiped silently.
   - Test: Task 4 `SaveRuleWithoutCountriesFieldKeepsExistingValue`.
4. **IPv6 attackers** (registries list IPv6 by prefix).
   - Expected: looked up correctly.
   - Test: Task 1 `LooksUpIPv6`.
5. **The service starting with no `geo` folder at all,** for example after a manual install.
   - Expected: the filter is inactive, the service runs normally, and the status says "not loaded".
   - Test: Task 2 `MissingFolderLoadsNothingAndReportsNotLoaded`.

---

### Task 1: Registry file parser and country lookup

**Files:**
- Create: `Source/EvlWatcher/EvlWatcher/Geo/DelegatedFileParser.cs`, `Geo/CountryDatabase.cs`, `Geo/ICountryLookup.cs`
- Modify: `EvlWatcher.csproj` (Compile entries), `Properties/AssemblyInfo.cs` (add `InternalsVisibleTo("EvlWatcher.Tests.Integration")`)
- Test: `Source/EvlWatcher/EvlWatcher.Tests.Integration/CountryDatabaseTests.cs`

**Interfaces (Produces), namespace `EvlWatcher.Geo`:**
- **`ICountryLookup`:**
  - `bool IsLoaded { get; }`
  - `string GetCountry(IPAddress ip)` returns an upper-case code, or null when unknown.
- **`DelegatedFileParser`:**
  - Struct `CountryRange { string Country; bool IsV6; ulong StartHi, StartLo, EndHi, EndLo; }`. IPv4 is stored as `StartHi = EndHi = 0` with the 32-bit value in `Lo`.
  - Method `static IList<CountryRange> Parse(TextReader reader, out string registry)`.
  - Skips the version header line (first line starting with a digit followed by `|`), summary lines (`|*|`), `#` comments, blank lines, lines with fewer than 7 fields, and statuses other than `allocated` / `assigned`.
  - IPv4: value is the address count, so end = start + count − 1. IPv6: value is the prefix length.
  - `registry` comes from field 0 of the first data line.
- **`CountryDatabase : ICountryLookup`:**
  - `static CountryDatabase Empty` (`IsLoaded = false`).
  - Constructor `CountryDatabase(IEnumerable<IList<CountryRange>> registries)`: sorts by start and uses binary search. `IsLoaded = total ranges > 0`.
  - `int RangeCount { get; }`
  - `GetCountry` maps IPv4-mapped IPv6 addresses to IPv4 first.

- [ ] **Step 1: Write the failing tests** in `CountryDatabaseTests`, using inline sample text in the real format:

  ```
  2|apnic|20261120|...
  apnic|*|ipv4|*|...|summary
  apnic|IN|ipv4|103.228.148.0|1024|20160101|allocated
  apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
  apnic|IN|ipv6|2401:4900::|32|20130101|allocated
  apnic||ipv4|1.2.3.0|256||reserved
  ```

  - `ParsesIpv4CountAndIpv6Prefix`: 3 ranges; registry `"apnic"`.
  - `LooksUpIPv4AtEdges`: `103.228.148.0` and `103.228.151.255` give `IN`; `103.228.152.0` gives null.
  - `LooksUpIPv6`: `2401:4900:1:2::5` gives `IN`.
  - `IPv4MappedIsLookedUpAsIPv4`: `::ffff:1.0.1.7` gives `CN`.
  - `ReservedAndSummaryLinesAreSkipped`: `1.2.3.4` gives null.
  - `EmptyDatabaseIsNotLoaded`: `CountryDatabase.Empty.IsLoaded == false`.
  - `MalformedLinesAreSkipped`: a line `apnic|IN|ipv4|not-an-ip|256|x|allocated` is ignored without throwing.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Build the service and the test project (Global Constraints), then run the tests filtered with `--filter CountryDatabaseTests`.
  - Expected: build FAIL (the types don't exist yet).
- [ ] **Step 3: Implement** the parser, the database and the interface, and add the csproj entries and `InternalsVisibleTo`.
- [ ] **Step 4: Run the service tests (without the firewall tests).** Expected: all pass, including the existing ones.
- [ ] **Step 5: Commit** with the message "Country filter: registry parser and country lookup".

### Task 2: Country data service (load, per-registry update, status)

**Files:**
- Create: `Geo/CountryDataService.cs`, `Geo/IRegistryDownloader.cs`, `Geo/HttpRegistryDownloader.cs`
- Modify: csproj
- Test: `EvlWatcher.Tests.Integration/CountryDataServiceTests.cs`

**Interfaces:**
- **`IRegistryDownloader`:** `string Download(string url)`. Returns the file text and throws on failure.
- **`HttpRegistryDownloader`:**
  - Uses `WebClient` with TLS 1.2 enabled and a 60 s timeout. Subclass `WebClient` and override `GetWebRequest` to set the timeout.
  - Sends the user agent `EvlWatcher`.
- **`CountryDataService : ICountryLookup`:**
  - Constructor: `CountryDataService(string geoFolder, IRegistryDownloader downloader, ILogger logger, Func<DateTime> utcNow)`.
  - `static readonly IReadOnlyDictionary<string,string> Sources` maps registry name to URL (the five from the spec).
  - `void Load()`:
    - Reads every `delegated-*.txt` in the folder.
    - Skips a missing or unparsable file, or one with fewer than 1,000 ranges, and logs a Warning.
    - Swaps in the new `CountryDatabase`.
  - `void UpdateAll()`:
    - For each source: download, parse, validate (≥ 1,000 ranges), write to `delegated-<name>.txt.tmp`, then `File.Copy(tmp, final, true)` and delete the tmp file.
    - A failure records `"<NAME>: <message>"` in the errors and keeps that registry's file.
    - Afterwards: `Load()`, record `UpdatedUtc = utcNow()` when at least one registry succeeded, and `LastError` = the errors joined with "; ", or null.
  - `bool NeedsUpdate`: true when no registry file exists, or the newest file write time is more than 7 days ago.
  - `void Start(bool autoUpdate)`:
    - `Load()`.
    - If `autoUpdate`: a `System.Threading.Timer` that runs `UpdateAll` on the thread pool, immediately if `NeedsUpdate`, and every 7 days after that.
    - Never runs on the scan thread.
  - `void UpdateNowAsync()`: queues `UpdateAll` on the thread pool. A second call while one is running is ignored.
  - `CountryDataStatus GetStatus()` returns `{ bool Loaded; DateTime? UpdatedUtc; int RangeCount; string LastError; IList<string> Registries }`. `UpdatedUtc` falls back to the newest file write time.
  - `ICountryLookup` members delegate to the current database. A `volatile` field swaps the database atomically.

- [ ] **Step 1: Write the failing tests.** Use a temp folder, a fake downloader that maps URL to text or throws, and the 1,000-range validation fed with generated sample files.
  - `LoadReadsAllRegistryFiles`.
  - `MissingFolderLoadsNothingAndReportsNotLoaded`: `Loaded == false`, no exception.
  - `CorruptFileIsSkippedOthersLoad`.
  - `UpdateWritesValidFilesAndReloads`.
  - `FailingRegistryKeepsItsFileOthersUpdate`: LACNIC throws. Its old file stays, the others are replaced, and `LastError` contains `"LACNIC"`.
  - `TooSmallDownloadIsRejected`: 10 ranges means the file is not replaced.
  - `NeedsUpdateAfterSevenDays`: set the file write time 8 days back.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement** the service, the downloader interface and the downloader, plus the csproj entries.
- [ ] **Step 4: Run the service tests.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Country filter: data service with per-registry weekly update".

### Task 3: Rule behaviour (first-attempt ban without a strike)

**Files:**
- Modify:
  - `Config/IPersistentTaskConfiguration.cs` (`IList<string> AllowedCountries { get; set; }`)
  - `Config/XmlTaskConfig.cs` (read the optional `<AllowedCountries>`; write it, or remove the element when the list is empty)
  - `tasks/GenericIPBlockingTask.cs`
  - `tasks/DefaultGenericTaskFactory.cs` (constructor takes an `ICountryLookup`)
  - `EvlWatcher.cs` `Main` (pass the service's lookup)
- Test: `EvlWatcher.Tests.Integration/CountryRuleTests.cs`

**Interfaces:**
- `GenericIPBlockingTask.FromConfiguration(IPersistentTaskConfiguration configuration, ILogger logger, ICountryLookup countries)`. The old two-argument overload passes `CountryDatabase.Empty`.
- `GenericIPBlockingTask.AllowedCountries` is an `ISet<string>`, upper case.
- Test seam: `GenericIPBlockingTask` exposes `internal void ComputeEvents(List<ExtractedEventRecord> events)`, or the tests call the existing `ProvideEvents` path if it is accessible. Use whichever the existing code allows, without changing behaviour.

**Algorithm** (in `OnComputeEvents`, after counting):
- For each IP, set `needed = IsCountryBlocked(ip) ? 1 : TriggerCount`.
- If count ≥ `needed` and the IP is not already blocked, add it to `_blockedIPsToDate`.
- Increment `_bannedCount` only when count ≥ `TriggerCount`.
- Log at Info: `"{Name}: banning {ip} on first attempt (country {cc}, rule allows only {list})"`.
- `IsCountryBlocked(ip)`:
  - Requires `AllowedCountries.Count > 0` and `countries.IsLoaded`.
  - The address is not loopback, not private (10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10), and not one of this machine's addresses (`Dns.GetHostAddresses(Dns.GetHostName())`, cached at construction).
  - `GetCountry` returns non-null and the result is not in `AllowedCountries`.

- [ ] **Step 1: Write the failing tests** with a fake `ICountryLookup` (IP → code) and the shipped 4625 rule regex. Events are built like the existing integration tests or from `ExtractedEventRecord { TimeCreated, Xml }` with 4625 XML:
  - `ForeignAddressBannedAfterOneAttemptWithoutStrike`:
    - 1 event from a `CN` address. Expect it in `GetTempBanVictims()`.
    - After 3 lock-time expiries and re-bans (advance the time via `LockTime = 1` and waits, or the existing time seam), `GetPermaBanVictims()` stays empty.
  - `ForeignAddressReachingTriggerCountGetsStrike`: 5 events give strike 1.
  - `AllowedCountryNeedsTriggerCount`: 1 event from `IN` is not banned, 5 events are.
  - `UnknownCountryNeedsTriggerCount`.
  - `NotLoadedNeedsTriggerCount`.
  - `PrivateAddressUsesNormalTrigger`: 192.168.1.20 with the lookup saying `CN`. Not banned after 1 event.
  - `XmlTaskConfigRoundTripsAllowedCountries`: read `<AllowedCountries>in, AE</AllowedCountries>` and get `{IN, AE}`. Write an empty list and the element is gone.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement** the changes above. Wire `Main`:
  - Create `new CountryDataService(geoFolder, new HttpRegistryDownloader(), logger, () => DateTime.UtcNow)`.
  - Create the factory with it.
  - Call `Start(serviceConfiguration.CountryDataAutoUpdate)` (Task 4 adds the setting). Until Task 4 lands, use `true`.
- [ ] **Step 4: Run the service tests.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Country filter: first-attempt ban without strike".

### Task 4: Contract, mapping, validation and service operations

**Files:**
- Modify:
  - `EvlWatcher.WCF/DTOs/GenericIPBlockingTaskDTO.cs`: `[DataMember] IList<string> AllowedCountries`
  - `EvlWatcher.WCF/IEvlWatcherService.cs`: `CountryDataStatusDTO GetCountryDataStatus()`, `void UpdateCountryDataNow()`, `void SetCountryDataAutoUpdate(bool enabled)`
  - `Config/RuleMapper.cs`
  - `Config/RuleValidator.cs`
  - `Config/IPersistentServiceConfiguration.cs` and `XmlServiceConfig.cs` (`bool CountryDataAutoUpdate`, element `<CountryDataAutoUpdate>` in `<Global>`, default true when missing)
  - `EvlWatcher.cs` (implement the operations; `UpdateCountryDataNow` → `UpdateNowAsync`; `SetCountryDataAutoUpdate` saves the setting and restarts the timer)
  - the service csproj if needed
- Create: `EvlWatcher.WCF/DTOs/CountryDataStatusDTO.cs` (`[DataContract]` with `Loaded`, `UpdatedUtc` (`DateTime?`), `RangeCount`, `LastError`, `Registries` (`string[]`), `AutoUpdate`), added to the WCF csproj.
- Test: `EvlWatcher.Tests.Integration/CountryContractTests.cs`

**Behaviour:**
- `RuleMapper` maps `AllowedCountries` both ways and normalises to trimmed upper case.
- **When the DTO's `AllowedCountries` is null** (an older console), `RuleMapper.Apply` keeps the existing value. An empty list clears it.
- `RuleValidator` reports `"Country codes must be two letters, e.g. IN."` for any entry not matching `^[A-Z]{2}$`.

- [ ] **Step 1: Write the failing tests:**
  - `MapperRoundTripsAllowedCountries`.
  - `SaveRuleWithoutCountriesFieldKeepsExistingValue`: null keeps `{IN}`.
  - `EmptyListClearsCountries`.
  - `ValidatorRejectsBadCodes`: `IND`, `I1` and `""` are rejected; `in` passes after normalisation.
  - `ServiceConfigDefaultsAutoUpdateToTrue`: XML without the element gives true. Use the existing XML-config test approach, or a temp `config.xml` if `XmlServiceConfiguration` accepts a path. If it doesn't, add an internal constructor taking the path.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the service tests, then build the console solution.**
  - Expected: all pass. The console compiles the shared contract from source and still builds.
- [ ] **Step 5: Commit** with the message "Country filter: contract, mapping, validation, service operations".

### Task 5: Console: country option on each rule

**Files:**
- Modify:
  - `EvlWatcherConsole/Rules/IRuleClient.cs`: `CountryDataStatusDTO GetCountryDataStatus()`
  - `Model/EvlWatcherModel.cs` (implement it via `Call`)
  - `ViewModel/RuleEditorViewModel.cs`
  - `ViewModel/RulesViewModel.cs` (fetch the status on each refresh and pass it to the editors)
  - `View/RulesView.xaml` (a row under the sentences; hidden in the wizard)
- Create: `Rules/CountryCodes.cs` (`static bool TryGetName(string code, out string englishName)` using `new RegionInfo(code).EnglishName`. It accepts only `^[A-Z]{2}$` that `RegionInfo` resolves.)
- Test: `EvlWatcherConsole.Tests/CountryOptionTests.cs`, plus updating the fake rule client in `RulesViewModelTests.cs`.

**RuleEditorViewModel additions:**
- `bool RestrictCountries`
- `string AllowedCountriesText` (comma-separated)
- `string CountryNamesText` (e.g. "India", or "India, United Arab Emirates")
- `string CountryError` (`"Unknown country code: XX"`)
- `bool CountryDataUnavailable`
- `string CountryNote` (the spec's note text, verbatim)
- Save puts `AllowedCountries` into the DTO: the parsed codes, or an empty list when the box is unticked. Save is blocked while `CountryError` is non-empty.
- The wizard (`isNew: true`) hides the row.

- [ ] **Step 1: Write the failing tests:**
  - `ShowsCountryNames`: `"in, ae"` gives `"India, United Arab Emirates"`.
  - `UnknownCodeBlocksSave`: `"XX"`.
  - `SaveSendsCodes`: ticked with `"IN"` saves `{"IN"}`.
  - `UntickedSavesEmptyList`.
  - `NotLoadedShowsHint`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement** the view-model members and the XAML row, using theme styles only.
- [ ] **Step 4: Run the console tests and the theme tests.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Console: country option on each rule".

### Task 6: Console: country data card on Settings

**Files:**
- Create: `ViewModel/CountryDataViewModel.cs`
- Modify:
  - `Rules/IRuleClient.cs`: add `void UpdateCountryDataNow()` and `void SetCountryDataAutoUpdate(bool enabled)`
  - `Model/EvlWatcherModel.cs`
  - `MainWindowViewModel.cs` (property `CountryData`, refreshed when the Settings tab is selected)
  - `View/MainWindow.xaml` (a card on the Settings tab)
- Test: `EvlWatcherConsole.Tests/CountryDataViewModelTests.cs`

**CountryDataViewModel(IRuleClient client):**
- `string StatusText`, for example:
  - "Updated 21/11/2026 · 312,000 ranges from APNIC, RIPENCC, ARIN, LACNIC, AFRINIC"
  - "Country data isn't loaded."
  - plus " · Last update problem: …" when there was one.
- `bool AutoUpdate` (two-way; the setter calls `SetCountryDataAutoUpdate`).
- `ICommand UpdateNowCommand` (calls `UpdateCountryDataNow`, then the status reads "Updating… check back in a minute").
- `void Refresh()`.
- Errors go to `string Error`.

- [ ] **Step 1: Write the failing tests:**
  - `StatusTextShowsDateCountAndRegistries`.
  - `NotLoadedText`.
  - `UpdateNowCallsService`.
  - `AutoUpdateToggleCallsService`.
  - `ServiceDownShowsError`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the console tests.** Expected: all pass.
- [ ] **Step 5: Commit** with the message "Console: country data status and update on Settings".

### Task 7: Installer snapshot, version 3.3.0, docs, end-to-end check

**Files:**
- Create: `Source/EvlWatcher/EvlWatcher/NSIS/fetch-geo.ps1`. It downloads the five files into `.\geo\` with the same URLs and TLS 1.2 and fails if any file has fewer than 1,000 data lines.
- Modify:
  - `NSIS/make.nsi`:
    - Install: `SetOutPath $INSTDIR\geo` + `SetOverwrite ifnewer` + `File "geo\delegated-*.txt"`, then restore `SetOverwrite on` and `SetOutPath $INSTDIR`.
    - Uninstall: `RMDir /r $INSTDIR\geo`.
    - Update the header comment with the inputs.
  - Version 3.3.0 in the three `AssemblyInfo.cs` files, the window title, `OutFile` and the README.
  - `NEWS.md`.
  - `Versions/v3/EvlWatcher-v3.3.0 release notes.txt`. Explain the outgoing HTTPS to the five registries, the first-attempt temporary bans that never become permanent on their own, that the country is where the address is registered (cloud, VPN and roaming users belong on the whitelist), and the re-ban effect.
  - `Source/AGENTS.md` (a country-filter section: `Geo/` classes, data folder, refresh rule, no-strike rule and why).

- [ ] **Step 1: End-to-end check on the dev machine, without touching the live service.**
  - Write a scratch console snippet or test that runs `CountryDataService.UpdateAll()` with the real `HttpRegistryDownloader` into a temp folder.
  - Expected: all 5 registries download and `GetCountry(103.228.149.59)` gives `"IN"`.
  - Record the result in the ledger. If the network blocks a registry, record which one.
- [ ] **Step 2: Version edits and docs.**
  - Run `git grep -n "3\.2\.0" -- Source README.md`.
  - Expected: only history entries remain.
- [ ] **Step 3: Rebuild both solutions and run both test suites.**
  - Expected: 0 warnings, all pass, all binaries at 3.3.0.0.
- [ ] **Step 4: Build the installer.**
  - Run `fetch-geo.ps1`, stage the inputs plus `geo\`, and run `makensis`.
  - Expected: no warnings. The installer goes to `Versions/v3/`, unsigned. Report its SHA-256.
- [ ] **Step 5: Commit** with the message "Release prep v3.3.0: country filter docs, installer snapshot, version". Then run the whole-branch review and finishing-a-development-branch.
