# Country filter per rule ("Only allow addresses from …")

Date: 2026-11-21 · Target release: v3.3.0 (on top of the unreleased v3.2.0 Analyzer branch)

## Intent

The maintainer's server should only be used from India. The attackers in the shared logs come from many
countries and mostly try slowly enough to stay under a rule's limit. Each EvlWatcher rule gets an option
**"Only allow addresses from: <countries>"**: a failed attempt from any other country is banned on its
**first** attempt, while addresses from the allowed countries keep the rule's normal limit (e.g. 5 within
60 minutes). This is option A of the conversation; blocking whole countries in the Windows Firewall before
they connect (option B) may follow in a later release.

## Goals

- Per rule, an optional list of allowed countries (ISO 3166 two-letter codes, e.g. `IN`; several allowed:
  `IN, AE`). Empty = off (today's behaviour).
- When set: an address the rule matches whose country is known and **not** in the list gets the rule's
  temporary ban on its first matched event (normal `LockTime`). **These first-attempt country bans do not
  count as strikes towards `PermaBanCount`** (maintainer's decision, option b): mistakes heal themselves
  after the ban length, and the firewall rule only holds currently active foreign attackers. Addresses from
  allowed countries reach permanent bans the normal way.
- Country data from the five regional internet registries' public "delegated" statistics files, refreshed
  by the service about weekly, with a copy shipped in the installer as fallback.
- Console: the option on each rule in the Rules tab (and the rule's Advanced view), and the country data's
  status with an **Update now** button on the Settings tab.

## Non-goals

- Changing Windows Firewall allow rules / blocking countries before they connect (option B, later).
- City/ISP-level geolocation, commercial geo databases, accounts or licence keys.
- Blocking whole countries pro-actively in the EvlWatcher firewall rule.
- A country option in the new-rule wizard (it stays available on the rule afterwards).

## Anti-goals

- Banning anyone because the country data is missing, broken or stale-and-unloadable: then **every rule
  falls back to its normal limit**.
- Overriding the whitelist: whitelisted addresses are never banned, as today.
- Country-banning private, loopback or this machine's own addresses.
- Blocking or slowing the scan loop with downloads.

## Constraints

- Service: .NET Framework 4.7.2, old-style csproj (new `.cs` files listed by hand), `lock (_syncObject)`
  for shared state, logging through `ILogger.Dump`, config writes through `ConfigFile.Save`.
- Contract: add fields only (`[DataMember]`), new operations with `[FaultContract(typeof(ServiceFaultDTO))]`;
  both sides rebuilt (AGENTS.md "IPC").
- Supported OS includes Windows 8.1 / Server 2012: HTTPS downloads must enable TLS 1.2 explicitly
  (`ServicePointManager.SecurityProtocol |= Tls12`).
- The service runs as LocalSystem; outbound HTTPS to the five registries must work through normal
  outbound firewall defaults; no proxy configuration in v1 (system proxy is used by default).

## Approaches considered

1. **Lookup in the service, data downloaded from the five registries + installer copy (chosen).** Free, no
   account, current within a week; needs outbound HTTPS.
2. Installer copy only. No internet needed, but data ages until the next release → new Indian ranges look
   foreign → wrong first-attempt bans. Rejected.
3. Commercial database (MaxMind etc.). Licence key and a third party for no accuracy gain at country level.
   Rejected.
- Doing it in the console was ruled out: only the service sees every attempt.

## Design (decided)

### Data

- Sources (pipe-separated "delegated" format, `registry|cc|type|start|value|date|status`):
  - `https://ftp.apnic.net/stats/apnic/delegated-apnic-latest`
  - `https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest`
  - `https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest`
  - `https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest`
  - `https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest`
- Use lines with type `ipv4` (value = number of addresses) and `ipv6` (value = prefix length) and status
  `allocated` or `assigned`; skip headers, summaries (`*`), comments, and other statuses.
- Files live in `<install dir>\geo\` (next to `config.xml`, writable by LocalSystem). The installer ships a
  snapshot there (downloaded at release build time); on upgrade it overwrites the snapshot only if the
  installed copy is older.
- **Update:** at service start (if the copy is older than 7 days) and then every 7 days, on a background
  timer separate from the scan loop. **Per registry** *(settled after review)*: each file is downloaded to a
  temp file, parsed and validated (at least 1,000 ranges and a valid header) and replaces only its own
  registry's file when valid; a failing registry keeps its previous file and its error is reported in
  `LastError` (e.g. "LACNIC: download failed"). After the run the in-memory lookup is rebuilt from all
  valid files and replaced atomically. On load, a missing or corrupt file is skipped and the others still
  load; `IsLoaded` is true when at least one registry loaded (the Settings line lists which). Global setting
  `<CountryDataAutoUpdate>true</CountryDataAutoUpdate>` (default true; false = installer copy / manual
  update only).
- **Lookup:** `CountryDatabase` holds sorted, non-overlapping ranges (IPv4 as `uint` start/end, IPv6 as two
  `ulong` halves) with binary search → country code or null. Built once per load (a few hundred thousand
  ranges, a few MB). IPv4-mapped IPv6 addresses are looked up as IPv4.
- If no data could be loaded at all, `CountryDatabase.IsLoaded == false` and the filter is inactive.

### Rule behaviour (service)

- `config.xml` per task: optional `<AllowedCountries>IN</AllowedCountries>` (comma-separated codes, upper
  case, trimmed; element missing or empty = off). Read in `XmlTaskConfig`, written back by `SaveRule`.
- `GenericIPBlockingTask` (in `OnComputeEvents`): for each matched IP, the trigger needed is
  `1` when the rule has allowed countries, the database is loaded, the address is not private/loopback/local,
  and its country is known and not in the list; otherwise `TriggerCount`. Unknown country (not in any
  registry file) → normal `TriggerCount`.
- A ban triggered **only** because of the country rule (the address had fewer than `TriggerCount` matches)
  is a temporary ban that does **not** increment `_bannedCount`. If the same address also reaches
  `TriggerCount` in the window, it is a normal ban and counts a strike as today.
- Whitelist handling stays where it is (victims are filtered against the whitelist before banning).
- Log at Info: `"{rule}: banning {ip} on first attempt (country {cc}, rule allows only {list})"`.
- Known effect, explained in the rule details note and the release notes: with the window longer than the
  ban length, a foreign address is banned again as soon as its ban lifts (its event is still in the window),
  so it stays banned for up to window + ban length after its last attempt. It never becomes permanent from
  country bans alone.
- Registry country ≠ user location: users with foreign-registered addresses (cloud regions, VPNs, roaming)
  get first-attempt temporary bans; the whitelist protects them. Stated in the rule details note and the
  release notes.

### Contract (EvlWatcher.WCF)

- `GenericIPBlockingTaskDTO`: new `[DataMember] IList<string> AllowedCountries` (null/empty = off).
  `RuleMapper` maps it both ways; `RuleValidator` rejects anything that isn't two letters A–Z.
- New `CountryDataStatusDTO { bool Loaded; DateTime? UpdatedUtc; int RangeCount; string LastError; bool AutoUpdate }`.
- New operations: `CountryDataStatusDTO GetCountryDataStatus()`, `void UpdateCountryDataNow()` (starts an
  update in the background and returns; status shows the result), `void SetCountryDataAutoUpdate(bool)`.

### Console

- **Rules tab, rule details:** a row under the existing sentences:
  `[x] Only allow addresses from [ IN        ] — others are banned on their first failed attempt.`
  The text box takes codes separated by commas; it shows the country names under it ("India") from a
  small built-in code → name table, and an error for unknown codes. Saved with the rule as today
  (`RuleEditorViewModel`, `SaveRule`).
- Under the row, a short note *(no confirmation dialog — settled after review)*: "Addresses are judged by
  the country they are registered in. Users on cloud servers, VPNs or abroad may get a temporary ban — add
  their addresses to the whitelist. Country bans are temporary and never become permanent on their own."
- If the service reports country data not loaded, the row shows a hint: "Country data isn't available, so
  this rule uses its normal limit for everyone."
- **Settings tab:** "Country data: updated 21/11/2026, 312,000 ranges from 5 registries"
  (or the last error), `[x] Update weekly from the internet registries`, **Update now**.
- **Analyzer:** no change in this release *(checked after review)*: foreign attackers are already
  temp-banned by the service and therefore excluded as "banned"; the addresses it still reports are from
  allowed or unknown countries, for which its window advice stays valid.

### Tests

- Service logic is tested in `EvlWatcher.Tests.Integration` (the only service test project; these tests
  don't touch the firewall and don't need admin):
  - `DelegatedFileParser`: header/summary/comment lines skipped, ipv4 count → range, ipv6 prefix → range,
    `reserved`/`available` skipped, malformed lines skipped.
  - `CountryDatabase`: lookup at range start/end/outside; IPv6; IPv4-mapped; unknown → null; built from
    several registries.
  - `GenericIPBlockingTask`: allowed list `IN`, a foreign address banned after 1 event **without a strike**
    (three country bans in a row never reach `GetPermaBanVictims`), a foreign address reaching
    `TriggerCount` gets a normal strike, an Indian address needs `TriggerCount`, unknown country needs
    `TriggerCount`, database not loaded → `TriggerCount`, private address → `TriggerCount`.
  - Updater: a failed or too-small download keeps that registry's previous file while the others update;
    a corrupt file on load is skipped (fake downloader / temp folder). `InternalsVisibleTo` for
    `EvlWatcher.Tests.Integration` is added if needed.
  - `XmlTaskConfig` / `RuleMapper` round-trip of `AllowedCountries`; validator rejects `IND`, `I1`.
- Console tests (`EvlWatcherConsole.Tests`): rule editor shows country names, rejects unknown codes, saves
  the list; Settings view model shows status and calls Update now.

### Release

v3.3.0 (version files as in AGENTS.md "Releasing"), installer ships `geo\` snapshot and deletes it on
uninstall, NEWS, release notes (explain: outbound HTTPS to the five registries; first-attempt bans; the
re-ban effect), AGENTS.md (country filter section).

## Left to the builder

- Exact parser/lookup data structures, timer mechanics, file names under `geo\`.
- The code → country-name table's source (any public ISO 3166 list embedded in the console).
- Wording polish within the console's style.
