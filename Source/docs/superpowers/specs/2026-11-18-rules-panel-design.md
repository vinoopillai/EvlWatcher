# Rules panel: plain-language rule settings + "paste an event" wizard

Status: draft for approval · 2026-11-18

## Intent

EvlWatcher's power is in its rules, but today they can only be changed by hand-editing `config.xml`: regexes, booster words, event-log names, times in seconds. The console can show a rule but not change it.

This work gives a **non-expert Windows admin** two things in the console:

1. **A settings screen for the existing rules.** They can turn a rule on or off and tune how strict it is, in plain language ("Ban an IP after 5 failed attempts within 2 minutes, for 60 minutes").
2. **A guided wizard to add a rule for a new attack.** They paste an event from Event Viewer and EvlWatcher finds the IP. They confirm it, and the console builds, tests and saves the rule. No regex knowledge is needed.

Saved changes take effect immediately, without restarting the service (option 1, chosen by the user).

## Goals

- Every rule in `config.xml` is listed, **including disabled ones**, with on/off and plain-language thresholds.
- A rule can be created from one pasted event in a few clicks, and the console proves it matches that event before saving.
- Save → the running service picks the change up within one scan cycle, with no service restart.
- Works on everything the console targets: Windows 10 1607+, Windows 11, and Server 2016/2019+ with Desktop Experience. Fluent theme and MDL2-safe glyphs as in AGENTS.md.

## Non-goals

- **Deleting rules.** Disabling is the way to retire one; it's reversible and the shipped defaults stay intact. *(My call: keeps a layman from losing a shipped rule, and `config.default.xml` exists for recovery anyway.)*
- Rules for IPs that appear only inside free text (for example in the middle of a message sentence) rather than as the whole value of an XML element. The wizard detects this case and says so. The existing Rule Tester tab (renamed "Advanced") stays for experts.
- Correlating several events, remote management of other machines, and enabling Windows audit policies.
- Re-ordering rules, rule categories, or import/export.

## Anti-goals (failures even if it "works")

- Saving a rule must **never** clear the firewall rule, drop permanent bans, or touch the whitelist.
- The wizard must never save a rule that doesn't match the event it was built from.
- A typo must never leave the service unable to start. Everything is validated **in the service** before anything is written to `config.xml`.
- Laymen should never have to see a regex unless they open "Advanced".

## Constraints and facts from the code

- **What the service matches.** Rules run against `EventRecord.ToXml()`. That's compact one-line XML with **single-quoted** attributes (`<Data Name='IpAddress'>`). Event Viewer's "XML View" is pretty-printed with **double** quotes. Generated regexes must match both forms; the existing rules use `.` in place of the quote character.
- **Booster words.** An event must contain **all** of a rule's booster words (`GenericIPBlockingTask.cs:134`). The comment in `config.xml` saying "at least one" is wrong, and this design follows the code.
- **What a rule matches.** Capture group 1 must parse with `IPAddress.TryParse`. The regex must have exactly one capture group.
- **Disabled rules.** `GetGlobalConfig()` only returns *running* tasks, so disabled rules are invisible today. Its `Active` flag is also always false, because `GenericIPBlockingTask.FromConfiguration` never sets it.
- **Stopping the scan thread.** When the thread stops it calls `ClearIPBanList()`. Reload must therefore **not** reuse the stop path.
- **Rules load once.** Workers are built once at the top of `Run()`. `XmlServiceConfiguration.Load()` already re-reads the file.
- **Writing rules back.** `XmlTaskConfig` can already write most fields back to `config.xml` through its setters. `Active` is read-only, and there's no way to add a new `<Task>`.
- **The pipe.** The service is .NET Framework 4.7.2 and the console is .NET 10. Contract types must be primitives, strings, arrays or plain DTOs (see AGENTS.md).

## Approaches considered

1. **New service operations with live reload: chosen.** The console sends rule changes over the existing named pipe. The service validates them, writes `config.xml` and rebuilds its rules in-process. A naive rebuild would reset each rule's in-memory state: temporary bans, strike counts toward a permanent ban, and IPs the admin removed by hand. That would lift bans, and could even re-ban an admin's own unbanned IP. So the reload **carries that state over by rule name** (see Live reload). *(My call: it's needed to satisfy the anti-goals. It supersedes the "temporary bans get lifted" trade-off discussed earlier.)*
2. Same operations, but the user restarts the service to apply. Less service code, but an extra step for a layman and the same effect on bans. Rejected.
3. The console edits `config.xml` directly. That makes two writers to one file and bypasses the service's admin check. Rejected.

## Design

### Service (EvlWatcher, EvlWatcher.WCF)

**New contract operations** (each with `EnsureClientPrivileges()` and `[FaultContract(typeof(ServiceFaultDTO))]`):

| Operation | Behaviour |
|---|---|
| `GenericIPBlockingTaskDTO[] GetRules()` | All rules from `config.xml` (via `_serviceconfiguration.TaskConfigurations`), enabled and disabled, with the correct `Active`. |
| `void SaveRule(GenericIPBlockingTaskDTO rule, bool isNew)` | Validates, then creates (`isNew`) or updates the `<Task>` with that name, then requests a reload. |
| `void SetRuleActive(string taskName, bool active)` | Writes the `Active` attribute, then requests a reload. |

- **Validation** (rejects with a `ServiceFaultDTO` carrying a new `ServiceErorCode.invalidRule` and a human-readable message the console shows as-is):
  - The name is non-empty, at most 64 characters and unique on create. It must exist on update, and it can't be renamed.
  - The regex compiles and has exactly one capture group.
  - `TriggerCount ≥ 1`, `EventAge ≥ 10` s, `LockTime ≥ 60` s.
  - `PermaBanCount ≥ 1`, **or negative, meaning "never ban permanently"**, the existing documented behaviour (`if (PermaBanCount >= 0)`). `0` is rejected, because the code would make the first temporary ban permanent. *(My call: keeps an existing feature, and an unrelated edit to a rule set to "never" must not fail validation.)*
  - At least one event log. **Only `SaveRule(isNew: true)` requires every log to exist on this machine** (`EventLogSession.GlobalSession.GetLogNames()`). Updates and `SetRuleActive` don't, because many shipped rules read logs that only exist when that software is installed (OpenSSH, IIS, SMB, RdpCoreTS), and the service already skips them quietly at runtime. *(My call.)*
  - At least one booster, none empty.
- **`GenericIPBlockingTaskDTO` gains `IList<string> MissingEventLogs`.** `GetRules()` fills it with the rule's event logs that don't exist on this machine, so the console can show "log not on this machine". It's ignored on save.
- **Persistence:**
  - Add `IPersistentServiceConfiguration.AddTask(...)` and make `IPersistentTaskConfiguration.Active` settable. Both write through to `config.xml` under the existing `_syncObject` lock.
  - New `<Task>` elements use the same layout as the existing ones (`Description`, `LockTime`, `OnlyNew`, `EventAge`, `TriggerCount`, `PermaBanCount`, `EventPath`, `RegexBoosters/Booster*`, `Regex`). Element text is escaped by `XElement`.
  - Update `config.xml`'s comment about boosters to say "all must be contained".
- **Live reload:**
  - Add a `_reloadRequested` flag next to `_stop`. `RequestReload()` sets it under `_syncObject` and calls `_workerThread.Interrupt()`.
  - Restructure `Run()` as an outer loop: `{ Load config; clear _logTasks; InitWorkersFromConfig; build the per-log dictionaries; inner scan loop }`. The inner loop exits to the outer one when `_reloadRequested` is set, which then clears the flag. Only `_stop` reaches the existing `ClearIPBanList()` exit.
  - `_logTasks` is read by WCF calls (`RemoveTemporaryBan`, `GetGlobalConfig`), so replacing it happens under `_syncObject`.
  - **State carry-over.** Each rule keeps three pieces of state in `GenericIPBlockingTask`:
    - `_blockedIPsToDate`: its temporary bans.
    - `_bannedCount`: strikes toward a permanent ban.
    - `_forgetIPsToDate`: IPs the admin removed by hand.
    
    Every rule is rebuilt on any save or toggle, not just the edited one. So when a rule with the same name exists both before and after the reload, the new task takes over the old task's three maps. Add an internal `CarryOverStateFrom(GenericIPBlockingTask previous)` for this. Rules that were removed or disabled drop their state. A rule that's re-enabled starts fresh. A changed `LockTime` applies to the carried-over bans from the next scan on, because expiry is computed at check time.
  - Permanent bans and the whitelist live in config/global state and survive a reload untouched. The firewall rule is only changed by the normal `PushBanList()` after the first post-reload scan. With state carried over, that push should normally change nothing.
- **Small fixes on the way:**
  - `GetGlobalConfig()` reports the real `Active` value (set `Active` in `FromConfiguration`).
  - `SaveGlobalConfig()` gets the missing `EnsureClientPrivileges()`.

### Console (EvlWatcherConsole)

**Tabs:** Bans & Whitelist · Live · **Rules** (new) · Settings · **Advanced** (the current Rule Tester, renamed and unchanged).

**Rules tab, list and details:**

```
┌ Rules ─────────────────────────┬──────────────────────────────────────────────┐
│ [+ New rule from an event]     │ RDP logins (Security 4625)        [● On ]    │
│                                │ Checks the Security log for failed attempts. │
│ ● RDP logins (Sec. 4625)       │                                              │
│ ● RDP (RdpCore 140)            │ Ban an IP after [ 5 ] failed attempts        │
│ ○ MariaDB              off     │ within [ 2 ] minutes.                        │
│ ● SSH (OpenSSH)                │ Ban it for [ 60 ] minutes.                   │
│ …                              │ Ban permanently after [ 3 ] temporary bans.  │
│                                │                                              │
│                                │ ▸ Advanced (event log, booster words, regex) │
│                                │                          [Discard] [Save]    │
└────────────────────────────────┴──────────────────────────────────────────────┘
```

- **The list** shows every rule from `GetRules()`, with an on/off dot and the description's first line as subtitle. Disabled rules are dimmed. Rules with `MissingEventLogs` show a small "log not on this machine" note. They can still be edited and toggled, and a tooltip explains that they have no effect here until that software is installed.
- **Permanent bans:** "Ban permanently after [ 3 ] temporary bans" has a **"Never ban permanently"** checkbox next to it. Ticking it stores `-1` and disables the number box.
- **On/off** is a toggle that saves immediately through `SetRuleActive`, with no Save click. A toast-style status line confirms it: "Rule applied. EvlWatcher reloaded its rules."
- **Thresholds** are number boxes in **minutes** in the UI. They're converted to seconds for `EventAge` and `LockTime`, and shown with a sentence around them as above. Save/Discard appear only when something changed, mirroring the Settings tab's edit model.
- **"Advanced"** is an expander, collapsed by default. It holds the event log(s), booster words (one per line), regex, and "only check new events" (`OnlyNew`), with the existing config.xml hint text for each. It's editable, validated by the service on save.
- **Errors** from the service are shown inline above Save, verbatim.
- **Refresh:** after any save the list reloads from `GetRules()`. Selection is kept by name.

**New rule wizard.** It opens in place of the details pane, three steps with a step indicator, Back/Next and Cancel.

1. **Paste the event.** "In Event Viewer, open the failed-login event → Details → XML View, select all and copy." There's a big monospace box. Next is disabled until the text parses as XML with an `<Event>` root (namespace-insensitive). Parse failure: "That doesn't look like an event's XML. Make sure you copied it from the XML View."
2. **Pick the attacker's IP.**
   - The console scans every **leaf element** under `EventData` **and** `UserData`, and lists each one whose whole trimmed value parses as an IP, as "**203.0.113.7**, found in *IpAddress*". The field label is the `Name` attribute for `<Data Name="…">`, otherwise the element name, for example *Address* in `<UserData><EventXML><Address>`. *(My call: covers structured `UserData` events such as the RdpCoreTS/TerminalServices ones at little extra cost.)*
   - Loopback and unspecified addresses (`127.0.0.1`, `::1`, `0.0.0.0`, `-`) are listed greyed, with "this is your own machine, not an attacker". If exactly one usable IP exists it's preselected.
   - **No named field holds an IP:** "EvlWatcher can't build a rule from this event automatically. Use the Advanced tab, or open a GitHub issue with this XML." Next stays disabled.
   - **Already covered:** before showing step 2, the console runs every *enabled* rule against the pasted event. If one already extracts an IP, it says "Already covered by rule *X*", with Continue anyway and Go to rule.
3. **Review and save.** Prefilled and editable in plain language:
   - **Name:** `{Provider short name} {EventID}`, for example "Security-Auditing 4625", made unique with a ` (2)` suffix if needed.
   - **Description:** "Bans IPs found in {Field} of event {EventID} from {Provider}."
   - **Thresholds:** 5 attempts / 2 minutes / 60 minutes / permanent after 3. These match the shipped rules.
   - **Generated** (shown under "Advanced", collapsed):
     - Event log = `<System><Channel>`.
     - Boosters = the provider name **and** `>{EventID}</EventID>`. That second form matches both `<EventID>4625</EventID>` and `<EventID Qualifiers='…'>4625</EventID>`.
     - Regex: for `<Data Name="X">` it's `<Data Name=.X.>([0-9A-Fa-f:.]+)</Data>`. For any other element `E` it's `<E(?:\s[^>]*)?>([0-9A-Fa-f:.]+)</E>`. Names are regex-escaped. A namespace prefix on the element, if present in the paste, is matched literally. The capture is validated by `IPAddress.TryParse` at match time, exactly like the service does.
   - **Self-test (anti-goal guard):** before Save is enabled, the console runs the generated boosters and regex the same way `GenericIPBlockingTask` does, against two forms of the event: the pasted text, and a **compact single-quote form** it produces from the parsed XML (`XDocument` → single line, attributes single-quoted, mimicking `ToXml()`). Both must yield the chosen IP. It shows "✓ This rule finds 203.0.113.7 in your event."
   - **Save:** `SaveRule(…, isNew: true)` is called. On success the wizard closes and the new rule is selected in the list, with the status line "Rule added and active."

**Code organisation:**

- **Pure logic** goes in a new `EvlWatcherConsole/Rules/RuleBuilder.cs`: parse the event, find IP candidates, build name, boosters and regex, build the compact form, run the self-test, and check which existing rule matches. It has no WPF or WCF dependencies.
- **View-models:**
  - `RulesViewModel`: list, selection, edit buffer, save/discard, toggle.
  - `NewRuleWizardViewModel`: step state.
  - Both are exposed from `MainWindowViewModel`, which keeps its existing refresh timer. The Rules tab **doesn't** auto-refresh while a rule is being edited or the wizard is open, the same pattern as `IsInGlobalEditMode`.
- **Model:** `EvlWatcherModel` gets `GetRules`, `SaveRule` and `SetRuleActive`.
- **Unit tests:** a new `EvlWatcherConsole.Tests` (MSTest, `net10.0-windows`) covers `RuleBuilder`, using real event samples. That means at least Security 4625 (pretty-printed and compact), an IPv6 event, an event with `-` as IP, an event with the IP only in free text, a `UserData` event (for example RdpCoreTS), and an `EventID` with `Qualifiers`. These run without admin rights.
- **Service tests:** the state carry-over (temporary bans, strike counts and hand-removed IPs survive a reload, and an unbanned IP isn't re-banned) is testable without admin rights against `GenericIPBlockingTask` directly. Add it to a new non-integration test project for the service, or to the existing one if no firewall access is needed.

## Left to the builder

- Exact control choices (ToggleButton vs CheckBox styled as a switch), spacing and wording polish, consistent with the existing Fluent styling and AGENTS.md's UI rules.
- Whether the wizard is a `UserControl` swapped into the details pane or a `ContentControl` with templates per step.
- Provider "short name" derivation (for example strip `Microsoft-Windows-`).
- Updating AGENTS.md (new contract operations, reload behaviour, the booster "all" semantics) and the README console section.
