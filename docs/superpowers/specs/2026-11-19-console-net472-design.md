# EvlWatcherConsole on .NET Framework 4.7.2 (Windows 7 onwards)

Date: 2026-11-19 · Target release: v3.1.0

## Intent

EvlWatcher must be usable from **Windows 7 SP1 / Server 2008 R2 SP1 onwards**. Today the
console (WPF, `net10.0-windows`) needs the .NET 10 Desktop Runtime, which does not exist for
Windows 7 and is not part of any Windows install. The service already runs on .NET Framework
4.7.2. Moving the console to the same framework means one prerequisite for the whole product,
and on Windows 10 1803+ / 11 / Server 2019+ that prerequisite is already built in.

The console must keep the look shipped in v3.0 (cards, count badges, icon buttons, underlined
tabs). Option **B** from the mockups (https://claude.ai/artifact/HQNSRsXSpLAaBCzS1TcUgs) was
chosen: our own flat light theme that renders the same on every Windows version.

## Goals

- Console targets **.NET Framework 4.7.2** and runs on Windows 7 SP1, 8.1, 10, 11 and
  Server 2008 R2 SP1, 2012, 2012 R2, 2016, 2019, 2022, 2025 (Desktop Experience), 32- and 64-bit.
- Same layout, behaviour and features as v3.0.2: all five tabs, Rules tab, new-rule wizard.
- Own light theme in `App.xaml` replacing the Fluent theme; looks like the v3.0 console in light mode.
- Icons drawn as vector geometry (no icon fonts), identical on every OS.
- Installer checks for .NET Framework 4.7.2 (needed by service **and** console) instead of .NET 10.
- All existing console unit tests keep passing, now running on .NET Framework.

## Non-goals

- Dark mode. Windows 7 has none and .NET Framework WPF does not follow the Windows setting.
  The theme is built on brush resources so a dark palette can be added later.
- Server Core support for the console (WPF needs Desktop Experience; unchanged).
- Windows Vista, Server 2008 (non-R2), Windows 8.0: .NET 4.7.2 can't be installed there.
- Changing the WCF contract, the service's behaviour or the rules.

## Anti-goals

- A console that starts but shows empty boxes for icons, or falls back to grey classic
  controls on some OS. Every control the app uses must be styled by our theme.
- Making the installer fail or block silent (`/S`) rollouts when .NET 4.7.2 is missing;
  it warns and offers the download, as it does today for .NET 10.
- Breaking upgrades: existing `config.xml` is still kept.

## Constraints

- .NET Framework 4.8 is the newest .NET on Windows 7; 4.7.2 is chosen to match the service.
- C# language: SDK-style project on net472 defaults to C# 7.3. Code must compile with it
  (repo convention is C# 7.x style anyway).
- Fonts: Windows 7 has Segoe UI, Consolas, Courier New. It has **no** Segoe MDL2 Assets,
  Segoe Fluent Icons or Cascadia Mono.
- The two solutions stay independent: the console keeps compiling the WCF contract from source.
- Build stays `dotnet build` for the console (SDK-style project targeting net472 with
  `UseWPF`); the service keeps building with .NET Framework MSBuild.

## Approaches considered

1. **Self-contained .NET 10 console.** No runtime install, keeps Fluent. Rejected: .NET 7+
   does not run on Windows 7 at all.
2. **Console on .NET Framework 4.7.2, native look (A).** Least work, but looks dated and
   different on each Windows version.
3. **Console on .NET Framework 4.7.2, own flat theme (B).** Chosen: one prerequisite shared
   with the service, same look everywhere, keeps the v3.0 UI.

## Design (decided)

### Project

- `EvlWatcherConsole.csproj`: `TargetFramework` → `net472`, keep `UseWPF`, drop the
  `System.ServiceModel.NetNamedPipe` package, add framework references `System.ServiceModel`
  and `System.Runtime.Serialization`. `EvlWatcherModel`'s `ChannelFactory`/`Call` pattern is
  unchanged (always close or abort each channel).
- Platform `AnyCPU` so it runs on 32- and 64-bit Windows 7.
- `app.manifest`: add `supportedOS` entries for Windows 7, 8, 8.1, 10/11 and DPI awareness
  (system-aware), keep `requireAdministrator`.
- Code fixes for APIs missing on .NET Framework: `string.Contains(string, StringComparison)`
  (use `IndexOf(...) >= 0`), `string.Contains(char)`, `Split(char)` overloads, plus anything
  else the compiler reports.
- Add an `App.config` with `<supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2"/>`
  so the build always emits `EvlWatcherConsole.exe.config`. *(Builder's call.)*
- Delete `Properties/PublishProfiles/Installer.pubxml`; the installer takes
  `EvlWatcherConsole.exe` and `EvlWatcherConsole.exe.config` from `bin\Release\net472\`.

### Theme (`App.xaml`, plus a `Themes/Light.xaml` dictionary if `App.xaml` gets too long)

- Brush resources **under the same keys** the views already use, so views barely change:
  `TextFillColorPrimaryBrush`, `TextFillColorSecondaryBrush`, `TextFillColorDisabledBrush`,
  `SystemFillColorSuccessBrush`, `SystemFillColorCriticalBrush`,
  `CardBackgroundFillColorDefaultBrush`, `CardStrokeColorDefaultBrush`,
  `ControlFillColorSecondaryBrush`, `DividerStrokeColorDefaultBrush`, and an accent brush.
- Text styles that came from Fluent: `BodyStrongTextBlockStyle`, `CaptionTextBlockStyle`,
  plus `AccentButtonStyle`.
- Implicit styles (with control templates) for every control type in use: `Window`,
  `TabControl`/`TabItem` (underline on the selected tab), `Button`, accent button,
  icon button, `TextBox`, `CheckBox`, `ComboBox`, `ListView`/`ListBox` and their items
  (selection = light blue fill with an accent bar), `ScrollViewer`/`ScrollBar`, `Expander`,
  `ToolTip`. Focus visuals must stay visible for keyboard use.
- Font: Segoe UI throughout; monospace text uses `Consolas, Courier New` (drop Cascadia Mono).
- Colours match the mockup's option B.

### Icons

- One `Geometry` resource per icon in use today (Add, Cancel, Lock, Unlock, Settings, Play,
  tab icons, and the rest of the current glyph set: E70F, E710, E711, E713, E72C, E72E, E768,
  E785, E8FD, E943, E9D9, EA18), drawn with `Path` and `Stretch="Uniform"`.
- `IconButtonStyle` / `IconTextStyle` switch from font glyphs to a `Path` whose `Data` comes
  from the button's `Tag` (or `Content`), so call sites change from `Content="&#xE710;"` to
  `Tag="{StaticResource AddIcon}"`. ToolTips and `AutomationProperties.Name` stay.
- Glyphs that today sit in a `TextBlock` with `IconTextStyle` (tab headers, Edit/Test/Reset,
  "New rule from an event") become a `Path` (via an `IconPathStyle`) in the same spot.
  *(Builder's call.)*

### Tests

- `EvlWatcherConsole.Tests` → `net472`; MSTest packages stay (they support .NET Framework).
  Turn off `ImplicitUsings` (needs C# 10) and add explicit `using`s. *(Builder's call.)*
- All existing tests keep passing; no new behaviour, so no new tests, except a test that loads
  `App.xaml` resources and checks every key the views reference exists (catches a missing
  style that would otherwise show only at runtime).

### Installer (`NSIS/make.nsi`)

- Replace the .NET 10 check with a .NET Framework 4.7.2 check:
  `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` `Release` ≥ 461808.
  If missing: warn (DetailPrint + Yes/No message box with `/SD IDNO`) that neither the service
  nor the console will run until it is installed, offer the download page, keep installing.
- Package `EvlWatcherConsole.exe` and `EvlWatcherConsole.exe.config`.
- Update the header comment (inputs, supported OS list).

### Docs and release

- AGENTS.md: console section (net472, own theme, vector icons, no Fluent/`DynamicResource`
  font glyphs), build commands, deployment targets, publishing steps.
- README / NEWS / release notes: supported OS list (Windows 8.1 / Server 2012 and later for
  3.1.0, see Release staging), ".NET 10 no longer needed".
- Version 3.1.0 in both `AssemblyInfo.cs`, window title, `make.nsi` `OutFile`, README link.

## Release staging (decided)

- **3.1.0** ships when the work is done and tested on Windows 10/11. Its docs and release notes
  claim **Windows 8.1 / Server 2012 and later**. The build itself already runs on .NET 4.7.2, so
  nothing in the code excludes Windows 7.
- **Windows 7 SP1 / Server 2008 R2** are announced in a later **3.1.x**, after the maintainer's
  VM test passes. Any service fix Windows 7 needs goes into that 3.1.x, not 3.1.0.
- Signing stays **SHA-256 only** (`Set-AuthenticodeSignature`, as today). When Windows 7 /
  2008 R2 are announced, the release notes say those systems need update **KB4474419** (SHA-2
  code signing) for the installer's signature to show as valid.
- The installer warning and the release notes say that installing .NET 4.7.2 on Windows 7 SP1 /
  Server 2008 R2 / Server 2012 needs update **KB4019990** first.

## Verification

- Build both solutions; run service integration tests (elevated, dev machine) and console tests.
- Manual smoke test on Windows 11 (or 10) by the builder: every tab, the wizard, a rule save.
- **Windows 7 SP1 and Server 2008 R2 VM test by the maintainer** (not possible on the dev box),
  before the 3.1.x that announces them: install, service starts, a 4625 rule bans an IP,
  console opens and shows icons correctly.

## Left to the builder

- Exact colour values, paddings and control templates, as long as they match mockup B.
- Whether the theme lives in `App.xaml` or a separate dictionary.
- Icon path data (any clean 16×16 outline set drawn in-house; no font or third-party assets
  with unclear licences).
