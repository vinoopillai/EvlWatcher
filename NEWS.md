## NEWS 

### 2026-11-21 preparing the release of v3.4.0
- Bans & Whitelist tab: one search box filters the temporary bans, permanent bans and whitelist as you type (e.g. 203.0.113 or 192.168)
- status bar: the service's latest activity (e.g. "3 min ago: Temporarily banning 203.0.113.7") and the age of the IP country data, amber when it is missing or over 14 days old

### 2026-11-21 preparing the release of v3.3.0
- new per-rule option "Only allow addresses from: IN" (any country codes): a failed attempt from another country is banned on the first try instead of after the rule's limit
- these country bans are temporary and never become permanent on their own; addresses from the allowed countries keep the rule's normal limits
- country data comes from the five internet registries, ships with the installer and is refreshed weekly by the service (status and "Update now" on the Settings tab)

### 2026-11-21 preparing the release of v3.2.0
- new "Analyzer" tab: scans this server's event logs for the last 24 hours, 7 days or 30 days and lists risks in plain language
- finds attackers that weren't banned (including slow ones that stay under a rule's window) and offers one-click "Ban permanently", "Ban all" and "Widen rule window" after a confirmation
- flags possible break-ins (a successful logon after failed attempts), a cleared Security log, new services, users and admin-group members, and account lockouts
- flags server problems that slow or break the server: disk and file-system errors, crashes, unexpected restarts, low memory or disk space, a full Security log

### 2026-11-19 preparing the release of v3.1.0
- the console no longer needs the .NET 10 Desktop Runtime: it runs on .NET Framework 4.7.2, like the service, which is built into Windows 10 1803+, 11 and Server 2019+
- supported on Windows 8.1 / Server 2012 and later (32- or 64-bit); Windows 7 / Server 2008 R2 will follow once tested
- same look as v3.0 in light mode, with its own theme and vector icons; dark mode was dropped

### 2026-11-19 preparing the release of v3.0.2
- SQL Server rule catches every failed login (event 18456), not only wrong passwords; existing installs: update the rule (see release notes)
- the new-rule wizard accepts XML copied from Event Viewer with "- " markers

### 2026-11-19 preparing the release of v3.0.1
- fixes the console making the service stop answering after 1-2 minutes (Rules tab stuck on "Loading rules..."): the console now closes every connection to the service

### 2026-11-18 preparing the release of v3.0
- new "Rules" tab: switch rules on/off and tune them in plain language
- new "New rule from an event" wizard: paste an event, EvlWatcher finds the IP and builds, tests and saves the rule
- rule changes apply live, without restarting the service, and keep existing bans
- console moved to .NET 10 with a Fluent look (needs the .NET 10 Desktop Runtime); upgrades keep your config.xml

### 2024-05-23 release of v.2.1.62 was completed
- that heisenbug that caused "enumeration changed" errors was fixed
- turns out, the bug was difficult to reproduce because it happens exactly one hour after manually removing ips from the temporary ban list
- thanks for reporting the stacktrace

### 2024-05-05 release of v.2.1.61 was completed
- adds better support for location errors (stacktrace)
- displays version number correctly

### 2024-01-20 release of v.2.1.6 was completed
- adds support for some more protocols (MariaDB, SQLServer, SMB Server, .)
- you can now copy IPs into the clipboard by pressing Ctrl+C
- fixes a bug in the whitelist 

### 2022-04-14 release of v.2.1.5 was completed
- fixes a bug where a windows misbehaviour could return 0.0.0.0 as offending IP, thus blocking all subnets
- try to fix a bug where a false positive warning about tasks taking too long are spamming the event logs of EvlWatcher

### 2022-01-22 release of v.2.1.4 was completed
- basic ipv6 support
- certificate was renewed

### 2021-06-03 release of v.2.1.3 was completed
- a negative perma-ban setting means that perma banning is disabled 
- whitelisted ips will - though they are not really banned - no longer show up in the temp ban list of the console
- there is now a button that will add all temporary bans to the permanent ban list 
- will now protect openssh out of the box
- fixed a potential security issue (unqoted service path)
- tasks that rely on log sources that are not present are now disabled, instead of throwing an error on every iteration (30 secs default)

### 2021-06-03 release of v.2.1.2 was completed
- a small typo in the license was fixed
- severity of some messages was adjusted (moved from info to verbose) to keep a cleaner event log
- it contains minor bugfixes and corrections, but nothing interesting apart from that its signed now.
- the console app now has a start menu entry
- the console app had some beauty fixes
- added ability to remove temp bans
- fixes a bug with forgetting ips
- replaces te old 'middle finger' with a more safe for work image

### 2020-12-28 preparing the release of v2.1 
- first, i want to say THANK YOU, to everyone who donated
- finally, we have received enough donations, so we can sign the next release. (and afford 3 beers on top of that)
- it contains minor bugfixes and corrections, but nothing interesting apart from that its signed now.
- it is planned to be released in mid-January, depending on when the dongle from certum.eu arrives (it's already ordered) [update 2021-01-06: still waiting for it]
  

### 2020-11-10 release of v2.0 finally complete
- So, this was about time that software got a new paint applied. The release of EvlWatcher 2.0 could finally be made, many thanks go to NukeDev and shimuldn.
- And it gives you a Windows Defender warning right away. What the heck? Damn we urgently need to fix that.
- You can get the whole story of the release [here](https://github.com/devnulli/EvlWatcher/pull/31), or you just check the [release notes](https://github.com/devnulli/EvlWatcher/blob/master/Versions/v2/EvlWatcher-v2.0%20release%20notes.txt)
- YEAH! I'm pretty pleased it's finally finished. I was procrastenating that for over a year after I promised it.
