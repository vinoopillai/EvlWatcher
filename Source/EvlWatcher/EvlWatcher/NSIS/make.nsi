; Build inputs: put these next to this script before compiling it with makensis
; (requires the nsSCM plugin):
;   EvlWatcher.exe, EvlWatcher.WCF.dll, config.xml, license.txt, EvlWatcher.ico
;       -> from Source\EvlWatcher\EvlWatcher\bin\Release\  (msbuild, .NET Framework 4.7.2)
;   EvlWatcherConsole.exe, EvlWatcherConsole.exe.config
;       -> from Source\EvlWatcherConsole\EvlWatcherConsole\bin\Release\net472\
;          dotnet build Source\EvlWatcherConsole\EvlWatcherConsole.sln -c Release
;
; Supported targets: Windows 8.1 / Server 2012 and later (32- or 64-bit) with Desktop Experience.
; Service and console need .NET Framework 4.7.2 (built into Windows 10 1803+, 11 and Server 2019+).
;
; Compile with NSIS 3.x: put nsSCM.dll (https://nsis.sourceforge.io/NsSCM_plug-in) into
; <NSIS>\Plugins\x86-ansi, then run:  makensis make.nsi

; nsSCM only exists as an ANSI plugin, and NSIS 3 builds Unicode installers by default.
Unicode false

Name "EvlWatcher"

!define DOTNET_DOWNLOAD_URL "https://dotnet.microsoft.com/download/dotnet-framework/net472"

; The file to write
Icon EvlWatcher.ico
OutFile "EvlWatcher-v3.0.2-setup.exe"

; The default installation directory
InstallDir $PROGRAMFILES\EvlWatcher

; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically)
InstallDirRegKey HKLM "Software\EvlWatcher" "InstallDir"

; Request application privileges
RequestExecutionLevel admin

;--------------------------------

LicenseText "By using this software, you agree to the following:"
LicenseData "license.txt"

; Pages

Page license
Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------

; The stuff to install
Section "EvlWatcher Service"

  SectionIn RO
  
  nsSCM::Stop /NOUNLOAD "EvlWatcher"
  nsSCM::Remove /NOUNLOAD "EvlWatcher"

  Sleep 5000

  ;;;;;;;;MODULES HERE;;;;;;;;;;

  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

  Delete $INSTDIR\EvlWatcher.exe
  Delete $INSTDIR\license.txt
  Delete $INSTDIR\EvlWatcherConsole.exe
  Delete $INSTDIR\EvlWatcherConsole.exe.config
  Delete $INSTDIR\EvlWatcher.WCF.dll
  ; config.xml is deliberately NOT deleted: it holds the admin's bans, whitelist and rule tweaks.

  ; Set output path to the installation directory.
  SetOutPath $INSTDIR

  ; Put file there

  File "EvlWatcher.exe"
  File "license.txt"
  File "EvlWatcher.WCF.dll"

  ; Fresh install: ship the default config. Upgrade: keep the existing one untouched.
  SetOverwrite off
  File "config.xml"
  SetOverwrite on

  ; Always refresh a copy of this version's defaults, so admins can compare it with
  ; their config.xml and pick up new or improved rules.
  File "/oname=config.default.xml" "config.xml"
  File "EvlWatcherConsole.exe"
  File "EvlWatcherConsole.exe.config"

  ; The service and the console both need .NET Framework 4.7.2 or later (Release >= 461808).
  ; Built into Windows 10 1803+, 11 and Server 2019+; older systems need it installed.
  ; Only warn: silent (/S) rollouts must not stop here, and it can be installed afterwards.
  ReadRegDWORD $0 HKLM "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release"
  IntCmp $0 461808 netfx_found netfx_missing netfx_found
  netfx_missing:
    DetailPrint "Warning: .NET Framework 4.7.2 not found. The EvlWatcher service and console will not run until it is installed."
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "EvlWatcher needs .NET Framework 4.7.2 or later, which is not installed.$\r$\n$\r$\nNeither the EvlWatcher service nor the console will run until it is installed. On Windows Server 2012 (and Windows 7 / Server 2008 R2), install update KB4019990 first.$\r$\n$\r$\nOpen the download page now?" /SD IDNO IDNO netfx_found
    ExecShell "open" "${DOTNET_DOWNLOAD_URL}"
  netfx_found:

  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\EvlWatcher "Install_Dir" "$INSTDIR"
  
  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "DisplayName" "EvlWatcher"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "Publisher" "Michael Schoenbauer"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "Version Major" 3
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "Version Minor" 0
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "DisplayIcon" '"$INSTDIR\EvlWatcher.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "Estimated Size" 3400
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher" "NoRepair" 1
  WriteUninstaller "uninstall.exe"
  
  nsSCM::Install /NOUNLOAD "EvlWatcher" "EvlWatcher service" 16 2 "$\"$INSTDIR\EvlWatcher.exe$\"" "" "" "" ""
  nsSCM::Start /NOUNLOAD "EvlWatcher"

SectionEnd

Section "Start Menu Entry"

  CreateDirectory "$SMPROGRAMS\EvlWatcher"
  CreateShortCut "$SMPROGRAMS\EvlWatcher\EvlWatcherConsole.lnk" "$INSTDIR\EvlWatcherConsole.exe"

SectionEnd

;;;;;;;MODULES HERE;;;;;;;;;;



;;;;;;;;;;;;;;;;;;

;--------------------------------

; Uninstaller

Section "Uninstall"
  
  nsSCM::Stop /NOUNLOAD "EvlWatcher"
  nsSCM::Remove /NOUNLOAD "EvlWatcher"

  Sleep 5000

	Delete "$SMPROGRAMS\EvlWatcher\EvlWatcherConsole.lnk"
	rmDir "$SMPROGRAMS\EvlWatcher"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EvlWatcher"
  DeleteRegKey HKLM SOFTWARE\EvlWatcher

  ; Remove files and uninstaller

  ;;;;;;;;MODULES HERE;;;;;;;;;;;

  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

  Delete $INSTDIR\EvlWatcher.exe
  Delete $INSTDIR\license.txt
  Delete $INSTDIR\config.xml
  Delete $INSTDIR\config.default.xml
  Delete $INSTDIR\EvlWatcherConsole.exe
  Delete $INSTDIR\EvlWatcherConsole.exe.config
  Delete $INSTDIR\EvlWatcher.WCF.dll


  Delete $INSTDIR\uninstall.exe

  ; Remove directories used
  RMDir "$INSTDIR\Source"
  RMDir "$INSTDIR"

SectionEnd