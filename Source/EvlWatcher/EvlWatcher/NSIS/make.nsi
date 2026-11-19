; Build inputs: put these next to this script before compiling it with makensis
; (requires the nsSCM plugin):
;   EvlWatcher.exe, EvlWatcher.WCF.dll, config.xml, license.txt, EvlWatcher.ico
;       -> from Source\EvlWatcher\EvlWatcher\bin\Release\  (msbuild, .NET Framework 4.7.2)
;   EvlWatcherConsole.exe
;       -> from Source\EvlWatcherConsole\EvlWatcherConsole\bin\publish\
;          dotnet publish -c Release -p:PublishProfile=Installer
;          (single-file, framework-dependent, win-x64: needs the .NET 10 Desktop Runtime)
;
; Supported targets: 64-bit Windows 10 (1607+), Windows 11, Windows Server 2016/2019/2022/2025
; with Desktop Experience. The service itself only needs .NET Framework 4.7.2.
;
; Compile with NSIS 3.x: put nsSCM.dll (https://nsis.sourceforge.io/NsSCM_plug-in) into
; <NSIS>\Plugins\x86-ansi, then run:  makensis make.nsi

; nsSCM only exists as an ANSI plugin, and NSIS 3 builds Unicode installers by default.
Unicode false

Name "EvlWatcher"

!define DOTNET_DOWNLOAD_URL "https://dotnet.microsoft.com/download/dotnet/10.0"

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

  ; The console (not the service) needs the .NET 10 Desktop Runtime (x64).
  ; Only warn: the service still installs and protects the machine without it,
  ; and silent (/S) rollouts must not stop here.
  FindFirst $0 $1 "$PROGRAMFILES64\dotnet\shared\Microsoft.WindowsDesktop.App\10.*"
  FindClose $0
  StrCmp $1 "" 0 dotnet_found   ; $1 = first matching version folder, empty if none
    DetailPrint "Warning: .NET 10 Desktop Runtime (x64) not found. EvlWatcherConsole will not start until it is installed."
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "EvlWatcherConsole needs the .NET 10 Desktop Runtime (x64), which is not installed.$\r$\n$\r$\nThe EvlWatcher service will still be installed and run normally.$\r$\n$\r$\nOpen the download page now?" /SD IDNO IDNO dotnet_found
    ExecShell "open" "${DOTNET_DOWNLOAD_URL}"
  dotnet_found:

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
  Delete $INSTDIR\EvlWatcher.WCF.dll


  Delete $INSTDIR\uninstall.exe

  ; Remove directories used
  RMDir "$INSTDIR\Source"
  RMDir "$INSTDIR"

SectionEnd