@echo off

rem This is Version 3.0 of this Script
rem Be careful when running this; it's liable to mess something up.

echo Checking Administrator Privileges..
SETLOCAL EnableDelayedExpansion
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do     rem"') do (
  set "DEL=%%a"
)

cls

sc start LanManServer >Nul
net session >Nul
if %errorlevel%==0 (
	echo Admin rights granted!
	goto :main
) else (
	echo Startup failed, no rights granted.
	goto :exit
)

:main
echo.
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
call :colorEcho 0b " AAST CyberPatriot Script v3.0"
echo.
call :colorEcho 0b "   Written by Isaac Fletcher"
echo.
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo 1. Begin Configurations

echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
call :colorEcho 0a "  Individual Configurations"
echo.
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

echo 2. Configure Account Policies
echo 3. Configure Rights Assignement (requires setup)
echo 4. Configure Firewall
echo 5. Configure AutoUpdate
echo 6. Configure Services
echo 7. Configure Security Policies
echo 8. Configure Audit Policies
echo 9. Configure LGPO
echo 10. Configure Windows Features (wait for restart)
echo 11. Miscellaneous Configurations
echo 12. System Scanning
echo.
echo 20. Exit
echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo.
set /p answer=Please choose an option: 
	if "%answer%"=="1" goto :setup
	if "%answer%"=="2" goto :accounts
	if "%answer%"=="3" goto :rights
	if "%answer%"=="4" goto :firewall
	if "%answer%"=="5" goto :autoupdate
	if "%answer%"=="6" goto :services
	if "%answer%"=="7" goto :security
	if "%answer%"=="8" goto :audit
	if "%answer%"=="9" goto :lgpo
	if "%answer%"=="10" goto :features
	if "%answer%"=="11" goto :misc
	if "%answer%"=="12" goto :scanning
	if "%answer%"=="20" (
		goto :exit 
	) ELSE (
		goto :exit
	)
pause

:setup
SETLOCAL
set /a full = 1

echo Have you done the Forensics Questions? (do so if not already)
pause
echo Is NTRights.exe on the Desktop? (do so if not already)
pause
echo Is the Group Policy config file on the Desktop? (do so if not already)
pause
echo Is the Powershell Script on the Desktop? (do so if not already)
pause
goto :ntrights


:ntrights
echo.
call :colorEcho 0e "Moving NTRights to Sys32.."
echo.
move %userprofile%\Desktop\ntrights.exe C:\Windows\System32
if %errorlevel%==1 (
	echo.
	call :colorEcho 0c "Check if the file is on the desktop. Skipping to Accounts."
	echo.
	pause
	goto :accounts
)

pause
goto :accounts

:accounts
echo.
call :colorEcho 0e "Configuring Accounts.."
echo.
echo.
call :colorEcho 06 "Disabling Default Account.."
echo.
net user Administrator /active:no
call :colorEcho 06 "Disabling Administrator Account.."
echo.
net user Guest /active:no

call :colorEcho 0e "Setting Password Policy.."
echo.
net accounts /minpwlen:8
net accounts /maxpwage:30
net accounts /minpwage:10
net accounts /lockoutwindow:30
net accounts /uniquepw:3

call :colorEcho 06 "Enabling Password Complexity Requirements.."
echo.
Powershell.exe -executionpolicy remotesigned -file %userprofile%\desktop\complex.ps1

echo.
call :colorEcho 06 "Setting Lockout Policy.."
echo.
net accounts /lockoutduration:30
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:30

call :colorEcho 06 "Normalizing Users.."
echo.
wmic UserAccount set PasswordExpires=true
wmic UserAccount set PasswordChangeable=True
wmic UserAccount set PasswordRequired=True

echo.
call :colorEcho 0e "Accounts Managed and Account Policies Configured!"
echo.
pause
if "%full%"=="1" (goto :rights) else (goto :main)

:rights
echo.
call :colorEcho 0e "Configuring User Rights Assignment.."
echo.

rem Everyone Permissions
ntrights -r SeRestorePrivilege -u "Everyone" 2>Nul
ntrights -r SENetworkLogonRight -u "Everyone" 2>Nul
ntrights -r SeChangeNotifyPrivilege -u "Everyone" 2>Nul
ntrights -r SeTcbPrivilege -u "Everyone" 2>Nul
ntrights +r SeDenyBatchLogonRight -u "Everyone" 2>Nul
ntrights +r SeDenyServiceLogonRight -u "Everyone" 2>Nul
ntrights +r SeDenyRemoteInteractiveLogonRight -u "Everyone" 2>Nul
ntrights -r SeDebugPrivilege -u "Everyone" 2>Nul
ntrights -r SeImpersonatePrivilege -u "Everyone" 2>Nul
ntrights +r SeDenyNetworkLogonRight +u "Everyone" 2>Nul
rem Users Permissions
ntrights -r SeRestorePrivilege -u "Users" 2>Nul
ntrights -r SENetworkLogonRight -u "Users" 2>Nul
ntrights -r SeChangeNotifyPrivilege -u "Users" 2>Nul
ntrights -r SeTcbPrivilege -u "Users" 2>Nul
ntrights +r SeDenyBatchLogonRight -u "Users" 2>Nul
ntrights +r SeDenyServiceLogonRight -u "Users" 2>Nul
ntrights +r SeDenyRemoteInteractiveLogonRight -u "Users" 2>Nul
ntrights -r SeDebugPrivilege -u "Users" 2>Nul
ntrights -r SeImpersonatePrivilege -u "Users" 2>Nul
rem Remote Desktop Permissions
ntrights -r SeRestorePrivilege -u "Remote Desktop Users" 2>Nul
ntrights -r SENetworkLogonRight -u "Remote Desktop Users" 2>Nul
ntrights -r SeChangeNotifyPrivilege -u "Remote Desktop Users" 2>Nul
ntrights -r SeTcbPrivilege -u "Remote Desktop Users" 2>Nul
ntrights +r SeDenyBatchLogonRight -u "Remote Desktop Users" 2>Nul
ntrights +r SeDenyServiceLogonRight -u "Remote Desktop Users" 2>Nul
ntrights +r SeDenyRemoteInteractiveLogonRight -u "Remote Desktop Users" 2>Nul
ntrights -r SeDebugPrivilege -u "Remote Desktop Users" 2>Nul
ntrights -r SeImpersonatePrivilege -u "Remote Desktop Users" 2>Nul
rem ANON Permissions
ntrights -r SeRestorePrivilege -u "ANONYMOUS LOGON" 2>Nul
ntrights -r SENetworkLogonRight -u "ANONYMOUS LOGON" 2>Nul
ntrights -r SeChangeNotifyPrivilege -u "ANONYMOUS LOGON" 2>Nul
ntrights -r SeTcbPrivilege -u "ANONYMOUS LOGON" 2>Nul
ntrights +r SeDenyBatchLogonRight -u "ANONYMOUS LOGON" 2>Nul
ntrights +r SeDenyServiceLogonRight -u "ANONYMOUS LOGON" 2>Nul
ntrights +r SeDenyRemoteInteractiveLogonRight -u "ANONYMOUS LOGON" 2>Nul
ntrights -r SeDebugPrivilege -u "ANONYMOUS LOGON" 2>Nul
ntrights -r SeImpersonatePrivilege -u "ANONYMOUS LOGON" 2>Nul
rem Guest Permissions	
ntrights -r SeRestorePrivilege -u "Guest" 2>Nul
ntrights -r SENetworkLogonRight -u "Guest" 2>Nul
ntrights -r SeChangeNotifyPrivilege -u "Guest" 2>Nul
ntrights -r SeTcbPrivilege -u "Guest" 2>Nul
ntrights +r SeDenyBatchLogonRight -u "Guest" 2>Nul
ntrights +r SeDenyServiceLogonRight -u "Guest" 2>Nul
ntrights +r SeDenyRemoteInteractiveLogonRight -u "Guest" 2>Nul
ntrights -r SeDebugPrivilege -u "Guest" 2>Nul
ntrights -r SeImpersonatePrivilege -u "Guest" 2>Nul
ntrights -r SeInteractiveLogonRight -u "Guest" 2>Nul
rem Admin Permissions
ntrights -r SeImpersonatePrivilege -u "Administrators" 2>Nul
ntrights +r SeMachineAccountPrivilege -u "Administrators" 2>Nul
ntrights -r SeDebugPrivilege -u "Administrators" 2>Nul
ntrights +r SeLockMemoryPrivilege -u "Administrators" 2>Nul

echo.
call :colorEcho 0e "User Rights Assigned"
echo.
pause
if "%full%"=="1" (goto :firewall) else (goto :main)

:firewall
netsh advfirewall set allprofiles state on
netsh advfirewall reset

echo.
call :colorEcho 0e "Firewall Enabled!"
echo.
netsh advfirewall firewall add rule name="TCP 0" protocol=TCP dir=in remoteport=21-23 action=block
netsh advfirewall firewall add rule name="TCP 21-23"  protocol=TCP dir=in remoteport=21-23 action=block
netsh advfirewall firewall add rule name="UDP 1900" protocol=UDP dir=in remoteport=1900 action=block
netsh advfirewall firewall add rule name="TCP 21-23" protocol=TCP dir=out remoteport=21-23 action=block
netsh advfirewall firewall add rule name="UDP 1900" protocol=UDP dir=out remoteport=1900 action=block
echo.
call :colorEcho 0e "Ports Configured!"
echo.
pause
if "%full%"=="1" (goto :autoupdate) else (goto :main)

:autoupdate
echo.
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
echo.
call :colorEcho 0e "Automatic Updates Enabled!"
echo.
pause
if "%full%"=="1" (goto :services) else (goto :main)

:services
echo.
sc stop spooler 2>Nul >Nul
sc config spooler start= disabled 2>Nul >Nul
sc stop remoteRegistry 2>Nul >Nul
sc config remoteRegistry start= disabled 2>Nul >Nul
sc stop sessionEnv 2>Nul >Nul
sc config sessionEnv start= disabled 2>Nul >Nul
sc stop BluetoothUserService 2>Nul >Nul
sc config BluetoothUserService 2>Nul >Nul
sc stop bthserv 2>Nul >Nul
sc config bthserv 2>Nul >Nul
sc stop TermService 2>Nul >Nul
sc config TermService start= disabled 2>Nul >Nul
sc stop UmRdpService 2>Nul >Nul
sc config UmRdpService start= disabled 2>Nul >Nul
sc stop LanManServer 2>Nul >Nul
sc config LanManServer start= demand 2>Nul >Nul
sc stop SNMPTrap 2>Nul >Nul
sc config SNMPTrap start= disabled 2>Nul >Nul
sc stop SSDPSRV 2>Nul >Nul
sc config SSDPSRV start= disabled 2>Nul >Nul
sc stop lmHosts 2>Nul >Nul
sc config lmHosts start= disabled 2>Nul >Nul
sc stop tapiSrv 2>Nul >Nul
sc config tapiSrv start= disabled 2>Nul >Nul
sc stop upnpHost 2>Nul >Nul
sc config upnpHost start= disabled 2>Nul >Nul
sc stop iprip 2>Nul >Nul
sc config iprip 2>Nul >Nul

net stop telnet
sc config tlntsvr start= disabled

echo Enabling critical services..
sc start wecsvc 2>Nul >Nul
sc config wecsvc start= auto 2>Nul >Nul
sc start eventlog 2>Nul >Nul
sc config eventlog start= auto 2>Nul >Nul
sc start WinDefend 2>Nul >Nul
sc config WinDefend start= auto 2>Nul >Nul
sc start mpssvc 2>Nul >Nul
sc config mpssvc start= auto 2>Nul >Nul
sc start wuauserv 2>Nul >Nul 
sc config wuaserv start= auto 2>Nul >Nul

echo.
call :colorEcho 0e "Services Configured!"
echo.
pause
if "%full%"=="1" (goto :security) else (goto :main)

:security
echo.
call :colorEcho 0e "Setting Security Policies.."
echo.
rem Blocking Microsoft Accounts
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUster /t REG_DWORD /d 3 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount" /v AllowYourAccount /t REG_DWORD /d 0 /f
rem Configuring Idle Timeout
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogff /t REG_DWORD /d 1 /f
rem Configuring Restart Logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn REG_DWORD /d 1 /f
rem Disabling Remote Assistance
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
rem Enabling SEHOP
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f
rem Enable Smart Screen
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 2 /f
rem Restrict CDROM
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
rem AutoAdmin Login
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
rem Clear Page File
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
rem Restrict Floppy
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
rem Limit local use of blank passwords
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f	
rem Audit global system objects
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
rem Forget LanMan Hashes
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
rem Audit backup/restore
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
rem Don't display last username
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
rem Installer Detection
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f
reg ADD "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
rem Restricting Printer Driver Installation
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
rem NTLM Configurations
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 0 /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
rem Enable UAC
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
rem UAC on Secure Desktop
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
rem Configuring LSA Protection
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
rem Max Pass Age
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 30 /f
rem Min Pass Age
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v MinimumPasswordAge /t REG_DWORD /d 10 /f
rem Require Strong Session key
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
rem Require Sign/Seal
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
rem Require Sign
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
rem Require Seal
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
rem WINRM Authentication
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f
rem Encryption for RDA
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WINRM\Client" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
rem Disabling 16bit Applications
reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v VDMDisallowed /t REG_DWORD /d 1 /f
rem Require CTRL ALT DEL
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
rem Restrict Anonymous Enum
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
rem Restrict Anonymous Enum
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f 
rem Disabling Domain Credential Storage
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
rem Automatic 15 Minute Timeout
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f 	
rem Security signature
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v enablesecuritysignature /t REG_DWORD /d 1 /f 
rem Security signature
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v requiresecuritysignature /t REG_DWORD /d 1 /f 
rem Don't give Everyone Perms to Anonymous
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous" /t REG_DWORD /d 0 /f 
rem SMB Passwords to third-party
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
rem Clear Null Session Pipes
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
rem Clear Reg Paths
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
rem Clear Reg Paths
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f
rem Restrict to Named Shares
reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
rem Enabling Smart Screen
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
rem Disabling Autoplay
reg ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg ADD "HKCU\SYSTEM\CurrentControlSet\Services\CDROM" /v AutoRun /t REG_DWORD /d 1 /f
rem Disabling Crash Dump
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f

echo.
call :colorEcho 0e "Security Policies Set!"
echo.
pause
if "%full%"=="1" (goto :audit) else (goto :main)

:audit
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

echo.
call :colorEcho 0e "Audit Policies Set!"
echo.
pause
if "%full%"=="1" (goto :lgpo) else (goto :main)

:lgpo
set /p lgpo=Do you want to do a sweep over the group policies? [Y/N] 
	if "%lgpo%"=="Y" (
		echo.
		call :colorEcho 0e "Beginning LGPO Sweep.." 
		echo.
	) ELSE (
		if "%lgpo%"=="y" (
		echo.
		call :colorEcho 0e "Beginning LGPO Sweep.." 
		echo.
		) ELSE (
			if "%full%"=="1": (
				echo.
				call :colorEcho 0e "Skipping to Features."
				echo.
				goto :features
		) ELSE (
			goto :exit
		)
		)
	)
	pause

secedit /configure /db %userprofile%\Desktop\Settings.sdb
if %errorlevel%==1 (
	echo.
	call :colorEcho 0c "Check if the file is on the desktop. Returning to the Menu."
	echo.
	goto :main
)

echo.
call :colorEcho 0e "LGPO Configured!"
echo.
pause
if "%full%"=="1" (goto :features) else (goto :main)

:features
echo.
call :colorEcho 0e "Configuring Windows Features.."
echo.
DISM /online /enable-feature /featurename:Internet-Explorer-Optional-amd64
DISM /online /disable-feature /featurename:RasRip /featurename:TFTP /featurename:TelnetClient /featurename:SMB1Protocol /featurename:SimpleTCP
DISM /online /disable-feature /featurename:Printing-Foundation-Features /featurename:Microsoft-Windows-Subsystem-Linux /featurename:WorkFolders-Client
DISM /online /disable-feature /featurename:TelnetServer
rem Disabling IIS
DISM /online /disable-feature /featurename:IIS-WebServerRole /featurename:IIS-WebServer /featurename:IIS-CommonHttpFeatures /featurename:IIS-HttpErrors /featurename:IIS-HttpRedirect /featurename:IIS-ApplicationDevelopment /featurename:IIS-NetFxExtensibility /featurename:IIS-NetFxExtensibility45 /featurename:IIS-HealthAndDiagnostics /featurename:IIS-HttpLogging /featurename:IIS-LoggingLibraries /featurename:IIS-RequestMonitor /featurename:IIS-HttpTracing /featurename:IIS-Security /featurename:IIS-URLAuthorization /featurename:IIS-RequestFiltering /featurename:IIS-IPSecurity /featurename:IIS-Performance /featurename:IIS-HttpCompressionDynamic /featurename:IIS-WebServerManagementTools /featurename:IIS-ManagementScriptingTools /featurename:IIS-IIS6ManagementCompatibility /featurename:IIS-Metabase /featurename:IIS-HostableWebCore /featurename:IIS-StaticContent /featurename:IIS-DefaultDocument /featurename:IIS-DirectoryBrowsing /featurename:IIS-WebDAV /featurename:IIS-WebSockets /featurename:IIS-ApplicationInit /featurename:IIS-ASPNET /featurename:IIS-ASPNET45 /featurename:IIS-ASP /featurename:IIS-CGI /featurename:IIS-ISAPIExtensions /featurename:IIS-ISAPIFilter /featurename:IIS-ServerSideIncludes /featurename:IIS-CustomLogging /featurename:IIS-BasicAuthentication /featurename:IIS-HttpCompressionStatic /featurename:IIS-ManagementConsole /featurename:IIS-ManagementService /featurename:IIS-WMICompatibility /featurename:IIS-LegacyScripts /featurename:IIS-LegacySnapIn /featurename:IIS-FTPServer /featurename:IIS-FTPSvc /featurename:IIS-FTPExtensibility


echo.
call :colorEcho 0e "Windows Features Configured!"
echo.
pause
if "%full%"=="1" (goto :misc) else (goto :main)

:misc
echo.
call :colorEcho 0e "Enabling QOL Features.."
echo.
rem Enabling File Visibility
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
rem Disabling Sticky Keys
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
rem Internet Explorer Configurations
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
rem Internet Explorer Enhanced Security Configurations
reg ADD "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
echo.
call :colorEcho 0e "Configuring Power Settings.."
echo.
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
echo.
call :colorEcho 0e "Misc Settings Configured"
echo.
pause
if "%full%"=="1" (goto :scanning) else (goto :main)

:scanning
echo.
call :colorEcho 0e "Beginning System Scan.."
echo.
Sfc.exe /scannow
echo.


rem put file scanning here 
echo.
call :colorEcho 0e "System Scan Complete!"
echo.
pause
if "%full%"=="1" (goto :end) else (goto :main)

:exit
echo.
call :colorEcho 0c "Failure. Program exiting."
echo.
pause
exit

cls

:end
echo.
call :colorEcho 0b "Make sure to verify that settings were changed and restart."
rem Turn on screen saver
rem Turn on UAC
echo.
pause
exit

:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i