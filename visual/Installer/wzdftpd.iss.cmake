[Setup]
InternalCompressLevel=ultra
OutputBaseFilename=wzdsetup082
SolidCompression=true
VersionInfoVersion=0.8.2
VersionInfoCompany=wzdftpd
VersionInfoDescription=Modular and cool cross-platform FTP server
VersionInfoTextVersion=zero eight two
VersionInfoCopyright=GPL
Compression=lzma/ultra
MinVersion=0,5.0.2195
AppCopyright=GPL
AppName=wzdftpd
AppVerName=wzdftpd 0.8.2
PrivilegesRequired=admin
DisableReadyPage=true
WindowVisible=false
AppPublisher=wzdftpd
AppPublisherURL=http://www.wzdftpd.net
AppSupportURL=http://www.wzdftpd.net
AppUpdatesURL=http://www.wzdftpd.net
AppVersion=0.8.2
UninstallDisplayName=wzdftpd
DefaultDirName={pf}\wzdftpd
;WizardImageFile=logo-large.bmp
;WizardSmallImageFile=logo-small.bmp
SetupIconFile=@CMAKE_CURRENT_SOURCE_DIR@/visual/Installer/wzd.ico
WizardImageStretch=true
[Components]
Name: core; Description: Core files; Flags: fixed; Types: custom compact full
Name: backends; Description: Backends; Types: custom full
Name: backends\plaintext; Description: Plaintext; Types: full custom compact
Name: backends\mysql; Description: MySQL; Types: custom full
Name: backends\pgsql; Description: PostgreSQL; Types: custom full
Name: backends\sqlite; Description: SQLite; Types: custom full
Name: modules; Description: Modules; Types: custom full
Name: modules\perl; Description: Perl; Types: custom full
Name: modules\sfv; Description: SFV; Types: full custom
Name: modules\tcl; Description: TCL; Types: custom full
Name: modules\zeroconf; Description: Zeroconf; Types: custom full
Name: tools; Description: Tools; Types: full custom
Name: tools\siteconfig; Description: site config; Types: full custom
Name: tools\siteuptime; Description: site uptime; Types: full custom
Name: tools\sitewho; Description: site who; Types: full custom
[Files]
Source: @CMAKE_CURRENT_BINARY_DIR@/wzdftpd/release/wzdftpd.exe; DestDir: {app}; Components: core; BeforeInstall: StopExistingService
Source: @CMAKE_CURRENT_BINARY_DIR@/libwzd/release/libwzd.dll; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_BINARY_DIR@/libwzd-core/release/libwzd_core.dll; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_BINARY_DIR@/wzdftpd/wzd.cfg.sample; DestDir: {app}; DestName: wzd.cfg; Components: core; Tasks: overwriteconfig; Flags: onlyifdoesntexist uninsneveruninstall
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/wzd.pem; DestDir: {app}; Components: core; Flags: onlyifdoesntexist 
Source: @CMAKE_CURRENT_SOURCE_DIR@/AUTHORS; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/ChangeLog; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/COPYING; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/INSTALL; DestDir: {app}; Components: core
;Source: @CMAKE_CURRENT_SOURCE_DIR@/KNOWN_BUGS; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/NEWS; DestDir: {app}; Components: core
;Source: @CMAKE_CURRENT_SOURCE_DIR@/NOTES; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/Permissions.ReadMeFirst; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/README; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/TLS.ReadMeFirst; DestDir: {app}; Components: core
;Source: @CMAKE_CURRENT_SOURCE_DIR@/TODO; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/UPGRADING; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@/VERSION; DestDir: {app}; Components: core
;Source: backends\libwzd_sqlite.dll; DestDir: {app}\backends; Components: backends\sqlite
Source: @CMAKE_CURRENT_BINARY_DIR@/backends/mysql/release/libwzd_mysql.dll; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@/backends/mysql/dropall.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@/backends/mysql/tables.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_BINARY_DIR@/backends/pgsql/release/libwzd_pgsql.dll; DestDir: {app}\backends; Components: backends\pgsql
Source: @CMAKE_CURRENT_SOURCE_DIR@/backends/pgsql/dropall.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@/backends/pgsql/createusers.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@/backends/pgsql/tables.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_BINARY_DIR@/backends/plaintext/release/libwzd_plaintext.dll; DestDir: {app}\backends; Components: backends\plaintext
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_ginfo.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_group.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_groups.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_help.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_rules.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_swho.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_user.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_users.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_vfs.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/file_who.txt; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
Source: @CMAKE_CURRENT_SOURCE_DIR@/wzdftpd/users.sample; DestDir: {app}\config; Components: core; Tasks: overwriteconfig
;Source: @CMAKE_CURRENT_BINARY_DIR@/modules/zeroconf/release/libwzd_zeroconf.dll; DestDir: {app}\modules; Components: modules\zeroconf
Source: @CMAKE_CURRENT_BINARY_DIR@/modules/perl/release/libwzd_perl.dll; DestDir: {app}\modules; Components: modules\perl
Source: @CMAKE_CURRENT_BINARY_DIR@/modules/sfv/release/libwzd_sfv.dll; DestDir: {app}\modules; Components: modules\sfv
Source: @CMAKE_CURRENT_BINARY_DIR@/modules/tcl/release/libwzd_tcl.dll; DestDir: {app}\modules; Components: modules\tcl
Source: @CMAKE_CURRENT_BINARY_DIR@/tools/sitewho/release/sitewho.exe; DestDir: {app}\tools; Components: tools\sitewho
Source: @CMAKE_CURRENT_BINARY_DIR@/tools/siteconfig/release/siteconfig.exe; DestDir: {app}\tools; Components: tools\siteconfig
Source: @CMAKE_CURRENT_BINARY_DIR@/tools/siteuptime/release/siteuptime.exe; DestDir: {app}\tools; Components: tools\siteuptime
[Dirs]
Name: {app}\backends; Components: core
Name: {app}\config; Components: core
Name: {app}\ftproot; Components: core
Name: {app}\logs; Components: core
Name: {app}\modules; Components: core
Name: {app}\tools; Components: core
[Run]
Filename: {app}\wzdftpd.exe; WorkingDir: {app}; Description: Install wzdftpd as a service; StatusMsg: Installing wzdftpd as a service...; Flags: runhidden; Components: core; Parameters: -si; Tasks: installservice
Filename: {app}\wzdftpd.exe; Parameters: -ss; WorkingDir: {app}; Description: Start wzdftpd service; StatusMsg: Starting wzdftpd service...; Flags: runhidden postinstall; Components: core; Tasks: installservice
[UninstallRun]
Filename: {app}\wzdftpd.exe; Parameters: -st; WorkingDir: {app}; Flags: runhidden; Components: core
Filename: {app}\wzdftpd.exe; Parameters: -sd; WorkingDir: {app}; Flags: runhidden; Components: core
[Code]
procedure StopExistingService;
var ResultCode1, ResultCode2 : Integer;
begin
	if FileExists('{app}\wzdftpd.exe') then
	begin
		Exec(ExpandConstant('{app}\wzdftpd.exe'), '-ss', '', SW_HIDE, ewWaitUntilTerminated, ResultCode1);
	end
	Exec(GetSystemDir()+'\net.exe', 'stop wzdftpd', GetSystemDir(), SW_HIDE, ewWaitUntilTerminated, ResultCode2);
	//MsgBox('Result1: ' + IntToStr(ResultCode1) + ' -- Result2:' + IntToStr(ResultCode2), mbInformation, MB_OK);
end;
[Tasks]
Name: overwriteconfig; Description: Overwrite old configuration; Flags: checkedonce; Components: core
Name: installservice; Description: Install wzdftpd as a service; Components: core
