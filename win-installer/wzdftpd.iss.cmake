[Setup]
AppName=wzdftpd
AppVerName=0.8.2
PrivilegesRequired=admin
InternalCompressLevel=ultra
Compression=lzma/ultra
DefaultDirName={pf}\wzdftpd
ShowLanguageDialog=auto
OutputDir=windows-installer
OutputBaseFilename=wzdftpd-setup
DefaultGroupName=wzdftpd
AppMutex=wzdftpdIsActive,Global\wzdftpdIsActive
AppPublisher=wzdftpd
AppPublisherURL=http://www.wzdftpd.net
AppSupportURL=http://www.wzdftpd.net
AppUpdatesURL=http://www.wzdftpd.net
AppVersion=0.8.2
UninstallDisplayIcon={app}\icons\wzd.ico
UninstallDisplayName=wzdftpd
VersionInfoVersion=0.8.2.0
VersionInfoCompany=www.wzdftpd.net
VersionInfoDescription=wzdftpd FTP daemon
VersionInfoTextVersion=0.8.2
VersionInfoCopyright=GPLv2 (see COPYING for more details)
AppCopyright=GPLv2 (see COPYING for more details)
MinVersion=0,5.0.2195
LicenseFile=@CMAKE_CURRENT_SOURCE_DIR@\COPYING
AppContact=http://www.wzdftpd.net
AppID=wzdftpd082
WizardImageFile=@CMAKE_CURRENT_SOURCE_DIR@\win-installer\sidepanel.bmp
WizardSmallImageFile=@CMAKE_CURRENT_SOURCE_DIR@\win-installer\toplogosquare.bmp
SetupIconFile=@CMAKE_CURRENT_SOURCE_DIR@\win-installer\wzd.ico
[Components]
Name: core; Description: Core files (required); Flags: fixed; Types: custom compact full
Name: backends; Description: Backends; Types: full
Name: backends\plaintext; Description: Plaintext (required); Types: custom compact full; Flags: fixed
Name: backends\mysql; Description: MySQL; Types: full
Name: backends\pgsql; Description: PostgreSQL; Types: full
Name: backends\sqlite; Description: SQLite; Types: full
Name: modules; Description: Modules; Types: full
Name: modules\perl; Description: Perl; Types: full
Name: modules\tcl; Description: Tcl; Types: full
Name: modules\sfv; Description: SFV; Types: full
Name: tools; Description: Tools; Types: full
Name: tools\siteconfig; Description: site config; Types: full
Name: tools\siteuptime; Description: site uptime; Types: full
Name: tools\sitewho; Description: site who; Types: full
Name: development; Description: Development files; Types: full
[Tasks]
Name: installservice; Description: Install wzdftpd as a service; Components: core
Name: startmenu; Description: Add wzdftpd to the start menu; Components: core
[Dirs]
Name: {app}\modules; Components: core
Name: {app}\backends; Components: core
Name: {app}\tools; Components: core
Name: {app}\config; Components: core
Name: {app}\logs; Components: core
Name: {app}\icons; Components: core; Tasks: startmenu
Name: {app}\ftproot; Components: core;
[Files]
Source: @CMAKE_CURRENT_BINARY_DIR@\wzdftpd\release\wzdftpd.exe; DestDir: {app}; Components: core; BeforeInstall: StopExistingService
Source: @CMAKE_CURRENT_BINARY_DIR@\libwzd-core\release\libwzd_core.dll; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_BINARY_DIR@\libwzd\release\libwzd.dll; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_BINARY_DIR@\modules\perl\release\libwzd_perl.dll; DestDir: {app}\modules; Components: modules\perl
Source: @CMAKE_CURRENT_BINARY_DIR@\modules\sfv\release\libwzd_sfv.dll; DestDir: {app}\modules; Components: modules\sfv
Source: @CMAKE_CURRENT_BINARY_DIR@\modules\tcl\release\libwzd_tcl.dll; DestDir: {app}\modules; Components: modules\tcl
Source: @CMAKE_CURRENT_BINARY_DIR@\backends\mysql\release\libwzd_mysql.dll; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_BINARY_DIR@\backends\pgsql\release\libwzd_pgsql.dll; DestDir: {app}\backends; Components: backends\pgsql
Source: @CMAKE_CURRENT_BINARY_DIR@\backends\plaintext\release\libwzd_plaintext.dll; DestDir: {app}\backends; Components: backends\plaintext
Source: @CMAKE_CURRENT_BINARY_DIR@\backends\sqlite\release\libwzd_sqlite.dll; DestDir: {app}\backends; Components: backends\sqlite
Source: @CMAKE_CURRENT_BINARY_DIR@\tools\siteconfig\release\siteconfig.exe; DestDir: {app}\tools; Components: tools\siteconfig
Source: @CMAKE_CURRENT_BINARY_DIR@\tools\siteuptime\release\siteuptime.exe; DestDir: {app}\tools; Components: tools\siteuptime
Source: @CMAKE_CURRENT_BINARY_DIR@\tools\sitewho\release\sitewho.exe; DestDir: {app}\tools; Components: tools\sitewho
Source: @CMAKE_CURRENT_BINARY_DIR@\wzdftpd\wzd.cfg.sample; DestDir: {app}; DestName: wzd.cfg; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_BINARY_DIR@\users.sample; DestDir: {app}\config; DestName: users; Flags: confirmoverwrite; Components: backends\plaintext
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\wzd.pem; DestDir: {app}\config; DestName: wzd.pem; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_who.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_ginfo.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_group.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_groups.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_help.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_rules.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_swho.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_user.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_users.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\wzdftpd\file_vfs.txt; DestDir: {app}\config; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\blank.file; DestDir: {app}\logs; DestName: wzdftpd.log; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\blank.file; DestDir: {app}\logs; DestName: xfer.log; Flags: confirmoverwrite; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\mysql\mysql_tables_create.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\mysql\mysql_database_create.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\mysql\mysql_database_drop.sql; DestDir: {app}\backends; Components: backends\mysql
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\pgsql\pgsql_tables_create.sql; DestDir: {app}\backends; Components: backends\pgsql
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\pgsql\pgsql_database_create.sql; DestDir: {app}\backends; Components: backends\pgsql
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\pgsql\pgsql_database_drop.sql; DestDir: {app}\backends; Components: backends\pgsql
Source: @CMAKE_CURRENT_SOURCE_DIR@\backends\sqlite\sqlite_tables_create.sql; DestDir: {app}\backends; Components: backends\sqlite
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_action.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_all.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_backend.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_cache.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_ClientThread.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_commands.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_configfile.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_configloader.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_crc32.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_crontab.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_data.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_debug.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_dir.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_events.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_file.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_fs.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_group.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_hardlimits.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_ip.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_libmain.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_list.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_log.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_login.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_messages.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_misc.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_mod.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_mutex.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_perm.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_protocol.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_ratio.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_section.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_shm.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_site.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_site_group.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_site_user.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_socket.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_string.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_strptime.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_strtoull.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_structs.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_threads.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_tls.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_types.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_user.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_utf8.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_vars.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-core\wzd_vfs.h; DestDir: {app}\include\libwzd-core; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\wzd_strtok_r.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\dlist.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\hash.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\list.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\stack.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\strpcpy.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-base\wzd_strlcat.h; DestDir: {app}\include\libwzd-base; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_tls.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_auth.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_base64.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_crypt.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_krb5.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_md5.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_md5crypt.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_pam.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\libwzd-auth\wzd_sha1.h; DestDir: {app}\include\libwzd-auth; Components: development
Source: @CMAKE_CURRENT_BINARY_DIR@\libwzd-core\release\libwzd_core.lib; DestDir: {app}\lib; Components: development
Source: @CMAKE_CURRENT_BINARY_DIR@\libwzd\release\libwzd.lib; DestDir: {app}\lib; Components: development
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\wzd-unreg.ico; DestDir: {app}\icons; Components: core; Tasks: startmenu
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\wzd.ico; DestDir: {app}\icons; Components: core; Tasks: startmenu
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\wzd-reg.ico; DestDir: {app}\icons; Components: core; Tasks: startmenu
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\wzd-start.ico; DestDir: {app}\icons; Components: core; Tasks: startmenu
Source: @CMAKE_CURRENT_SOURCE_DIR@\win-installer\wzd-stop.ico; DestDir: {app}\icons; Components: core; Tasks: startmenu
Source: @CMAKE_CURRENT_SOURCE_DIR@\COPYING; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\VERSION; DestDir: {app}; Components: core
Source: @CMAKE_CURRENT_SOURCE_DIR@\README; DestDir: {app}; Components: core
[INI]
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: logdir; String: " {app}\logs"; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: logfile; String: " {app}\logs\wzdftpd.log"; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: xferlog; String: " {app}\logs\xfer.log"; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: backend; String: " ""{app}\backends\libwzd_plaintext.dll"""; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: tls_certificate; String: " {app}\config\wzd.pem"; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: sitefile_ginfo; String: " {app}\config\file_ginfo.txt"; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: sitefile_group; String: " {app}\config\file_group.txt"; Components: core
Filename: {app}\wzd.cfg; Section: GLOBAL; Key: sitefile_user; String: " {app}\config\file_user.txt"; Components: core
Filename: {app}\wzd.cfg; Section: plaintext; Key: param; String: " {app}\config\users"
Filename: {app}\wzd.cfg; Section: sqlite; Key: #param; String: " !{app}\config\users.db"; Components: backends\sqlite
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_rules; String: " !{app}\config\file_rules.txt"; Components: core
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_groups; String: " !{app}\config\file_groups.txt"; Components: core
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_help; String: " !{app}\config\file_help.txt"; Components: core
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_swho; String: " !{app}\config\file_swho.txt"; Components: core
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_users; String: " !{app}\config\file_users.txt"; Components: core
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_vfsls; String: " !{app}\config\file_vfs.txt"; Components: core
Filename: {app}\wzd.cfg; Section: custom_commands; Key: site_who; String: " !{app}\config\file_who.txt"; Components: core
Filename: {app}\config\users; Section: GROUPS; Key: default_home; String: {app}\ftproot; Components: backends\plaintext
Filename: {app}\config\users; Section: USERS; Key: home; String: {app}\ftproot; Components: backends\plaintext
[Icons]
Name: {group}\Install wzdftpd service; Filename: {app}\wzdftpd.exe; Parameters: -si; WorkingDir: {app}; Components: core; Tasks: startmenu; IconFilename: {app}\icons\wzd-reg.ico; IconIndex: 0
Name: {group}\Remove wzdftpd service; Filename: {app}\wzdftpd.exe; Parameters: -sd; WorkingDir: {app}; Components: core; Tasks: startmenu; IconFilename: {app}\icons\wzd-unreg.ico; IconIndex: 0
Name: {group}\Start wzdftpd service; Filename: {app}\wzdftpd.exe; Parameters: -ss; WorkingDir: {app}; Components: core; Tasks: startmenu; IconFilename: {app}\icons\wzd-start.ico; IconIndex: 0
Name: {group}\Stop wzdftpd service; Filename: {app}\wzdftpd.exe; Parameters: -st; WorkingDir: {app}; Components: core; Tasks: startmenu; IconFilename: {app}\icons\wzd-stop.ico; IconIndex: 0
Name: {group}\wzdftpd website; Filename: http://www.wzdftpd.net; Components: core; Tasks: startmenu
Name: {group}\Online documentation; Filename: http://www.wzdftpd.net/trac/wiki/Documentation; Components: core; Tasks: startmenu
Name: {group}\Discussion forums; Filename: http://www.wzdftpd.net/smf/; Components: core; Tasks: startmenu
Name: {group}\Report a bug or request a feature; Filename: http://www.wzdftpd.net/trac/newticket; Components: core; Tasks: startmenu
Name: {group}\IRC channel; Filename: http://www.wzdftpd.net/trac/wiki/IrcChannel; Components: core; Tasks: startmenu
[Run]
Filename: {app}\wzdftpd.exe; Parameters: -si; WorkingDir: {app}; StatusMsg: Installing the wzdftpd service...; Tasks: installservice
Filename: {app}\wzdftpd.exe; Parameters: -ss; WorkingDir: {app}; StatusMsg: Starting the wzdftpd service...; Flags: postinstall; Tasks: installservice; Description: Start the wzdftpd service
[UninstallRun]
Filename: {app}\wzdftpd.exe; Parameters: -st; WorkingDir: {app}
Filename: {app}\wzdftpd.exe; Parameters: -sd; WorkingDir: {app}
[Code]
procedure StopExistingService;
var ResultCode : Integer;
begin
	if FileExists('{app}\wzdftpd.exe') then
	begin
		Exec(ExpandConstant('{app}\wzdftpd.exe'), '-st', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
		Exec(ExpandConstant('{app}\wzdftpd.exe'), '-sd', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
	end
	Exec(GetSystemDir()+'\net.exe', 'stop wzdftpd', GetSystemDir(), SW_HIDE, ewWaitUntilTerminated, ResultCode);
	Exec(GetSystemDir()+'\sc.exe', 'stop wzdftpd', GetSystemDir(), SW_HIDE, ewWaitUntilTerminated, ResultCode);
	Exec(GetSystemDir()+'\sc.exe', 'delete wzdftpd', GetSystemDir(), SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
