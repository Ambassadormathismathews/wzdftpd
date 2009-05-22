[GLOBAL]
# This is the main config file
# lines begining with a # are ignored, as empty lines
# all lines must be of the form:
# <name> = <value>
# (for windows users: without the < > ;-)

config version = @WZD_VERSION@

# enable experimental or untested code (default: false)
#experimental = true

# backup config when saving changes (default: false)
backup config = true

# Listen port (default: 21)
# IMPORTANT: under unix, you'll need privileges to bind to a system port
# ( < 1024 )
#port = 21

# PASV range (default: 1025->65536)
# specify this if you want to get a specific range
pasv_low_range = 1024
pasv_high_range  = 65535
#pasv_ip = 62.xxx.xxx.xxx
#pasv_ip = 134.xxx.xx.xx

# uncomment this line to disable ident checks (default: check for ident)
#disable_ident = 1

# unix only: server will drop privileges to a user after binding port
# you can specify a user login name
# This will only be used if run by root !
#server_uid = pollux

# unix only: file where pid of server will be stored
# (default: /var/run/wzdftpd.pid)
# this is used by init.d script
#pid_file = @CMAKE_INSTALL_PREFIX@/@localstatedir@/run/@PACKAGE@/wzdftpd.pid

# the name of the file in each dir that should be added to every answer
dir_message = .message

# log file for server activity
logfile = @CMAKE_INSTALL_PREFIX@/@localstatedir@/log/@PACKAGE@/wzd.log

# set to 0 if you do not want syslog (default: 1)
#use_syslog = 0

# log file for transfered files (default: do not log)
xferlog = @CMAKE_INSTALL_PREFIX@/@localstatedir@/log/@PACKAGE@/xferlog

# directory to store various log files
logdir = @CMAKE_INSTALL_PREFIX@/@localstatedir@/log/@PACKAGE@

# max number of child threads (default: 64)
max_threads = 64

# max number of users allowed to connect to server (default: 64)
max_users = 64

# backend to use for auth (default: plaintext)
# you can check backend version with directives > and <
# e.g: backend = plaintext > 120
# ONE BACKEND IS NEEDED !
# backend name SHOULD NEVER contains spaces !
#backend = plaintext > 123
backend = @CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/backends/libwzd_plaintext.so > 124
#backend = @CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/backends/libwzd_mysql.so
#backend = @CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/backends/libwzd_pgsql.so
#backend = @CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/backends/libwzd_pam.so
#backend = @CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/backends/libwzd_sqlite.so

# speed limits in bytes /sec (approx !)
# 0 = no limit
# ex: max_dl_speed = 300000
max_ul_speed = 0
max_dl_speed = 0

# deny_access_files_uploaded (default: 0)
# if you say 1 here, users trying to download file whereas
# the file is being uploaded will be denied
deny_access_files_uploaded = 1

# default permissions for created dirs (default: 775)
# these permissions are in standard chmod() format (octal)
# default: 775 (user and group can upload in directory)
#umask = 775

# hide_dotted_files (default: 0)
# hide files beggining by a '.'
#hide_dotted_files = 1

# Log level (default: normal)
# Verbosity of log (only messages >= level will be displayed)
# can be one of (in order):
# lowest, flood, info, normal, high, critical
#loglevel = lowest

# help file location
help_file = @CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_help.txt

# TLS Options

# Certificate (only used in ssl mode, otherwise ignored)
tls_certificate = @CMAKE_INSTALL_PREFIX@/@sysconfdir@/wzd.pem

# Mode (default: explicit)
#  explicit: server starts in clear mode, wait for "AUTH TLS" and then switch to ssl
#    you can use explicit mode with normal (clear) mode
#  explicit_strict: server will start in clear mode, but will accept ONLY logins switched to ssl
#  implicit: server starts in ssl mode, no clear connection is possible
#tls_mode = explicit

# cipher list (default: ALL)
# you should not use this option or let "ALL" unless you know
# what you are doing
# see openssl ciphers, man openssl(1)
#tls_cipher_list = ALL

# /TLS

##### SITE FILES
sitefile_ginfo	= @CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_ginfo.txt
sitefile_group	= @CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_group.txt
sitefile_user	= @CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_user.txt

##### INCLUSIONS
# You can include other files
# maximum recursion is 16 (too big IMHO)
#include permissions.cfg

##### Zeroconf Settings
[ZEROCONF]
zeroconf_port = 21
#zeroconf_username = wzdftpd
#zeroconf_password = wzdftpd
#zeroconf_path = /tmp

##### IP RESTRICTIONS
[pre_ip_check]

# wildcards are accepted (*,?) - NOTE * stops after the first match of the next
#   char
#
# WARNING: to match all ip ending by 0.1 you MUST write *.*.0.1, NOT *.0.1
#xxx.xxx.org = allow
localhost = allow
#*.xxx.fr = allow
* = allow
#* = deny

##### PERMISSIONS
# you must add prefixes before permissions: -group =user +flag or *
# you can use negations : !*
# REMEMBER that the FIRST corresponding rule is applied, so order is important (never put * first !)
# ex: site_who = =admin -group1 +F =toto
# delete = -admin
[perms]
site_addip = +O +G
site_adduser = +O +G
site_backend = +O
site_chacl = +O
site_change = +O +G
site_changegrp = +O +G
site_checkperm = +O
site_chgrp = +O
site_chmod = +O
site_chown = +O
site_chpass = *
site_chratio = +O +G
site_close = +O
site_color = !=guest *
site_delip = +O +G
site_deluser = +O +G
site_flags = -admin
site_free = *
site_ginfo = +O +G
site_give = *
site_group = +O
site_groups = +O
site_grpadd = +O
site_grpaddip = +O
site_grpchange = +O
site_grpdel = +O
site_grpdelip = +O
site_grpkill = +O
site_grpratio = +O
site_grpren = +O
site_gsinfo = +O +G
site_help = *
site_idle = *
site_invite = !=guest *
site_kick = +O
site_kill = +O
site_link = +O
site_msg = +O
site_perm = +O
site_purge = +O +G
site_readd = +O +G
site_reload = +O
site_reopen = +O
site_rules = *
site_rusage = +O
site_savecfg = +O
site_sections = +O
site_showlog = +O
site_shutdown = +O
site_su = +O
site_swho = +O
site_tagline = !=guest *
site_take = +O
site_unlock = +O
site_uptime = *
site_user = +O +G
site_users = -admin
site_utime = *
site_vars = +O
site_vars_group = +O
site_vars_user = +O
site_version = +O
site_who = !=guest *
site_wipe = +O
site_vfsls = +O
site_vfsadd = +O
site_vfsdel = +O

# REMOVE ME OR YOU DON'T KNOW WHAT WILL HAPPEN !
#site_my_free = *
#site_test = =pollux

[modules]
# modules are dynamic libraries
# order *IS* important
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_debug.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_test.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_sfv.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_tcl.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_perl.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_python.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_zeroconf.so = deny
@CMAKE_INSTALL_PREFIX@/@datadir@/@PACKAGE@/modules/libwzd_dupecheck.so = deny

[sfv]
progressmeter = [WzD] - %3d%% Complete - [WzD]
del_progressmeter = \[.*] - ...% Complete - \[WzD]
incomplete_indicator = ../(incomplete)-%releasename
other_completebar = [WzD] - ( %.0mM %fF - COMPLETE ) - [WzD]
create_symlinks = false

##### Dupecheck settings.
[dupecheck]
## Where should dupecheck keep it's sqlite database?
# database = @CMAKE_INSTALL_PREFIX@/@localstatedir@/lib/dupelog

[plaintext]
param = @CMAKE_INSTALL_PREFIX@/@sysconfdir@/users

[mysql]
# User, pass, host, port(0=default) and db must be entered.
#
# If you wish to use SSL encrypted connections with your intended server,
# first make sure it can receive such requests, then use one of three ways
# to connect to it.
#
#param = login:password@host:port/base
#
#param = login:password@host:port/base|ca-cert
#param = login:password@host:port/base|client-cert|client-key
#param = login:password@host:port/base|ca-cert|client-cert|client-key

[pgsql]
# User, pass, host, port(0=default) and db must be entered.
#
# The last parameter is used for SSL connection and is optional.
# It can have the values disable, allow, prefer, require.
# The default option is disable.
#
#param = login:password@host:port/base
#param = login:password@host:port/base|sslmode

[sqlite]
#param = @CMAKE_INSTALL_PREFIX@/@sysconfdir@/users.db

[sections]
# sections are used to define local server properties
# format: name = path path_filter
#   path is a regexp (man regex) to specify where the section is
#   path_filter is a filter to restrict dir names when using mkdir
# the simplest section is: ALL = /* .*
# order *IS* important (first matching section is taken)
#   that means the more generic section should be the last
ALL = /* ^([]\[A-Za-z0-9_.'() \t+-])*$

[cron]
# cronjobs are commands to execute periodically
# syntax: name = minute hour day_of_month month day_of_week command
# the name is ignored, but must be unique
# each field is an integer, of *
# syntax is similar to *nix 'crontab' command (man 5 crontab), except
#  ranges are not supported (for now)
# command should be an absolute path (with args if needed)
# NOTE: if command produce output, it will be logged with level LEVEL_INFO
# the following command will be run the 2 of each month, at 05:00 am
#cron1 = 5 * 2 * * /bin/cleanup.sh

# order *IS* important (the name of the event is ignored)
[events]
#event1 = MKDIR /bin/df

# Here you can define external site commands.
# You must use absolute paths
[custom_commands]
#my_free = /usr/local/bin/free.sh
# this defines the SITE RULES command, which prints the following file
site_rules = !@CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_rules.txt

site_groups = !@CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_groups.txt
site_swho = !@CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_swho.txt
site_users = !@CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_users.txt
site_vfsls = !@CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_vfs.txt
site_who = !@CMAKE_INSTALL_PREFIX@/@sysconfdir@/file_who.txt

# first char is delimiter
# format is e.g name = |/home/vfsroot|/physical/path|
# if delimiter is |
# for windows you can either write
#    vfs = |/home/pollux/K|/cygdrive/k|
# or
#    vfs = |/home/pollux/K|k:|
# you can add permissions at end of line to restrict vfs for some user, group,
# flags or anything allowed by permissions syntax (see PERMISSIONS at end of
# this file for more details)
#   vfs = |/home/pollux/K|k:| +O =user
[vfs]
#vfs1 = |/home/pollux/vfs|/etc|
#vfs2 = |/home/pollux/K|/tmp|

# You can modify custom ftp replies here
# Define message like that if on one line:
#   <message_num> = My custom message
# You can also use files to include messages:
#   message_num = +/path/to/file
# I STRONGLY recommend to leave messages 227 (pasv reply), 257 (pwd) untouched
# most interesting messages are:
#  220 (banner), 230 (welcome message), 221 (logout)
[messages]
#220 = my ftp server ready




#############
# NOTE: Configuration options defined below are currently not implemented
# and therefore serve no purpose at the moment. They will be included in
# a future release of wzdftpd.
#############

# dynamic ip (default: 0)
# if you specify 1 here, the server will try to use your system to detect
# ip changes. 0 deactivates these checks (if you have a static ip).
# if you specify a canonical name, the server will use DNS lookups
#dynamic_ip = xxx.myftp.org
#dynamic_ip = 1
