/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <unistd.h>

#include <pwd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "wzd_debug.h"
#include "wzd_structs.h"

#include "wzd_savecfg.h"
#include "wzd_vfs.h"
#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_perm.h"
#include "wzd_crontab.h"
#include "wzd_backend.h"
#include "wzd_ServerThread.h"



static void save_header (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# This is the main config file\n" );
  fprintf( file, "# lines begining with a # are ignored, as empty lines\n" );
  fprintf( file, "# all lines must be of the form:\n" );
  fprintf( file, "# <name> = <value>\n" );
  fprintf( file, "# (for windows users: without the < > ;-)\n" );
  fprintf( file, "\n" );
}

static void save_serverip (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# Server ip (default: *)\n");
  fprintf( file, "# If you specify an ip, the server will bind to this ip and\n");
  fprintf( file, "# will refuse connections on other interfaces\n");
  fprintf( file, "# ip should be 128 chars max\n");
  fprintf( file, "# if you specify an ip beginning by +, the server will use DNS lookups\n" );
  fprintf( file, "#ip = 127.0.0.1\n" );
  fprintf( file, "#ip = *\n" );
  fprintf( file, "ip = %s\n", mainConfig->ip );
  fprintf( file, "\n" );
}

static void save_dynamicip (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# dynamic ip (default: 0)\n" );
  fprintf( file, "# if you specify 1 here, the server will try to use your system to detect\n");
  fprintf( file, "# ip changes\n");
  fprintf( file, "# 0 desactivates checks\n");
  fprintf( file, "# if you specify an ip beginning by +, the server will use DNS lookups\n");
  fprintf( file, "#dynamic_ip = +xxx.myftp.org\n");
  fprintf( file, "#dynamic_ip = 1\n");
  fprintf( file, "#dynamic_ip = 0\n");
  fprintf( file, "dynamic_ip = %s\n", mainConfig->dynamic_ip);
  fprintf( file, "\n");
}

static void save_listenport (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# Listen port (default: 21)\n");
  fprintf( file, "# IMPORTANT: under unix, you'll need privileges to bind to a system port\n");
  fprintf( file, "# ( < 1024 )\n");
  fprintf( file, "#port = 6969\n");
  fprintf( file, "port = %d\n", mainConfig->port);
  fprintf( file, "\n");
}

static void save_pasvrange (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# PASV range (default: 1025->65536)\n");
  fprintf( file, "# specify this if you want to get a specific range\n");
  fprintf( file, "#pasv_low_range = 2500\n");
  fprintf( file, "#pasv_high_range  = 3000\n");
  fprintf( file, "pasv_low_range = %u\n", mainConfig->pasv_low_range);
  fprintf( file, "pasv_high_range  = %u\n", mainConfig->pasv_high_range);
  fprintf( file, "\n" );
}


static void save_pasvip (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# PASV ip (default: 0.0.0.0)\n");
  fprintf( file, "# specify this if you want to ???????????\n");
  fprintf( file, "#pasv_ip = 62.xxx.xxx.xxx\n");
  fprintf( file, "#pasv_ip = 134.xxx.xx.xx\n");
  fprintf( file, "pasv_ip = %d.%d.%d.%d\n",
      mainConfig->pasv_ip[0], mainConfig->pasv_ip[1],
      mainConfig->pasv_ip[2], mainConfig->pasv_ip[3]);
  fprintf( file, "\n" );
}

static void save_serveruid (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );

  fprintf( file, "# unix only: server will drop privileges to a user after binding port\n");
  fprintf( file, "# you can specify a user login name\n");
  fprintf( file, "# This will only be used if run by root !\n");
  fprintf( file, "#server_uid = pollux\n");
#ifndef WIN32
  {
    struct passwd * p;
#warning "FIXME server does not always have a uid"
    p = getpwuid (getlib_server_uid());
    if (p!=NULL)
      fprintf( file, "server_uid = %s\n", p->pw_name );
  }
#endif /* WIN32 */
  fprintf( file, "\n");
}

static void save_pidfile (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# unix only: file where pid of server will be stored\n");
  fprintf( file, "# (default: /var/run/wzdftpd.pid)\n");
  fprintf( file, "# this is used by init.d script\n");
  fprintf( file, "#pid_file = /var/run/wzdftpd.pid\n");
  fprintf( file, "pid_file = %s\n", mainConfig->pid_file);
  fprintf( file, "\n");
}

static void save_dirmessage (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# the name of the file in each dir that should be added to every answer\n");
  fprintf( file, "#dir_message = .message\n");
  if (mainConfig->dir_message)
    fprintf( file, "dir_message = %s\n", mainConfig->dir_message);
  fprintf( file, "\n");
}

static void save_logging (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# use ONE of the following:\n");
  fprintf( file, "\n");
  fprintf( file, "# log file for server activity\n");
  fprintf( file, "#logfile = /var/log/wzd.log\n");
  if (mainConfig->logfilename)
    fprintf( file, "logfile = %s\n", mainConfig->logfilename);
  fprintf( file, "\n");
  fprintf( file, "# if you prefer syslog (default: yes, except for cygwin)\n");
  fprintf( file, "#use_syslog = 1\n");
  fprintf( file, "use_syslog = %d\n", CFG_GET_OPTION(mainConfig,CFG_OPT_USE_SYSLOG)?1:0);
  fprintf( file, "\n");
  fprintf( file, "# log file for transfered files (default: do not log)\n");
  if (mainConfig->xferlog_name)
    fprintf( file, "xferlog = %s\n", mainConfig->xferlog_name);
  else
    fprintf( file, "#xferlog = /var/log/xferlog\n");
  fprintf( file, "\n");
}

static void save_maxthreads (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# max number of child threads (default: 32)\n");
  fprintf( file, "max_threads = %d\n", mainConfig->max_threads );
  fprintf( file, "\n");
}

static void save_backend (FILE *file)
{
  char *version, *name;

  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# backend to use for auth (default: plaintext)\n");
  fprintf( file, "# you can check backend version with directives > and <\n");
  fprintf( file, "# e.g: backend = plaintext > 120\n");
  fprintf( file, "# ONE BACKEND IS NEEDED !\n");
  fprintf( file, "# backend name SHOULD NEVER contains spaces !\n");
  fprintf( file, "#backend = plaintext > 122\n");

  if (mainConfig->backend.name[0])
  {
    version = backend_get_version (&mainConfig->backend);
    name = backend_get_name (&mainConfig->backend);

    /* TODO XXX FIXME NO NO NO ! need to check if backend has a minimum version, which name it has etc. */
/*#warning "FIXME NO NO NO ! need to check if backend has a minimum version, which name it has etc."*/
    fprintf( file, "backend = libwzd%s.so > %s\n", mainConfig->backend.name, version);

    /* TODO XXX FIXME NO NO NO ! string can be auto-generated with backend name ! */
/*#warning "FIXME NO NO NO ! string can be auto-generated with backend name !"*/
/*    if (strcmp("plaintext", name) == 0)
      fprintf( file, "backend_param_plaintext = %s\n", mainConfig->backend.param);*/
    if (mainConfig->backend.param)
      fprintf( file, "backend_param_%s = %s\n", name, mainConfig->backend.param);

    if (version) free (version);
    if (name) free (name);
  }
  fprintf( file, "\n");
}

static void save_speedlimit (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# speed limits in bytes /sec (approx !)\n");
  fprintf( file, "# 0 = no limit\n");
  fprintf( file, "# ex: max_dl_speed = 300000\n");
  fprintf( file, "max_ul_speed = %d\n", mainConfig->global_ul_limiter.maxspeed);
  fprintf( file, "max_dl_speed = %d\n", mainConfig->global_dl_limiter.maxspeed);
  fprintf( file, "\n");
}

static void save_denyaccessfilesuploaded (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# deny_access_files_uploaded (default: 0)\n");
  fprintf( file, "# if you say 1 here, users trying to download file whereas\n");
  fprintf( file, "# the file is being uploaded will be denied\n");
  fprintf( file, "deny_access_files_uploaded = %d\n",
      CFG_GET_OPTION(mainConfig,CFG_OPT_DENY_ACCESS_FILES_UPLOADED)?1:0);
  fprintf( file, "\n");
}

static void save_hidedottedfiles (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "# hide_dotted_files (default: 0)\n");
  fprintf( file, "# hide files beggining by a '.'\n");
  fprintf( file, "hide_dotted_files = %d\n",
      CFG_GET_OPTION(mainConfig,CFG_OPT_HIDE_DOTTED_FILES)?1:0);
  fprintf( file, "\n");
}

#if 0
static void save_sfvchecker (FILE *file)
{
  WZD_ASSERT_VOID( file != NULL );
  fprintf( file, "## deprecated ? ##\n");
  fprintf( file, "# Available ONLY if compiled with INTERNAL_SFV=1\n");
  fprintf( file, "# Enable internal sfv checking (default: no)\n");
  fprintf( file, "#internal_sfv_checker = 1\n");
  fprintf( file, "\n");
}
#endif



static void save_loglevel (FILE *file)
{
  if (file==NULL) return;
  fprintf( file, "# Log level (default: normal)\n");
  fprintf( file, "# Verbosity of log (only messages >= level will be displayed)\n");
  fprintf( file, "# can be one of (in order):\n");
  fprintf( file, "# lowest, flood, info, normal, high, critical\n");
  fprintf( file, "loglevel = %s\n", loglevel2str(mainConfig->loglevel));
  fprintf( file, "\n");
}

static void save_tlsoptions (FILE *file)
{
  wzd_param_t *current;
  char * tls[4] = { NULL, "explicit", "explicit_strict", "implicit" };

  if (file==NULL) return;
  fprintf( file, "# TLS Options\n");
  fprintf( file, "\n");

  fprintf( file, "# cygwin, version winsock only: you must specify where the tls wrapper dll is\n");
  current = mainConfig->param_list;
  while (current) {
    if (strcmp("tls_wrapper", current->name)==0)
      break;
    current = current->next_param;
  }
  if (current)
    fprintf( file, "param_tls_wrapper = %s\n", (char*)current->param);
  else
    fprintf( file, "#param_tls_wrapper = /usr/share/wzdftpd/wzd_tlswrap.dll\n");
  fprintf( file, "\n");
  
  fprintf( file, "# Certificate (only used in ssl mode, otherwise ignored)\n");
  fprintf( file, "#tls_certificate = /etc/wzdftpd/wzd.pem\n");
/*  if (mainConfig->tls_certificate[0])
    fprintf( file, "tls_certificate = %s\n", mainConfig->tls_certificate);
  else
    fprintf( file, "#tls_certificate = /etc/wzd.pem\n");*/
  fprintf( file, "\n");
  
  fprintf( file, "# Mode (default: explicit)\n");
  fprintf( file, "#  explicit: server starts in clear mode, wait for \"AUTH TLS\" and then switch to ssl\n");
  fprintf( file, "#    you can use explicit mode with normal (clear) mode\n");
  fprintf( file, "#  explicit_strict: server will start in clear mode, but will accept ONLY logins switched to ssl\n");
  fprintf( file, "#  implicit: server starts in ssl mode, no clear connection is possible\n");
  if (mainConfig->tls_type != TLS_NOTYPE)
    fprintf( file, "tls_mode = %s\n", tls[mainConfig->tls_type]);
  else
    fprintf( file, "#tls_mode = explicit\n");
  fprintf( file, "\n");
  
  fprintf( file, "# cipher list (default: ALL)\n");
  fprintf( file, "# you should not use this option or let \"ALL\" unless you know\n");
  fprintf( file, "# what you are doing\n");
  fprintf( file, "# see openssl ciphers, man openssl(1)\n");
/*  if (mainConfig->tls_cipher_list[0])
    fprintf( file, "tls_cipher_list = %s\n", mainConfig->tls_cipher_list);
  else*/
    fprintf( file, "#tls_cipher_list = ALL\n");
  fprintf( file, "\n");
  fprintf( file, "# /TLS\n");
  fprintf( file, "\n");
}

static void save_iprestrictions (FILE *file)
{
  wzd_ip_t * current;
  
  if (file==NULL) return;

  fprintf( file, "##### IP RESTRICTIONS\n");
  fprintf( file, "\n");
  fprintf( file, "# This is global ip checking, BEFORE KNOWING the user name (default NO)\n");
  fprintf( file, "# to enable it, uncomment the following\n");
  fprintf( file, "# 0 = disabled\n");
  fprintf( file, "# 1 = order allow, deny\n");
  fprintf( file, "# 2 = order deny, allow\n");
  fprintf( file, "login_pre_ip_check = %d\n", mainConfig->login_pre_ip_check);
  fprintf( file, "\n");
  fprintf( file, "# now the allowed ip: you can put as many lines login_pre_ip = as you want,\n");
  fprintf( file, "# one per line\n");
  fprintf( file, "# wildcards are accepted (*,?) - NOTE * stops after the first match of the next\n");
  fprintf( file, "#   char\n");
  fprintf( file, "# you can write hostname, two possibilities:\n");
  fprintf( file, "#  +hostname: we will compare gethostbyname(hostname) to user_ip\n");
  fprintf( file, "#  -hostname: we will compare hostname to gethostbyaddr(user_ip)\n");
  fprintf( file, "# this is usefull combined with wildcards (-*.abo.wanadoo.fr)\n");
  fprintf( file, "# YOU CAN ONLY USE WILDCARDS ON LINES BEGINNING BY -\n");
  fprintf( file, "#\n");
  fprintf( file, "# WARNING: to match all ip ending by 0.1 you MUST write *.*.0.1, NOT *.0.1\n");
  fprintf( file, "#login_pre_ip_allowed = +xxx.xxx.org\n");
  fprintf( file, "#login_pre_ip_allowed = -xxx\n");
  fprintf( file, "#login_pre_ip_allowed = +localhost\n");
  fprintf( file, "#login_pre_ip_allowed = +127.0.0.1\n");
  fprintf( file, "#login_pre_ip_allowed = +xxx\n");
  fprintf( file, "#login_pre_ip_allowed = -*.xxx.fr\n");
  
  current = mainConfig->login_pre_ip_allowed;
  while (current) {
    fprintf( file, "login_pre_ip_allowed = %s\n", current->regexp);
    current = current->next_ip;
  }
  fprintf( file, "#login_pre_ip_denied = *\n");
  
  current = mainConfig->login_pre_ip_denied;
  while (current) {
    fprintf( file, "login_pre_ip_denied = %s\n", current->regexp);
    current = current->next_ip;
  }

  fprintf( file, "\n");
}

static void save_vfs (FILE *file)
{
  wzd_vfs_t * current;

  if (file==NULL) return;
  fprintf( file, "##### VFS\n");
  fprintf( file, "# first char is delimiter\n");
  fprintf( file, "# format is e.g vfs = |/home/vfsroot|/physical/path|\n");
  fprintf( file, "# if delimiter is |\n");
  fprintf( file, "# for windows you can either write\n");
  fprintf( file, "#    vfs = |/home/pollux/K|/cygdrive/k|\n");
  fprintf( file, "# or\n");
  fprintf( file, "#    vfs = |/home/pollux/K|k:|\n");
  fprintf( file, "# you can add permissions at end of line to restrict vfs for some user, group,\n");
  fprintf( file, "# flags or anything allowed by permissions syntax (see PERMISSIONS at end of\n");
  fprintf( file, "# this file for more details)\n");
  fprintf( file, "#   vfs = |/home/pollux/K|k:| +O =user\n");
  fprintf( file, "#vfs = |/home/pollux/vfs|/etc|\n");
  fprintf( file, "#vfs = |/home/pollux/K|/tmp|\n");

  current = mainConfig->vfs;
  while (current) {
    fprintf( file, "vfs = |%s|%s|", current->virtual_dir, current->physical_dir);
    if (current->target)
      fprintf (file, " %s\n", current->target);
    else
      fprintf (file, "\n");
    current = current->next_vfs;
  }
  
  fprintf( file, "\n");
}

static void save_modules (FILE *file)
{
  char buffer[256];
  wzd_module_t * current_module;
  wzd_param_t * current_param;

  if (file==NULL) return;
  fprintf( file, "##### MODULES\n");
  fprintf( file, "# modules are dynamic libraries\n");
  fprintf( file, "# order *IS* important\n");
  fprintf( file, "#module = /usr/share/wzdftpd/modules/libwzd_test.so\n");
  fprintf( file, "#module = /usr/share/wzdftpd/modules/libwzd_sfv.so\n");

  current_module = mainConfig->module;
  while (current_module) {
    fprintf( file, "module = %s\n", current_module->name);
    current_module = current_module->next_module;
  }

  fprintf( file, "\n");

  current_param = mainConfig->param_list;
  while (current_param) {
    /* TODO param_tls_wrapper is so specific ? */
    if (strcmp("tls_wrapper", current_param->name)!=0)
      if (current_param->length<256) {
        memcpy(buffer,current_param->param,current_param->length);
        buffer[current_param->length] = '\0';
        fprintf( file, "param_%s = %s\n", current_param->name,buffer);
      }
    current_param = current_param->next_param;
  }

  fprintf( file, "\n");
}

static void save_sections (FILE *file)
{
  wzd_section_t * current;
  
  if (file==NULL) return;
  fprintf( file, "##### SECTIONS\n");
  fprintf( file, "# sections are used to define local server properties\n");
  fprintf( file, "# format: section = name path path_filter\n");
  fprintf( file, "#   path is a regexp to specify to specify where the section is\n");
  fprintf( file, "#   path_filter is a filter to restrict dir names when using mkdir\n");
  fprintf( file, "# the simplest section is: ALL /* *\n");
  fprintf( file, "# order *IS* important (first matching section is taken)\n");
  fprintf( file, "#   that means the more generic section should be the last\n");
  fprintf( file, "#section = ALL /* ^([]\\[A-Za-z0-9_.'() \\t+-])*$\n");

  
  current = mainConfig->section_list;
  while (current) {
    fprintf( file, "section = %s %s %s\n",current->sectionname,
        current->sectionmask,
        current->sectionre);
    current = current->next_section;
  }

  fprintf( file, "\n");
}

static void save_cscripts (FILE *file)
{
  wzd_hook_t * current;
  
  if (file==NULL) return;
  fprintf( file, "##### CUSTOM SCRIPTS\n");
  fprintf( file, "# Custom scripts (or binaries) to be executed before/after certain commands\n");
  fprintf( file, "# order *IS* important\n");
  fprintf( file, "#cscript = MKDIR /bin/df\n");

  current = mainConfig->hook;
  while (current) {
    /* XXX filter by opt and external_command fields ?? */
    if ((!current->opt) && (current->external_command))
      fprintf( file, "cscript = %s %s\n", event2str(current->mask), current->external_command);
    current = current->next_hook;
  }

  fprintf( file, "\n");
}

static void save_sitecmd (FILE *file)
{
  wzd_hook_t * current;
  
  if (file==NULL) return;
  fprintf( file, "##### CUSTOM SITE COMMANDS\n");
  fprintf( file, "# Here you can define external site commands.\n");
  fprintf( file, "#site_cmd = my_free ./free.sh\n");

  current = mainConfig->hook;
  while (current) {
    /* XXX filter by opt and external_command fields ?? */
    if ((current->opt) && (current->external_command))
      fprintf( file, "site_cmd = %s %s\n", current->opt, current->external_command);
    current = current->next_hook;
  }

  fprintf( file, "\n");
}

static void save_sitefile (FILE *file)
{
  if (file==NULL) return;
  fprintf( file, "##### SITE FILES\n");
  fprintf( file, "sitefile_ginfo  = %s\n", mainConfig->site_config.file_ginfo);
  fprintf( file, "sitefile_group  = %s\n", mainConfig->site_config.file_group);
  fprintf( file, "sitefile_groups = %s\n", mainConfig->site_config.file_groups);
  fprintf( file, "sitefile_help = %s\n", mainConfig->site_config.file_help);
  fprintf( file, "sitefile_rules  = %s\n", mainConfig->site_config.file_rules);
  fprintf( file, "sitefile_swho = %s\n", mainConfig->site_config.file_swho);
  fprintf( file, "sitefile_user = %s\n", mainConfig->site_config.file_user);
  fprintf( file, "sitefile_users  = %s\n", mainConfig->site_config.file_users);
  fprintf( file, "sitefile_who  = %s\n", mainConfig->site_config.file_who);
  fprintf( file, "\n");
}

static void save_cronjobs (FILE *file)
{
  wzd_cronjob_t * current;
  extern wzd_cronjob_t * crontab;
  
  if (file==NULL) return;
  fprintf( file, "##### CRON JOBS\n");
  fprintf( file, "# cronjobs are commands to execute periodically\n");
  fprintf( file, "# syntax: cronjob = minute hour day_of_month month day_of_week command\n");
  fprintf( file, "# each field is an integer, of *\n");
  fprintf( file, "# syntax is similar to *nix 'crontab' command (man 5 crontab), except\n");
  fprintf( file, "#  ranges are not supported (for now)\n");
  fprintf( file, "# command should be an absolute path (with args if needed)\n");
  fprintf( file, "# NOTE: if command produce output, it will be logged with level LEVEL_INFO\n");
  fprintf( file, "# the following command will be run the 2 of each month, at 05:00 am\n");
  fprintf( file, "#cronjob = 5 * 2 * * /bin/cleanup.sh\n");
  
  current = crontab;
  while (current) {
    if ( current->hook && ! current->hook->hook ) {
      fprintf( file, "cronjob = %s %s %s %s %s %s\n",
          current->minutes,
          current->hours,
          current->day_of_month,
          current->month,
          current->day_of_week,
          (char*)current->hook->hook
          );
    }
    current = current->next_cronjob;
  }

  fprintf( file, "\n");
}

static void save_custommessages (FILE *file)
{
  extern char *msg_tab[HARD_MSG_LIMIT];
  int i;

  if (file==NULL) return;
  fprintf( file, "##### CUSTOM MESSAGES\n");
  fprintf( file, "# You can modify custom ftp replies here\n");
  fprintf( file, "# Define message like that if on one line:\n");
  fprintf( file, "#   message_<num> = My custom message\n");
  fprintf( file, "# You can also use files to include messages:\n");
  fprintf( file, "#   message_num = +/path/to/file\n");
  fprintf( file, "# I STRONGLY recommend to leave messages 227 (pasv reply), 250 (cwd) untouched\n");
  fprintf( file, "# most interesting messages are:\n");
  fprintf( file, "#  220 (banner), 230 (welcome message), 221 (logout)\n");
  fprintf( file, "#message_220 = pollux ftp server ready\n");

  /* TODO XXX FIXME BUG !
   * some custom messages contains CR ... (e.g: 211)
   */
  /* XXX which are custom messages ?? */
  for( i = 0 ; i < HARD_MSG_LIMIT ; i++ )
    if (msg_tab[i])
      fprintf( file, "message_%d = %s\n", i, msg_tab[i]);

  fprintf( file, "\n");
}

/* XXX do we need this part ? */
#if 0
static void save_inclusions (FILE *file)
{
  if (file==NULL) return;
  fprintf( file, "##### INCLUSIONS\n");
  fprintf( file, "# You can include other files\n");
  fprintf( file, "# maximum recursion is 16 (too big IMHO)\n");
  fprintf( file, "#include permissions.cfg\n");
  fprintf( file, "\n");
}
#endif

static void save_permissions (FILE *file)
{
#if 0
  char buffer[256];
  char * ptr;
  unsigned int length;
  wzd_command_perm_t * current;
  wzd_command_perm_entry_t * entry;
#endif /* 0 */
  
  if (file==NULL) return;
  fprintf( file, "##### PERMISSIONS\n");
  fprintf( file, "# Permissions lines begin by -\n");
  fprintf( file, "# permissions can be of form: -group =user +flag or *\n");
  fprintf( file, "# you can use negations : !*\n");
  fprintf( file, "# REMEMBER that the FIRST corresponding rule is applied, so order is important (never put * first !)\n");
  fprintf( file, "# ex: -site_who = =admin -group1 +F =toto\n");
  fprintf( file, "#-delete = -admin\n");

  /** \bug this code is f*cked ! it must now use wzd_command_t, and
   * perm2str() !
   */
#if 0
  /* TODO XXX FIXME perm list will be printed in the reverse order ! */
  current = mainConfig->perm_list;
  while (current) {
    /* parse current->entry_list */
    ptr = buffer;
    length=0;
    entry = current->entry_list;
    while (entry) {
      *ptr++ = ' ';
      length ++;
      if (strcmp(entry->target,"*")!=0) {
        switch(entry->cp) {
          case CPERM_USER: *ptr++ = '='; break;
          case CPERM_GROUP: *ptr++ = '-'; break;
          case CPERM_FLAG: *ptr++ = '+'; break;
        }
        length ++;
      }
      strncpy(ptr,entry->target,256-length);
      length += strlen(ptr);
      ptr = buffer+length;
      entry = entry->next_entry;
    }
    buffer[length]='\0';
    fprintf( file, "-%s =%s\n",
        current->command_name,
        buffer);
    current = current->next_perm;
  }
#endif /* 0 */

  fprintf( file, "  \n");
}
 







int wzd_savecfg( void )
{
  FILE *file;
  char filenamenew[256];
  extern char configfile_name[256];

  strncpy (filenamenew, configfile_name, sizeof(filenamenew));
  strcat (filenamenew, ".NEW");

  file = fopen(filenamenew,"w");
  if(!file) {
    out_log(LEVEL_CRITICAL,"Could not open file %s !\n",filenamenew);
    return -1;
  }

  save_header (file);
  save_serverip (file);
  save_dynamicip (file);
  save_listenport (file);
  save_pasvrange (file);
  save_pasvip (file);
  save_serveruid (file);
  save_pidfile (file);
  save_dirmessage (file);
  save_logging (file);
  save_maxthreads (file);
  save_backend (file);
  save_speedlimit (file);
  save_denyaccessfilesuploaded (file);
  save_hidedottedfiles (file);

#if 0
  save_sfvchecker (file);
#endif
  save_loglevel (file);
  save_tlsoptions (file);
  save_iprestrictions (file);
  save_vfs (file);
  save_modules (file);
  save_sections (file);
  save_cscripts (file);
  save_sitecmd (file);
  save_sitefile (file);
  save_cronjobs (file);
  save_custommessages (file);
  save_permissions (file);

#if 0
  save_inclusions (file);
#endif
 
  fclose(file);

#ifndef _MSC_VER
#warning "Rename files, .NEW -> .cfg"
#endif

  return 0;
}
