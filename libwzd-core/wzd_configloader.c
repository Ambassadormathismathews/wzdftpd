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
/** \file wzd_configloader.c
 * \brief Load config file from wzd_configfile_t to memory
 */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include <fcntl.h> /* O_RDONLY */

#include <ctype.h> /* isspace */

#ifndef WIN32
#include <grp.h>	/* getgrnam() */
#include <pwd.h>	/* getpwnam() */
#endif

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_string.h"
#include "wzd_utf8.h"
#include "wzd_configfile.h"
#include "wzd_configloader.h"
#include "wzd_crontab.h"
#include "wzd_events.h"
#include "wzd_libmain.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_section.h"
#include "wzd_socket.h"
#include "wzd_site.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

static void _cfg_parse_crontab(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_custom_commands(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_events(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_messages(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_modules(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_permissions(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_pre_ip(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_sections(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_sitefiles(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_vfs(const wzd_configfile_t * file, wzd_config_t * config);




void cfg_init(wzd_config_t * cfg)
{
  WZD_ASSERT_VOID(cfg != NULL);

  memset(cfg, 0, sizeof(*cfg));

  /* default values */
  cfg->port = 21;
  cfg->pasv_low_range = 1025;
  cfg->pasv_high_range = 65535;

  cfg->max_threads = 32;
  cfg->umask = 0775;
  cfg->data_buffer_length = 16384;

#if !defined(DEBUG)
#if !defined(_WIN32)
    CFG_SET_OPTION(cfg,CFG_OPT_USE_SYSLOG);
#endif /* _WIN32 */
#else /* DEBUG */
    CFG_CLR_OPTION(cfg,CFG_OPT_USE_SYSLOG);
#endif

  cfg->loglevel = LEVEL_NORMAL;

#if (defined (__FreeBSD__) && (__FreeBSD__ < 5)) || defined(WIN32) || defined(__APPLE__)
  cfg->logfilemode = O_CREAT | O_WRONLY | O_APPEND;
#else /* ! BSD */
  cfg->logfilemode = O_CREAT | O_WRONLY | O_APPEND | O_SYNC;
#endif /* BSD */

  cfg->xferlog_fd = -1;
  cfg->controlfd = -1;

  commands_init(&cfg->commands_list);
  commands_add_defaults(cfg->commands_list);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  cfg->tls_type = TLS_EXPLICIT;
#else
  cfg->tls_type = TLS_NOTYPE;
#endif

  cfg->event_mgr = wzd_malloc(sizeof(wzd_event_manager_t));
  event_mgr_init(cfg->event_mgr);
}

/** \brief Frees a wzd_config_t (using wzd_free() )
 */
void cfg_free(wzd_config_t * cfg)
{
  WZD_ASSERT_VOID(cfg != NULL);

  wzd_free(cfg->logfilename);
  wzd_free(cfg->config_filename);
  wzd_free(cfg->pid_file);
  wzd_free(cfg->dir_message);
  wzd_free(cfg->xferlog_name);
  wzd_free(cfg->logdir);
  wzd_free(cfg->backend.name);

  wzd_free(mainConfig->site_config.file_ginfo);
  wzd_free(mainConfig->site_config.file_group);
  wzd_free(mainConfig->site_config.file_groups);
  wzd_free(mainConfig->site_config.file_help);
  wzd_free(mainConfig->site_config.file_rules);
  wzd_free(mainConfig->site_config.file_swho);
  wzd_free(mainConfig->site_config.file_user);
  wzd_free(mainConfig->site_config.file_users);
  wzd_free(mainConfig->site_config.file_vfs);
  wzd_free(mainConfig->site_config.file_who);

  event_mgr_free(cfg->event_mgr);
  wzd_free(cfg->event_mgr);

  commands_fini(cfg->commands_list);

  config_free(cfg->cfg_file);

  memset(cfg, 0, sizeof(wzd_config_t));
  wzd_free(cfg);
}


/** \brief Load a \a wzd_configfile_t into a \a wzd_config_t
 */
wzd_config_t * cfg_store(wzd_configfile_t * file, int * error)
{
  wzd_config_t * cfg;
  wzd_string_t * str, * ptr;
  char * p;
  unsigned long ul;
  int ret;
  int i;

  cfg = wzd_malloc(sizeof(wzd_config_t));
  if (!cfg) { if (error) *error = E_NOMEM; return NULL; }

  cfg_init(cfg);
  cfg->cfg_file = file;

  /* DATA_BUFFER_LENGTH */
  str = config_get_string(file, "GLOBAL", "data_buffer_length", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0')
      cfg->data_buffer_length = ul;
    else
      out_log(LEVEL_HIGH,"ERROR invalid value for data_buffer_length\n");
    str_deallocate(str);
  }

  /* DENY_ACCESS_FILES_UPLOADED */
  str = config_get_string(file, "GLOBAL", "deny_access_files_uploaded", NULL);
  if (str) {
    if (strcasecmp(str_tochar(str),"allow")==0 || strcmp(str_tochar(str),"1")==0) {
      CFG_SET_OPTION(cfg,CFG_OPT_DENY_ACCESS_FILES_UPLOADED);
    }
    str_deallocate(str);
  }

  /* DIR_MESSAGE */
  str = config_get_string(file, "GLOBAL", "dir_message", NULL);
  if (str) {
    cfg->dir_message = strdup(str_tochar(str));
    str_deallocate(str);
  }

  /* DISABLE_IDENT */
  str = config_get_string(file, "GLOBAL", "disable_ident", NULL);
  if (str) {
    if (strcasecmp(str_tochar(str),"allow")==0 || strcmp(str_tochar(str),"1")==0) {
      CFG_SET_OPTION(cfg,CFG_OPT_DISABLE_IDENT);
    }
    str_deallocate(str);
  }

  /* DISABLE_TLS */
  str = config_get_string(file, "GLOBAL", "disable_tls", NULL);
  if (str) {
    if (strcasecmp(str_tochar(str),"allow")==0 || strcmp(str_tochar(str),"1")==0) {
      CFG_SET_OPTION(cfg,CFG_OPT_DISABLE_TLS);
    }
    str_deallocate(str);
  }

  /* DYNAMIC_IP */
  str = config_get_string(file, "GLOBAL", "dynamic_ip", NULL);
  if (str) {
    strncpy(cfg->dynamic_ip,str_tochar(str),MAX_IP_LENGTH);
    str_deallocate(str);
  }

  /* HIDE_DOTTED_FILES */
  str = config_get_string(file, "GLOBAL", "hide_dotted_files", NULL);
  if (str) {
    if (strcasecmp(str_tochar(str),"allow")==0 || strcmp(str_tochar(str),"1")==0) {
      CFG_SET_OPTION(cfg,CFG_OPT_HIDE_DOTTED_FILES);
    }
    str_deallocate(str);
  }

  /* IP XXX to be implemented */

  /* LOGFILE */
  str = config_get_string(file, "GLOBAL", "logfile", NULL);
  if (str) {
    cfg->logfilename = strdup(str_tochar(str));
    str_deallocate(str);
  } else {
    out_err(LEVEL_CRITICAL,"No logfile found !\n");
    cfg_free(cfg);
    return NULL;
  }

  /* LOGLEVEL */
  str = config_get_string(file, "GLOBAL", "loglevel", NULL);
  if (str) {
    i = str2loglevel(str_tochar(str));
    if( i==-1 ) {
      out_err(LEVEL_HIGH,"valid levels are lowest, flood, info, normal, high, critical\n");
      cfg_free(cfg);
      return NULL;
    }
    cfg->loglevel = i;
    str_deallocate(str);
  }

  /* MAX_DL_SPEED */
  str = config_get_string(file, "GLOBAL", "max_dl_speed", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0')
      cfg->global_dl_limiter.maxspeed = ul;
    str_deallocate(str);
  }

  /* MAX_THREADS */
  str = config_get_string(file, "GLOBAL", "max_threads", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0') {
      if (ul > 1 && ul < 2000) /** XXX hardlimit */
        cfg->max_threads = ul;
      else
        out_log(LEVEL_HIGH,"ERROR max_threads must be between 1 and 2000\n");
    }
    str_deallocate(str);
  }

  /* MAX_UL_SPEED */
  str = config_get_string(file, "GLOBAL", "max_ul_speed", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0')
      cfg->global_ul_limiter.maxspeed = ul;
    str_deallocate(str);
  }

  /* PASV_IP */
  str = config_get_string(file, "GLOBAL", "pasv_ip", NULL);
  if (str) {
    char host_ip[64];
    if (!socket_getipbyname(str_tochar(str), host_ip, sizeof(host_ip))) {
      memcpy(cfg->pasv_ip,host_ip,4); /** \bug pasv_ip does not support IPv6 ! */
    } else {
      out_log(LEVEL_HIGH,"ERROR Could NOT resolve ip %s (pasv_ip)\n",str_tochar(str));
    }
    str_deallocate(str);
  }

  /* PASV_LOW_RANGE */
  str = config_get_string(file, "GLOBAL", "pasv_low_range", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0')
      cfg->pasv_low_range = ul;
    str_deallocate(str);
  }

  /* PASV_HIGH_RANGE */
  str = config_get_string(file, "GLOBAL", "pasv_high_range", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0')
      cfg->pasv_high_range = ul;
    str_deallocate(str);
  }

  /* PID_FILE */
  str = config_get_string(file, "GLOBAL", "pid_file", NULL);
  if (str) {
    cfg->pid_file = strdup(str_tochar(str));
    str_deallocate(str);
  }

  /* PORT */
  str = config_get_string(file, "GLOBAL", "port", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),NULL,0);
    if (ul > 65535) {
      out_err(LEVEL_CRITICAL,"Invalid port number !\n");
      cfg_free(cfg);
      return NULL;
    }
    cfg->port = ul;
    str_deallocate(str);
  }

  /* SERVER_GID */
  str = config_get_string(file, "GLOBAL", "server_gid", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0') { /* numeric id */
      setlib_server_gid(ul);
    }
#ifndef WIN32
    else { /* not a number, try a group name */
      struct group * g;
      g = getgrnam(str_tochar(str));
      endgrent();
      if (g) {
        setlib_server_gid(g->gr_gid);
      } else {
        out_err(LEVEL_HIGH,"server_gid: could not find gid for group %s\n",str_tochar(str));
      }
    }
#endif
    str_deallocate(str);
  }

  /* SERVER_UID */
  str = config_get_string(file, "GLOBAL", "server_uid", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,0);
    if (p && *p == '\0') { /* numeric id */
      setlib_server_uid(ul);
    }
#ifndef WIN32
    else { /* not a number, try a user name */
      struct passwd * p;
      p = getpwnam(str_tochar(str));
      endpwent();
      if (p) {
        setlib_server_uid(p->pw_uid);
      } else {
        out_err(LEVEL_HIGH,"server_uid: could not find uid for user %s\n",str_tochar(str));
      }
    }
#endif
    str_deallocate(str);
  }

  /* TLS MODE */
  str = config_get_string(file, "GLOBAL", "tls_mode", NULL);
  if (str) {
    if (strcasecmp(str_tochar(str),"explicit")==0) {
      cfg->tls_type = TLS_EXPLICIT;
    }
    else if (strcasecmp(str_tochar(str),"explicit_strict")==0) {
      cfg->tls_type = TLS_STRICT_EXPLICIT;
    }
    else if (strcasecmp(str_tochar(str),"implicit")==0) {
      cfg->tls_type = TLS_IMPLICIT;
    }
    else {
      out_err(LEVEL_CRITICAL,"Invalid TLS mode !\n");
    }
    str_deallocate(str);
  }

  /* UMASK */
  str = config_get_string(file, "GLOBAL", "umask", NULL);
  if (str) {
    ul = strtoul(str_tochar(str),&p,8);
    if (p && *p == '\0')
      cfg->umask = ul;
    else
      out_log(LEVEL_HIGH,"ERROR invalid value for umask\n");
    str_deallocate(str);
  }

  /* XFERLOG */
  str = config_get_string(file, "GLOBAL", "xferlog", NULL);
  if (str) {
    cfg->xferlog_name = strdup(str_tochar(str));
    str_deallocate(str);
  }

  /* BACKEND */
  str = config_get_string(file, "GLOBAL", "backend", NULL);
  if (str) {
    char * predicate = NULL, * version = NULL;
    ptr = str_read_token(str);
    if (ptr) {
      ret = backend_validate(str_tochar(ptr),predicate,version);
      if (!ret) {
        if (cfg->backend.handle == NULL) {
          /*        i = backend_init(value);*/
          cfg->backend.name = wzd_strdup(str_tochar(ptr));
        } else { /* multiple backends ?? */
          ret=0;
        }
      }
    }
    str_deallocate(ptr);
    str_deallocate(str);
  }


  _cfg_parse_pre_ip(file, cfg);

  _cfg_parse_sitefiles(file, cfg);

  _cfg_parse_messages(file, cfg);
  _cfg_parse_sections(file, cfg);
  _cfg_parse_vfs(file, cfg);

  /* custom commands must be added before permissions */
  _cfg_parse_custom_commands(file, cfg);
  _cfg_parse_events(file, cfg);
  _cfg_parse_modules(file, cfg);
  _cfg_parse_permissions(file, cfg);

  _cfg_parse_crontab(file, cfg);

  return cfg;
}

/******************* STATIC ******************/

static void _cfg_parse_pre_ip(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i, value;
  int err;
  char * address, * check;
  
  array = config_get_keys(file,"pre_ip_check",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    address = (char*)str_tochar(array[i]);
    if (!address) continue;
    check = config_get_value(file, "pre_ip_check", address);
    if (!check) continue;

    if (strcasecmp(check,"allow")==0 || strcmp(check,"1")==0) value = 1;
    else if (strcasecmp(check,"deny")==0 || strcmp(check,"0")==0) value = 0;
    else {
      out_err(LEVEL_HIGH,"ERROR while parsing pre_ip %s: must be allow or deny\n",address);
      continue;
    }

    err = ip_add_check(&config->login_pre_ip_checks,address,value);
    if (err) {
      /* print error message but continue parsing */
      out_err(LEVEL_HIGH,"ERROR while parsing pre_ip %s\n",address);
    }

  }

  str_deallocate_array(array);
}

static void _cfg_parse_crontab(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * cron_name;
  wzd_string_t * cron_value;
  wzd_string_t * min, * hour, * day, * month, * day_of_week;
  
  array = config_get_keys(file,"cron",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    cron_name = (char*)str_tochar(array[i]);
    if (!cron_name) continue;
    cron_value = config_get_string(file, "cron", cron_name, NULL);

    min = str_tok(cron_value," \t");
    hour = str_tok(cron_value," \t");
    day = str_tok(cron_value," \t");
    month = str_tok(cron_value," \t");
    day_of_week = str_tok(cron_value," \t");

    if (min && hour && day && month && day_of_week) {

      if (cronjob_add(&config->crontab,NULL,str_tochar(cron_value),
            str_tochar(min),str_tochar(hour),str_tochar(day),
            str_tochar(month),str_tochar(day_of_week))) {
        out_log(LEVEL_HIGH,"ERROR while adding cron entry [cron] : %s\n",cron_name);
      } else {
        out_log(LEVEL_INFO,"Added cron entry : %s\n",cron_name);
      }

    } else {
      out_log(LEVEL_HIGH,"ERROR Invalid cron entry found at entry [cron] : %s\n",cron_name);
    }
    str_deallocate(min); str_deallocate(hour); str_deallocate(day);
    str_deallocate(month); str_deallocate(day_of_week);
    str_deallocate(cron_value);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_custom_commands(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * command_name;
  wzd_string_t * value;
  
  array = config_get_keys(file,"custom_commands",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    command_name = (char*)str_tochar(array[i]);
    if (!command_name) continue;
    value = config_get_string(file, "custom_commands", command_name, NULL);

    /** \bug the following does NOT work if the command is not a SITE command */

    /* add custom command */
    if (commands_add_external(config->commands_list,command_name,value)) {
      out_log(LEVEL_HIGH,"ERROR while adding custom command: %s\n",command_name);
      str_deallocate(value);
      continue;
    }

    /* default permission */
    if (commands_set_permission(config->commands_list,command_name,"*")) {
      out_log(LEVEL_HIGH,"ERROR setting default permission to custom command %s\n",command_name);
      str_deallocate(value);
      /** \bug XXX remove command from   config->commands_list */
      continue;
    }

    out_log(LEVEL_INFO,"Added custom command %s : %s\n",command_name,str_tochar(value));

    str_deallocate(value);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_events(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * event_name;
  wzd_string_t * event, * value;
  unsigned long eventmask;
  
  array = config_get_keys(file,"events",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    event_name = (char*)str_tochar(array[i]);
    if (!event_name) continue;
    value = config_get_string(file, "events", event_name, NULL);
    event = str_tok(value," \t");

    if (event && value) {
      eventmask = str2event(str_tochar(event));
      if (eventmask) {
        wzd_string_t * command;
        /* split parameters */
        command = str_read_token(value);
        if (event_connect_external(config->event_mgr, eventmask, command, value)==0) {
/*        if (!hook_add_external(&config->hook,eventmask,str_tochar(value))) {*/
          out_log(LEVEL_INFO,"Added event %s : [%s] [%s]\n",str_tochar(event),str_tochar(command),str_tochar(value));
        } else {
          out_log(LEVEL_HIGH,"ERROR while adding event: %s\n",event_name);
        }
      }
    } else {
      out_log(LEVEL_HIGH,"ERROR incorrect syntax for event: %s\n",event_name);
    }

    str_deallocate(event);
    str_deallocate(value);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_messages(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * key_name, * p;
  wzd_string_t * value;
  char * message;
  unsigned long ul;
  
  array = config_get_keys(file,"messages",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    key_name = (char*)str_tochar(array[i]);
    if (!key_name) continue;
    value = config_get_string(file, "messages", key_name, NULL);
    if (!value) continue;

    ul = strtoul(key_name,&p,0);
    if (p && *p == '\0' && ul < HARD_MSG_LIMIT) {
      /* memory will be freed at server exit */
      message = wzd_strdup(str_tochar(value));
      setMessage(message,(int)ul);
    } else
      out_log(LEVEL_HIGH,"ERROR invalid value for message number (key %s)\n",key_name);

    str_deallocate(value);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_modules(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * module_name;
  wzd_string_t * permission;
  
  array = config_get_keys(file,"modules",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    module_name = (char*)str_tochar(array[i]);
    if (!module_name) continue;
    permission = config_get_string(file, "modules", module_name, NULL);

    if (strcasecmp(str_tochar(permission),"allow")==0 || strcmp(str_tochar(permission),"1")==0) {
      if (module_check(module_name)) {
        out_err(LEVEL_HIGH,"ERROR module name [%s] is invalid\n",module_name);
        str_deallocate(permission);
        continue;
      }
      err = module_add(&config->module, module_name);
      if (err) {
        /* print error message but continue parsing */
        out_err(LEVEL_HIGH,"ERROR while parsing module %s\n",module_name);
      }
    } else {
      out_log(LEVEL_INFO,"not loading module %s, not enabled in config\n",module_name);
    }

    str_deallocate(permission);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_permissions(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * permission_name;
  wzd_string_t * permission;
  
  array = config_get_keys(file,"perms",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    permission_name = (char*)str_tochar(array[i]);
    if (!permission_name) continue;
    ascii_lower(permission_name,strlen(permission_name));
    permission = config_get_string(file, "perms", permission_name, NULL);

    err = commands_set_permission(config->commands_list, permission_name, str_tochar(permission));
    if (err) {
      /* print error message but continue parsing */
      out_err(LEVEL_HIGH,"ERROR while parsing permission %s, ignoring\n",permission_name);
    }

    str_deallocate(permission);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_sections(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * section_name;
  wzd_string_t * section, * section_mask;
  
  array = config_get_keys(file,"sections",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    section_name = (char*)str_tochar(array[i]);
    if (!section_name) continue;
    section = config_get_string(file, "sections", section_name, NULL);

    section_mask = str_read_token(section);
    if (section_mask) {
      /* section now contains the filter used to create new directories/files */
      if (section_add(&config->section_list,section_name,str_tochar(section_mask),str_tochar(section))) {
        out_log(LEVEL_HIGH,"ERROR: error when adding section %s, check section mask and filter\n",section_name);
      }
      str_deallocate(section_mask);
    } else {
      out_log(LEVEL_HIGH,"ERROR: incorrect section definition for %s, missing section_mask\n",section_name);
    }
    str_deallocate(section);
  }

  str_deallocate_array(array);
}

static void _cfg_parse_sitefiles(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t * filename;
  
  filename = config_get_string(file, "GLOBAL", "sitefile_ginfo", NULL);
  if (filename) { config->site_config.file_ginfo = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);
  
  filename = config_get_string(file, "GLOBAL", "sitefile_group", NULL);
  if (filename) { config->site_config.file_group = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);
  
  filename = config_get_string(file, "GLOBAL", "sitefile_groups", NULL);
  if (filename) { config->site_config.file_groups = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);
  
  filename = config_get_string(file, "GLOBAL", "sitefile_help", NULL);
  if (filename) { config->site_config.file_help = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);
  
  filename = config_get_string(file, "GLOBAL", "sitefile_swho", NULL);
  if (filename) { config->site_config.file_swho = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);
  
  filename = config_get_string(file, "GLOBAL", "sitefile_user", NULL);
  if (filename) { config->site_config.file_user = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);

  filename = config_get_string(file, "GLOBAL", "sitefile_users", NULL);
  if (filename) { config->site_config.file_users = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);

  filename = config_get_string(file, "GLOBAL", "sitefile_who", NULL);
  if (filename) { config->site_config.file_who = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);

  filename = config_get_string(file, "GLOBAL", "sitefile_vfs", NULL);
  if (filename) { config->site_config.file_vfs = wzd_strdup(str_tochar(filename)); }
  str_deallocate(filename);
}

static void _cfg_parse_vfs(const wzd_configfile_t * file, wzd_config_t * config)
{
  wzd_string_t ** array;
  int i;
  int err;
  char * key_name;
  wzd_string_t * value, * physical_path, * virtual_path, * permissions;
  char delimiter[2];
  
  array = config_get_keys(file,"vfs",&err);
  if (!array) return;

  for (i=0; array[i] != NULL; i++) {
    key_name = (char*)str_tochar(array[i]);
    if (!key_name) continue;
    value = config_get_string(file, "vfs", key_name, NULL);
    if (!value) continue;

    delimiter[0] = str_tochar(value)[0];
    delimiter[1] = '\0';
    str_erase(value, 0, 1);

    virtual_path = str_tok(value,delimiter);
    physical_path = str_tok(value,delimiter);
    permissions = str_tok(value,delimiter);
    if (permissions) str_trim_left(permissions);

    if (physical_path && virtual_path) {
      if (permissions)
        err = vfs_add_restricted(&config->vfs,str_tochar(virtual_path),str_tochar(physical_path),str_tochar(permissions));
      else
        err = vfs_add(&config->vfs,str_tochar(virtual_path),str_tochar(physical_path));
      if (!err) {
        out_log(LEVEL_INFO,"Added vfs %s => %s\n",str_tochar(physical_path),str_tochar(virtual_path));
      } else {
        out_log(LEVEL_HIGH,"ERROR while adding vfs %s\n",key_name);
        out_log(LEVEL_HIGH,"Please check destination exists and you have correct permissions\n");
      }
    } else {
      out_log(LEVEL_HIGH,"ERROR incorrect syntax for vfs %s\n",key_name);
    }

    str_deallocate(permissions);
    str_deallocate(virtual_path);
    str_deallocate(physical_path);
    str_deallocate(value);
  }

  str_deallocate_array(array);
}

