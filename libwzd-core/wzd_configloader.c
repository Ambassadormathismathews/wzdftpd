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

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_string.h"
#include "wzd_utf8.h"
#include "wzd_configfile.h"
#include "wzd_configloader.h"
#include "wzd_crontab.h"

#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_section.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

static void _cfg_parse_commands(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_crontab(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_modules(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_pre_ip(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_sections(const wzd_configfile_t * file, wzd_config_t * config);
static void _cfg_parse_sitefiles(const wzd_configfile_t * file, wzd_config_t * config);




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
}

/** \brief Frees a wzd_config_t (using wzd_free() )
 */
void cfg_free(wzd_config_t * cfg)
{
  WZD_ASSERT_VOID(cfg != NULL);

  commands_fini(cfg->commands_list);

  wzd_free(cfg);
}


/** \brief Load a \a wzd_configfile_t into a \a wzd_config_t
 */
wzd_config_t * cfg_store(wzd_configfile_t * file, int * error)
{
  wzd_config_t * cfg;
  wzd_string_t * str, * ptr;
  unsigned long ul;
  int ret;
  int i;

  cfg = wzd_malloc(sizeof(*cfg));
  if (!cfg) { if (error) *error = E_NOMEM; return NULL; }

  cfg_init(cfg);
  cfg->cfg_file = file;

  /* DISABLE_TLS */
  str = config_get_string(file, "GLOBAL", "disable_tls", NULL);
  if (str) {
    if (strcasecmp(str_tochar(str),"allow")==0 || strcmp(str_tochar(str),"1")==0) {
      CFG_SET_OPTION(cfg,CFG_OPT_DISABLE_TLS);
    }
    str_deallocate(str);
  }

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

  _cfg_parse_sections(file, cfg);

  _cfg_parse_commands(file, cfg);
  _cfg_parse_modules(file, cfg);

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

static void _cfg_parse_commands(const wzd_configfile_t * file, wzd_config_t * config)
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

