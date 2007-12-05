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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <io.h>
#else
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <time.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h> /* WZD_MODULE_INIT */
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_file.h>

#include "libwzd_dupecheck_dupelog.h"

MODULE_NAME(dupecheck);
MODULE_VERSION(100);

static event_reply_t dupecheck_event_preupload(const char * args);
static event_reply_t dupecheck_event_postupload(const char * args);

/***** EVENT HOOKS *****/
static event_reply_t dupecheck_event_preupload(const char * args)
{
  int ret;

  const char *filename, *username;
  char *str = strdup(args), *ptr;
  username = strtok_r(str, " ", &ptr);
  filename = ptr;

  if (strrchr(filename, '/') != NULL)
  {
    filename = strrchr(filename, '/') + 1;
  }

  ret = dupelog_is_upload_allowed(filename);

  free(str);

  return ret;
}

static event_reply_t dupecheck_event_postupload(const char * args)
{
  int ret;

  char *filename, *path, *username;
  char *str = strdup(args), *ptr;

  username = strtok_r(str, " ", &ptr);
  // TODO: Make sure path is absolute!
  path = ptr;
  filename = strrchr(path, '/');

  if (filename == NULL)
  {
    // TODO: Make sure this is an absolute path,
    // so make path = getcwd() or something equally silly.
    filename = path;
    path = "./";
  }
  else
  {
    *filename = '\0';
    filename++;
  }

  ret = dupelog_add_entry(path, filename);

  free(str);

  return ret;
}

static event_reply_t dupecheck_event_postupload_denied(const char * args)
{
  int ret;

  const char *filename, *username;
  char *str = strdup(args), *ptr;
  username = strtok_r(str, " ", &ptr);
  filename = ptr;

  if (strrchr(filename, '/') != NULL)
  {
    filename = strrchr(filename, '/') + 1;
  }

  ret = dupelog_delete_entry(filename);

  free(str);

  return ret;
}

static event_reply_t dupecheck_event_dele(const char * args)
{
  int ret;

  if (strrchr(args, '/') != NULL)
  {
    args = strrchr(args, '/') + 1;
  }

  return dupelog_delete_entry(args);
}

/***********************/
/* WZD_MODULE_INIT     */
int WZD_MODULE_INIT (void)
{ 
  wzd_string_t *params;
  params = STR("%filepath");

  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_PREUPLOAD, dupecheck_event_preupload, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_POSTUPLOAD, dupecheck_event_postupload, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_POSTUPLOAD_DENIED, dupecheck_event_postupload_denied, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_DELE, dupecheck_event_dele, NULL);
  
  out_log(LEVEL_INFO, "Dupecheck: Module loaded!\n");
  return 0;
}

int WZD_MODULE_CLOSE(void)
{
/* Using it does more bad than good
 hook_remove(&getlib_mainConfig()->hook,EVENT_PREUPLOAD,(void_fct)&dupecheck_hook_preupload);
  hook_remove(&getlib_mainConfig()->hook,EVENT_POSTUPLOAD,(void_fct)&dupecheck_hook_postupload);
  hook_remove(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&dupecheck_hook_site);
  */
  out_log(LEVEL_INFO, "Dupecheck: Module unloaded!\n");
  return 0;
}
