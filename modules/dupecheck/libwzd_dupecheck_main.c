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
#include <sqlite3.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h> /* WZD_MODULE_INIT */
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_file.h>

#include "libwzd_dupecheck_main.h"

MODULE_NAME(dupecheck);
MODULE_VERSION(100);

static event_reply_t dupecheck_event_preupload(const char * args);
static event_reply_t dupecheck_event_postupload(const char * args);

int dupecheck_allowupload(const char *filename);
int dupecheck_addtodb(const char *path, const char *filename);

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

  ret = dupecheck_allowupload(filename);

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

  ret = dupecheck_addtodb(path, filename);

  free(str);

  return ret;
}

int check_table_created(sqlite3 *db)
{
  int retval = sqlite3_exec(db,
"CREATE TABLE IF NOT EXISTS dupelog"
"    ("
"     filename TEXT,"
"     path TEXT,"
"     added_at INTEGER,"
"     PRIMARY KEY (filename)"
"    )",NULL, NULL, NULL);

  return retval == SQLITE_OK;
}

sqlite3 *opendb()
{
  sqlite3 *db;
  
  if (sqlite3_open("/wzdftpd/dupedb", &db) != SQLITE_OK)
  {
    out_err(LEVEL_HIGH, "Dupecheck: Could not open dupedb '%s': %s\n", "/wzdftpd/dupedb", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }

  if (!check_table_created(db))
  {
    out_err(LEVEL_HIGH, "Dupecheck: Could not create table for dupelog: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }

  return db;
}

int dupecheck_allowupload(const char *filename)
{
  sqlite3_stmt *stmt;
  sqlite3 *db;
  int retval;

  out_log(LEVEL_INFO, "Dupecheck: Checking '%s'\n", filename);
  db = opendb();

  if (!db)
    return EVENT_OK;

  const char *selectQuery = "SELECT added_at FROM dupelog WHERE filename = ?";
  if (sqlite3_prepare(db, selectQuery, -1, &stmt, NULL) != SQLITE_OK)
  {
    if (stmt)
      sqlite3_finalize(stmt);
    out_err(LEVEL_HIGH, "Dupecheck: Could not prepare select query for '%s': %s\n", filename, sqlite3_errmsg(db));
    sqlite3_close(db);
    return EVENT_OK;
  }

  sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
  retval = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  sqlite3_close(db);

  if (retval == SQLITE_ROW)
  {
    out_log(LEVEL_INFO, "Dupecheck: Disallowing file, found in dupelog.\n");
    return EVENT_DENY;
  }
  else
  {
    out_log(LEVEL_INFO, "Dupecheck: Allowing file, not found in dupelog! :)\n");
    return EVENT_OK;
  }
}

int dupecheck_addtodb(const char *path, const char *filename)
{
  sqlite3_stmt *stmt;
  sqlite3 *db;

  out_log(LEVEL_INFO, "Dupecheck: Adding '%s'\n", filename);
  db = opendb();

  if (!db)
    return EVENT_OK;

  const char *insertQuery = "INSERT INTO dupelog (filename, path, added_at) VALUES (?, ?, ?)";
  if (sqlite3_prepare(db, insertQuery, -1, &stmt, NULL) != SQLITE_OK)
  {
    if (stmt)
      sqlite3_finalize(stmt);
    out_err(LEVEL_HIGH, "Dupecheck: Could not prepare insert query for '%s': %s\n", filename, sqlite3_errmsg(db));
    sqlite3_close(db);
    return EVENT_OK;
  }

  sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, path, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, time(NULL));
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  sqlite3_close(db);

  return EVENT_OK;
}

/***********************/
/* WZD_MODULE_INIT     */
int WZD_MODULE_INIT (void)
{ 
  wzd_string_t *params;
  params = STR("%filepath");

  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_PREUPLOAD, dupecheck_event_preupload, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_POSTUPLOAD, dupecheck_event_postupload, NULL);
  
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
