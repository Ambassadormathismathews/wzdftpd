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

#include "libwzd_dupecheck_dupelog.h"

#include <stdio.h>
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
#include <libwzd-core/wzd_messages.h>

/* These two are defined further down. */
static int check_table_created(sqlite3 *db);
static sqlite3 *opendb();

int dupelog_is_upload_allowed(const char *filename)
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

int dupelog_add_entry(const char *path, const char *filename)
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

int dupelog_delete_entry(const char *filename)
{
  sqlite3_stmt *stmt;
  sqlite3 *db;
  int retval;

  out_log(LEVEL_INFO, "Dupecheck: Removing dupelog entry for '%s'\n", filename);
  db = opendb();

  if (!db)
    return EVENT_OK;

  const char *deleteQuery = "DELETE FROM dupelog WHERE filename = ?";
  if (sqlite3_prepare(db, deleteQuery, -1, &stmt, NULL) != SQLITE_OK)
  {
    if (stmt)
      sqlite3_finalize(stmt);
    out_err(LEVEL_HIGH, "Dupecheck: Could not prepare delete query for '%s': %s\n", filename, sqlite3_errmsg(db));
    sqlite3_close(db);
    return EVENT_OK;
  }

  sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
  retval = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  sqlite3_close(db);

  return EVENT_OK;
}

void dupelog_print_matching_dirs(const char *pattern, int limit, wzd_context_t *context)
{
  sqlite3_stmt *stmt;
  sqlite3 *db;
  int retval, rows = 0;

  out_log(LEVEL_INFO, "Dupecheck: Matching '%s'\n", pattern);

  db = opendb();
  if (!db)
    return;

  const char *selectQuery = "SELECT path, added_at FROM dupelog WHERE lower(path) GLOB lower(?) GROUP BY path ORDER BY added_at DESC LIMIT ?";
  if (sqlite3_prepare(db, selectQuery, -1, &stmt, NULL) != SQLITE_OK)
  {
    if (stmt)
      sqlite3_finalize(stmt);
    out_err(LEVEL_HIGH, "Dupecheck: Could not prepare select query for '%s': %s\n", pattern, sqlite3_errmsg(db));
    sqlite3_close(db);
    return;
  }

  sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, limit);
  while ((retval = sqlite3_step(stmt)) == SQLITE_ROW)
  {
    char timeFormatted[11];
    time_t time = sqlite3_column_int(stmt, 1);

    strftime(timeFormatted, 11, "%F", localtime(&time));
    send_message_raw_formatted(context, "210- %s  %s", timeFormatted, sqlite3_column_text(stmt, 0));
    rows++;
  }
  sqlite3_finalize(stmt);

  send_message_raw_formatted(context, "210 -- %d matches for '%s'", rows, pattern);

  sqlite3_close(db);
}

static int check_table_created(sqlite3 *db)
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

static sqlite3 *opendb()
{
  sqlite3 *db;
  const char *dbpath = config_get_value(getlib_mainConfig()->cfg_file, "dupecheck", "database");
  if (dbpath == NULL)
    dbpath = DUPECHECK_DEFAULT_DB;

  if (sqlite3_open(dbpath, &db) != SQLITE_OK)
  {
    out_err(LEVEL_HIGH, "Dupecheck: Could not open dupedb '%s': %s\n", dbpath, sqlite3_errmsg(db));
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
