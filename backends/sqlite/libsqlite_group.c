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

#include "libsqlite.h"

/** 
 * \file libsqlite_group.c
 * \brief Sqlite backend groups functions
 * \addtogroup backend_sqlite
 * @{
 */

static int   libsqlite_group_next_id();
static gid_t libsqlite_group_get_id_by_name(const char *name);
static void  libsqlite_group_get_ip(wzd_group_t *group);
static void  libsqlite_group_update_ip(gid_t gid, wzd_group_t *group);

/**
 * \brief retrieve the next group id. used in libsqlite_group_add.
 * \return an available group id, or INVALID_GROUP on error.
 */
static int libsqlite_group_next_id()
{
  int ret;
  int count = 0;

  gid_t max_gid=INVALID_GROUP;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return INVALID_GROUP;
  
  sqlite3_prepare(db, "SELECT COUNT(gid), MAX(gid) FROM groups;",
                  -1, &stmt, NULL);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return INVALID_GROUP;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        count = sqlite3_column_int(stmt, 0);
        max_gid = sqlite3_column_int(stmt, 1);
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  /* no group in table then it's the first.. */
  if (max_gid == 0 && count == 0) return 0;

  /* max_gid shoud be set > -1 it's an error */
  if (max_gid == INVALID_GROUP) return INVALID_GROUP;

  /* else max_gid + 1 */
  return ++max_gid;
}

/**
 * \brief retrieve group ref by gid
 * \param gid the group id.
 * \return group reference in database or -1 on error.
 */
int libsqlite_group_get_ref_by_id(gid_t gid)
{
  int ret, ref=-1;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return ref;
  
  sqlite3_prepare(db, "SELECT gref FROM groups WHERE gid = ?;", -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, gid);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
        return ref;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        ref = sqlite3_column_int(stmt, 0);
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return ref;
}

/**
 * \brief retrieve group id by ref.
 * \param ref the group ref in database.
 * \return gid or INVALID_GROUP on error.
 */
gid_t libsqlite_group_get_id_by_ref(int ref)
{
  int ret;

  gid_t gid=INVALID_GROUP;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return gid;
  
  sqlite3_prepare(db, "SELECT gid FROM groups WHERE gref = ?;", -1,
                  &stmt, NULL);

  sqlite3_bind_int(stmt, 1, ref);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return gid;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        gid = sqlite3_column_int(stmt, 0);
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return gid;
}

/**
 * \brief retrieve group id by group name.
 * \param name the group name
 * \return gid or INVALID_GROUP on error.
 */
static gid_t libsqlite_group_get_id_by_name(const char *name)
{
  int ret;

  gid_t gid=INVALID_GROUP;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return gid;
  
  sqlite3_prepare(db, "SELECT gid FROM groups WHERE groupname = ?;", -1,
                  &stmt, NULL);

  sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return gid;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        gid = sqlite3_column_int(stmt, 0);
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return gid;
}

/**
 * \brief retrieve group's ips.
 * \param group struct to be completed
 */
static void libsqlite_group_get_ip(wzd_group_t *group)
{
  int ret, ref;
  const char *ip=NULL;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  ref = libsqlite_group_get_ref_by_id(group->gid);
  if (ref == -1) return;

  db = libsqlite_open();
  if (db == NULL) return;
  
  sqlite3_prepare(db, "SELECT ip FROM groupip WHERE gref = ?;",
                  -1, &stmt, NULL);

  sqlite3_bind_int(stmt, 1, ref);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        ip = (char *) sqlite3_column_text(stmt, 0);
        if (ip == NULL) continue;
        if (strlen(ip) < 1) continue;
        if (strlen(ip) > MAX_IP_LENGTH) continue;
        ip_add_check(&group->ip_list, ip, 1);
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return;
}

/**
 * \brief retrieve a group by id.
 * \param gid the group id
 * \return group struct or NULL on error.
 */
wzd_group_t *libsqlite_group_get_by_id(gid_t gid)
{
  int ret;

  wzd_group_t *group=NULL;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  out_log(SQLITE_LOG_CHANNEL, "Sqlite backend search for gid(%d)\n", gid);

  db = libsqlite_open();
  if (db == NULL) return NULL;
  
  sqlite3_prepare(db,
    "SELECT groupname, defaultpath, tagline, groupperms, max_idle_time, \
            num_logins, max_ul_speed, max_dl_speed, ratio               \
       FROM groups                                                      \
      WHERE gid = ?;",
    -1, &stmt, NULL);

  sqlite3_bind_int(stmt, 1, gid);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE )
  {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return NULL;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend gid(%d) found.\n", gid);
        group = group_allocate();
        group->gid = gid;
        _TXT_CPY(group->groupname, (char *) sqlite3_column_text(stmt, 0), HARD_GROUPNAME_LENGTH);
        _TXT_CPY(group->defaultpath, (char *) sqlite3_column_text(stmt, 1), WZD_MAX_PATH); 
        _TXT_CPY(group->tagline, (char *) sqlite3_column_text(stmt, 2), MAX_TAGLINE_LENGTH);
        group->groupperms = sqlite3_column_int(stmt, 3);
        group->max_idle_time = sqlite3_column_int(stmt, 4);
        group->num_logins = sqlite3_column_int(stmt, 5);
        group->max_ul_speed = sqlite3_column_double(stmt, 6);
        group->max_dl_speed = sqlite3_column_double(stmt, 7);
        group->ratio = sqlite3_column_int(stmt, 8);

        libsqlite_group_get_ip(group);

        break;
    }
  }

  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  if (! group) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite backend gid(%d) not found.\n", gid);
  }

  return group;
}

/**
 * \brief retrieve group struct by name
 * \param name the group name
 * \return group struct or NULL on error.
 */
wzd_group_t *libsqlite_group_get_by_name(const char *name)
{
  return libsqlite_group_get_by_id(libsqlite_group_get_id_by_name(name));
}

gid_t *libsqlite_group_get_list()
{
  int ret;
  
  int index=0;
  gid_t *group_list=NULL;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return NULL;

  sqlite3_prepare(db, "SELECT gid FROM groups;", -1, &stmt, NULL);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return NULL;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        group_list = realloc(group_list, (index + 2) * sizeof(gid_t));
        group_list[index++] = sqlite3_column_int(stmt, 0);
        group_list[index] = -1;
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return group_list; 
}

/**
 * \brief add a group to database.
 * \param group the group struct
 * \return 1 on success, else 0
 */
int libsqlite_group_add(wzd_group_t *group)
{
  char *errmsg;
  char *query;
  sqlite3 *db=NULL;

  group->gid = libsqlite_group_next_id();
  if (group->gid == INVALID_GROUP) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite Backend could'nt get next gid.\n");
    return 0;
  }

  db = libsqlite_open();
  if (! db) return 0;

  query = sqlite3_mprintf(
    "INSERT INTO groups (                                             \
         gid, groupname, defaultpath, tagline, groupperms,            \
         max_idle_time, num_logins, max_ul_speed, max_dl_speed, ratio \
      ) VALUES (                                                      \
         %d, '%q', '%q', '%q', %d, %d, %d, %d, %d, %d                 \
      );",
    group->gid, group->groupname, group->defaultpath, group->tagline,
    group->groupperms, group->max_idle_time, group->num_logins,
    group->max_ul_speed, group->max_dl_speed, group->ratio
  );

  out_log(SQLITE_LOG_CHANNEL, "add query: %s\n", query);

  sqlite3_exec(db, query, NULL, NULL, &errmsg);
  if (errmsg) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite backend query error: %s\n", errmsg);
    libsqlite_close(&db);
    return 0;
  }
  sqlite3_free(query);

  libsqlite_group_update_ip(group->gid, group);

  libsqlite_close(&db);
  return 1;
}

/**
 * \brief update group data
 * \param gid current database gid
 * \param group struct who contains modification
 * \param mod_type flags on what was modified.
 */
void libsqlite_group_update(gid_t gid, wzd_group_t *group,
                            unsigned long mod_type)
{
  char separator = ' ';
  char *query=NULL;
  char *errmsg=NULL;
  sqlite3 *db=NULL;

  db = libsqlite_open();
  if (! db) return;

  libsqlite_add_to_query(&query, "UPDATE groups SET");
  if (mod_type & _GROUP_GROUPNAME) {
    libsqlite_add_to_query(&query, "%c groupname = '%q'", separator, group->groupname);
    separator = ',';
  }
  if (mod_type & _GROUP_DEFAULTPATH) {
    libsqlite_add_to_query(&query, "%c defaultpath = '%q'", separator, group->defaultpath);
    separator = ',';
  }
  if (mod_type & _GROUP_TAGLINE) {
     libsqlite_add_to_query(&query, "%c tagline = '%q'", separator, group->tagline);
    separator = ',';
  }
  if (mod_type & _GROUP_GID) {
    libsqlite_add_to_query(&query, "%c gid = %d", separator, group->gid);
    separator = ',';
  }
  if (mod_type & _GROUP_IDLE) {
    libsqlite_add_to_query(&query, "%c max_idle_time = %d", separator, group->max_idle_time);
    separator = ',';
  }
  if (mod_type & _GROUP_GROUPPERMS) {
    libsqlite_add_to_query(&query, "%c groupperms = %d", separator, group->groupperms);
    separator = ',';
  }
  if (mod_type & _GROUP_MAX_ULS) {
    libsqlite_add_to_query(&query, "%c max_ul_speed = %f", separator, group->max_ul_speed);
    separator = ',';
  }
  if (mod_type & _GROUP_MAX_DLS) {
    libsqlite_add_to_query(&query, "%c max_dl_speed = %f", separator, group->max_dl_speed);
    separator = ',';
  }
  if (mod_type & _GROUP_NUMLOGINS) {
    libsqlite_add_to_query(&query, "%c num_logins = %d", separator, group->num_logins);
    separator = ',';
  }
  if (mod_type & _GROUP_RATIO) {
    libsqlite_add_to_query(&query, "%c ratio = %d", separator, group->ratio);
    separator = ',';
  }
  if (mod_type & _GROUP_IP) {
    libsqlite_group_update_ip(gid, group);
  }

  if (separator == ',') {
    libsqlite_add_to_query(&query, " WHERE gid = %d;", gid);
 
    out_log(SQLITE_LOG_CHANNEL, "Backend sqlite update query: %s\n", query);
   
    sqlite3_exec(db, query, NULL, NULL, &errmsg);
    if (errmsg) {
      out_log(SQLITE_LOG_CHANNEL, "query error: %s\n", errmsg);
    }

    libsqlite_close(&db);
  }

  sqlite3_free(query);
 
  return;
}

/**
 * \brief used by libsqlite_group_update to modif group's ips.
 * \param gid the current database group id.
 * \param group group data.
 */
static void libsqlite_group_update_ip(gid_t gid, wzd_group_t *group)
{
  int gref;
  sqlite3 *db=NULL;
  char *query=NULL;
  char *errmsg=NULL;

  wzd_group_t *db_group=NULL;
  struct wzd_ip_list_t *delete=NULL;
  struct wzd_ip_list_t *add=NULL;
  struct wzd_ip_list_t *curr;

  gref = libsqlite_group_get_ref_by_id(gid);
  if (gref == -1) return;

  db = libsqlite_open();
  if (!db) return;
 
  /* retrieve list in db */
  db_group = group_allocate();
  db_group->gid = gid;
  libsqlite_group_get_ip(db_group);

  /* retrieve add && update list */
  libsqlite_update_ip(db_group->ip_list, group->ip_list, &delete, &add);
  group_free(db_group); 

  /* delete */
  for (curr = delete; curr; curr = curr->next_ip) {
    query = sqlite3_mprintf("DELETE FROM groupip WHERE gref=%d AND ip='%q';",
                            gref, curr->regexp);
    sqlite3_exec(db, query, NULL, NULL, &errmsg);
    if (errmsg) {
      out_log(SQLITE_LOG_CHANNEL, "Sqlite query error: %s\n", errmsg);
      sqlite3_free(errmsg);
      errmsg = NULL;
    }
    sqlite3_free(query);
  }
  
  /* add */
  for(curr = add; curr; curr = curr->next_ip) {
    query = sqlite3_mprintf("INSERT INTO groupip (gref, ip) VALUES (%d, '%q');",
                            gref, curr->regexp);
    sqlite3_exec(db, query, NULL, NULL, &errmsg);
    if (errmsg) {
      out_log(SQLITE_LOG_CHANNEL, "Sqlite query error: %s\n", errmsg);
      sqlite3_free(errmsg);
      errmsg = NULL;
    }
    sqlite3_free(query);
  }

  ip_list_free(delete);
  ip_list_free(add);

  libsqlite_close(&db);

  return;
}

/**
 * \brief delete a group.
 * \param gid the group id
 */
void libsqlite_group_del(gid_t gid)
{
  int i;
  char *errmsg;
  char *query;
  sqlite3 *db=NULL;

  db = libsqlite_open();
  if (! db) return;

  char *query_tab[] = {
    "DELETE FROM groups WHERE gid=%d;",
    "DELETE FROM ugr WHERE gid=%d",
    NULL,
  };

  for (i=0; query_tab[i]; i++) {
    query = sqlite3_mprintf(query_tab[i], gid);
    sqlite3_exec(db, query, NULL, NULL, &errmsg);
    sqlite3_free(query);
  }

  libsqlite_close(&db);

  return;
}

/** @} */

