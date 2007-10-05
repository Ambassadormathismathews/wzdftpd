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
 * \file libsqlite_user.c
 * \brief Sqlite backend users function
 * \addtogroup backend_sqlite
 * @{
 */

static uid_t libsqlite_user_next_id();
static int   libsqlite_user_get_ref_by_uid(uid_t uid);
static void  libsqlite_user_get_groups(wzd_user_t *user);
static void  libsqlite_user_get_ip(wzd_user_t *user);
static void  libsqlite_user_get_stats(wzd_user_t *user);
static void  libsqlite_user_update_ip(uid_t uid, wzd_user_t *user);
static void  libsqlite_user_update_group(uid_t uid, wzd_user_t *user);
static void  libsqlite_user_update_stats(uid_t uid, wzd_user_t *user);

/**
 * \brief Retrieve the next usable uid. used in INSERT query. (libsqlite_user_add)
 * \return an avialable uid or INVALID_USER on error.
 */
static uid_t libsqlite_user_next_id()
{
  int ret;

  int count=0;
  uid_t max_uid=INVALID_USER;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return INVALID_USER;
  
  sqlite3_prepare(db, "SELECT COUNT(uid), MAX(uid) FROM users;",
                  -1, &stmt, NULL);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return INVALID_USER;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        count = sqlite3_column_int(stmt, 0);
        max_uid = sqlite3_column_int(stmt, 1);
        break;
    }
  }
 
 sqlite3_finalize(stmt);
 libsqlite_close(&db);

 /* no user in table then it's the first.. */
 if (max_uid == 0 && count == 0) return 0;

 /* max_uid shoud be set > -1 it's an error */
 if (max_uid == INVALID_USER) return INVALID_USER;

 /* else max_uid + 1 */
 return ++max_uid;
}

/**
 * \brief Retrieve user ID by user name.
 * \param username the username.
 * \return the uid or INVALID_USER.
 */
uid_t libsqlite_user_get_id_by_name(const char *username)
{
  int ret;
  uid_t uid = INVALID_USER;
  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return INVALID_USER;

  sqlite3_prepare(db, "SELECT uid FROM users WHERE username = ?", -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC);

  while ( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        uid = sqlite3_column_int(stmt, 0);
        out_log(SQLITE_LOG_CHANNEL, "Backend sqlite got a result: uid=%d\n", uid);
        break;
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Backend sqlite step error: %s\n", sqlite3_errmsg(db));
        break;
    }
  }

  sqlite3_finalize(stmt);

  if (uid == INVALID_USER) {
    out_log(SQLITE_LOG_CHANNEL, "Backend sqlite user not found.\n");
  }
  else {
    out_log(SQLITE_LOG_CHANNEL, "Backend sqlite found user: %s(%d)\n", username,
            uid);
  }

  libsqlite_close(&db);

  return uid;
}

/**
 * \brief Retieve user ref in table by uid.
 * \param uid user id.
 * \return the ref on success or -1 on error.
 */
static int libsqlite_user_get_ref_by_uid(uid_t uid)
{
  int ret, ref = -1;
  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return ref;

  sqlite3_prepare(db, "SELECT uref FROM users WHERE uid = ?", -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, uid);

  while ( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        ref = sqlite3_column_int(stmt, 0);
        out_log(SQLITE_LOG_CHANNEL, "Backend sqlite got a result: uid=%d\n", uid);
        break;
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Backend sqlite step error: %s\n", sqlite3_errmsg(db));
        break;
    }
  }

  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return ref;
}

/**
 * \brief retrieve ip list when retrieve an user struct.
 * \param user the user struct who will be completed.
 */
static void libsqlite_user_get_ip(wzd_user_t *user)
{
  int ret, ref;
  const char *ip;
  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  ref = libsqlite_user_get_ref_by_uid(user->uid);
  if (ref == -1) return;

  db = libsqlite_open();
  if (db == NULL) return;

  sqlite3_prepare(db, "SELECT ip FROM userip WHERE uref = ?", -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, ref);

  while( (ret=sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        ip = (char *) sqlite3_column_text(stmt, 0);
	if (ip == NULL) continue;
	if (strlen(ip) < 1 || strlen(ip) >= MAX_IP_LENGTH) continue;
	ip_add_check(&user->ip_list, ip, 1);
        break;
    }
  }

  sqlite3_finalize(stmt);
  libsqlite_close(&db);
  return;
}

/**
 * \brief retrieve an user struct by it uid.
 * \return wzd_user_t struct filled or NULL on error.
 */
wzd_user_t *libsqlite_user_get_by_id(uid_t uid)
{
  int ret;
  wzd_user_t *user=NULL;
  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  out_log(SQLITE_LOG_CHANNEL, "Sqlite backend search for uid(%d)\n", uid);

  db = libsqlite_open();
  if (db == NULL) return NULL;

  sqlite3_prepare(db, 
    "SELECT username, userpass, rootpath, tagline, flags, creator, max_idle_time, \
            max_ul_speed, max_dl_speed, num_logins, credits, ratio,      \
            user_slots, leech_slots, perms, last_login                   \
       FROM users                                                        \
       WHERE uid = ?",
       -1, &stmt, NULL);

  sqlite3_bind_int(stmt, 1, uid);

  while( (ret=sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend found user.\n");
        user = user_allocate();
        user->uid = uid;
        _TXT_CPY(user->username, (char *) sqlite3_column_text(stmt, 0), HARD_USERNAME_LENGTH);
        _TXT_CPY(user->userpass, (char *) sqlite3_column_text(stmt, 1), MAX_PASS_LENGTH);
        _TXT_CPY(user->rootpath, (char *) sqlite3_column_text(stmt, 2), WZD_MAX_PATH);
        _TXT_CPY(user->tagline,  (char *) sqlite3_column_text(stmt, 3), MAX_TAGLINE_LENGTH);
        _TXT_CPY(user->flags, (char *) sqlite3_column_text(stmt, 4), MAX_FLAGS_NUM);

        user->creator = sqlite3_column_int(stmt, 5);
	user->max_idle_time = sqlite3_column_int(stmt, 6);
	user->max_ul_speed = (u32_t) sqlite3_column_int64(stmt, 7);
	user->max_dl_speed = (u32_t) sqlite3_column_int64(stmt, 8);
	user->num_logins = sqlite3_column_int(stmt, 9);
	user->credits = sqlite3_column_int64(stmt, 10);
	user->ratio = sqlite3_column_int(stmt, 11);
	user->user_slots = sqlite3_column_int(stmt, 12);
	user->leech_slots = sqlite3_column_int(stmt, 13);
        user->userperms = (unsigned long) sqlite3_column_int64(stmt, 14);
	user->last_login = sqlite3_column_int(stmt, 15);

	libsqlite_user_get_ip(user);
        libsqlite_user_get_groups(user);
        libsqlite_user_get_stats(user);
        break;
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error in query.\n");
        break;
    }
  }


  sqlite3_finalize(stmt);

  libsqlite_close(&db);

  return user;
}

/**
 * \brief Retrieve a user struct by it name.
 * \return a user struct filled or NULL.
 */
wzd_user_t *libsqlite_user_get_by_name(const char *username)
{
  uid_t uid;
  uid = libsqlite_user_get_id_by_name(username);
  if (uid == INVALID_USER) {
    return NULL;
  }
  return libsqlite_user_get_by_id(uid);
}

/**
 * \brief retrieve groups list for a user struct.
 * \param user the user struct who will be completed.
 */
static void libsqlite_user_get_groups(wzd_user_t *user)
{
  int ret, uref, gref;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  uref = libsqlite_user_get_ref_by_uid(user->uid);
  if (uref == -1) return;

  db = libsqlite_open();
  if (db == NULL) return;
  
  sqlite3_prepare(db, "SELECT gref FROM ugr WHERE uref = ?;", -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, uref);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        gref = sqlite3_column_int(stmt, 0);
        user->groups[user->group_num++] = libsqlite_group_get_id_by_ref(gref);
        break;
    }
  }
 
 sqlite3_finalize(stmt);
 libsqlite_close(&db);
}

/**
 * \brief retrieve stats for user struct
 * \param user an user struct who will be completed.
 */
static void libsqlite_user_get_stats(wzd_user_t *user)
{
  int ret, uref;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  uref = libsqlite_user_get_ref_by_uid(user->uid);
  if (uref == -1) return;

  db = libsqlite_open();
  if (db == NULL) return;
  
  sqlite3_prepare(db, "SELECT bytes_ul_total, bytes_dl_total, files_ul_total, files_dl_total FROM stats WHERE uref = ?;", -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, uref);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        user->stats.bytes_ul_total = sqlite3_column_int64(stmt, 0);
        user->stats.bytes_dl_total = sqlite3_column_int64(stmt, 1);
        user->stats.files_ul_total = sqlite3_column_int(stmt, 2);
        user->stats.files_dl_total = sqlite3_column_int(stmt, 3);
        break;
    }
  }
 
 sqlite3_finalize(stmt);
 libsqlite_close(&db);
}

/**
 * \brief retrieve users list.
 * \return an uid array or NULL
 */
uid_t *libsqlite_user_get_list()
{
  int ret;
  
  int index=0;
  uid_t *user_list=NULL;

  sqlite3 *db=NULL;
  sqlite3_stmt *stmt=NULL;

  db = libsqlite_open();
  if (db == NULL) return NULL;
  
  sqlite3_prepare(db, "SELECT uid FROM users;", -1, &stmt, NULL);

  while( (ret = sqlite3_step(stmt)) != SQLITE_DONE ) {
    switch(ret) {
      case SQLITE_ERROR:
        out_log(SQLITE_LOG_CHANNEL, "Sqlite backend error.\n");
	return NULL;
      case SQLITE_BUSY:
        continue;
      case SQLITE_ROW:
        user_list = realloc(user_list, (index + 2) * sizeof(uid_t));
        user_list[index++] = sqlite3_column_int(stmt, 0);
        user_list[index] = -1;
        break;
    }
  }
 
  sqlite3_finalize(stmt);
  libsqlite_close(&db);

  return user_list; 
}

/**
 * \brief add user to database.
 * \param user user struct used to fill tables
 * \return -1 on error, else 0
 */
int libsqlite_user_add(wzd_user_t *user)
{
  int uref;
  char *errmsg;
  char *query;
  char passbuffer[MAX_PASS_LENGTH];
  sqlite3 *db=NULL;

  user->uid = libsqlite_user_next_id();
  if (user->uid == INVALID_USER) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite Backend could'nt get next uid.\n");
    return -1;
  }
  
  if (strcmp(user->userpass, "%") == 0) {
      strncpy(passbuffer, user->userpass, MAX_PASS_LENGTH - 1);
  }
  else if (changepass(user->username, user->userpass, passbuffer,
           MAX_PASS_LENGTH-1)) {
    memset(user->userpass, 0, MAX_PASS_LENGTH);
    return -1;
  }

  db = libsqlite_open();
  if (! db) return -1;

  query = sqlite3_mprintf(
    "INSERT INTO users (                                                 \
        uid, username, userpass, rootpath, tagline, flags, creator, max_idle_time,\
        max_ul_speed, max_dl_speed, num_logins, ratio, user_slots,       \
        leech_slots, perms, credits, last_login                          \
      ) VALUES (                                                         \
         %d, '%q', '%q', '%q', '%q', '%q', %d, %d, %u, %u, %d, %d, %d, %d,  \
         %d, %d, %d                                                      \
      );",
    user->uid, user->username, passbuffer, user->rootpath,
    user->tagline, user->flags, user->creator, user->max_idle_time,
    user->max_ul_speed, user->max_dl_speed, user->num_logins,
    user->ratio, user->user_slots, user->leech_slots,
    user->userperms, user->credits, user->last_login
  );

  out_log(SQLITE_LOG_CHANNEL, "add query: %s\n", query);

  sqlite3_exec(db, query, NULL, NULL, &errmsg);
  sqlite3_free(query);
  if (errmsg) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite backend query error: %s\n", errmsg);
    goto error_sqlite_close; 
  }

  uref = libsqlite_user_get_ref_by_uid(user->uid);
  if (uref == -1) return -1;
#ifndef WIN32
    query = sqlite3_mprintf(
      "INSERT INTO stats (                                               \
        uref, bytes_ul_total, bytes_dl_total, files_ul_total,            \
        files_dl_total                                                   \
       ) VALUES (                                                        \
        %d, %"PRId64", %"PRId64", %d, %d                                 \
       );",
       uref, user->stats.bytes_ul_total, user->stats.bytes_dl_total,
       user->stats.files_ul_total, user->stats.files_dl_total
    );
#else
    query = sqlite3_mprintf(
      "INSERT INTO stats (                                               \
        uref, bytes_ul_total, bytes_dl_total, files_ul_total,            \
        files_dl_total                                                   \
       ) VALUES (                                                        \
        %d, %I64u, %I64u, %d, %d                                         \
       );",
       uref, user->stats.bytes_ul_total, user->stats.bytes_dl_total,
       user->stats.files_ul_total, user->stats.files_dl_total
    );
#endif /* WIN32 */
  out_log(SQLITE_LOG_CHANNEL, "add query: %s\n", query);

  sqlite3_exec(db, query, NULL, NULL, &errmsg);
  sqlite3_free(query);
  if (errmsg) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite backend query error: %s\n", errmsg);
    goto error_sqlite_close;
  }

  libsqlite_user_update_ip(user->uid, user);
  libsqlite_user_update_group(user->uid, user);

error_sqlite_close:
  libsqlite_close(&db);
  return 0;
}

/**
 * \brief Delete user in database.
 * \param uid userid to delete.
 */
void libsqlite_user_del(uid_t uid)
{
  int ref;
  char *errmsg=NULL;
  char *query=NULL;
  sqlite3 *db=NULL;

  ref = libsqlite_user_get_ref_by_uid(uid);
  if (ref == -1) return;

  db = libsqlite_open();
  if (!db) return;

  query = sqlite3_mprintf(
    "DELETE FROM users WHERE uref = %d;                  \
     DELETE FROM userip WHERE uref = %d;                \
     DELETE FROM ugr WHERE uref = %d;                   \
     DELETE FROM stats WHERE uref = %d",
     ref, ref, ref, ref
  );

  sqlite3_exec(db, query, NULL, NULL, &errmsg);
  sqlite3_free(query);
  if (errmsg) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite backend query(%s) error: %s\n", query,
            errmsg);
    goto error_sqlite_close;
  }

error_sqlite_close:
  libsqlite_close(&db);
}

/**
 * \brief update an user.
 * \param uid current table userid.
 * \param user user struct who containt modification.
 * \param mod_type flags on what was modified.
 * \return -1 on error, else 0
 */
int libsqlite_user_update(uid_t uid, wzd_user_t *user, unsigned long mod_type)
{
  char separator = ' ';
  char *query=NULL;
  char *errmsg=NULL;
  char passbuffer[MAX_PASS_LENGTH];
  sqlite3 *db=NULL;

  db = libsqlite_open();
  if (! db) return -1;

  libsqlite_add_to_query(&query, "UPDATE users SET");

  if (mod_type & _USER_USERNAME) {
    libsqlite_add_to_query(&query, "%c username='%q' ", separator, user->username);
    separator = ',';
  }
  if (mod_type & _USER_USERPASS) {
    if (strcmp(user->userpass, "%") == 0) {
      strncpy(passbuffer, user->userpass, MAX_PASS_LENGTH - 1);
    }
    else if (changepass(user->username, user->userpass, passbuffer,
                        MAX_PASS_LENGTH-1)) {
      memset(user->userpass, 0, MAX_PASS_LENGTH);
      free(query);
      libsqlite_close(&db);
      return -1;
    }
    libsqlite_add_to_query(&query, "%c userpass='%q' ", separator, passbuffer);
    separator = ',';
  }
  if (mod_type & _USER_ROOTPATH) {
    libsqlite_add_to_query(&query, "%c rootpath='%q' ", separator, user->rootpath);
    separator = ',';
  }
  if (mod_type & _USER_TAGLINE) {
    libsqlite_add_to_query(&query, "%c tagline='%q' ", separator, user->tagline);
    separator = ',';
  }
  if (mod_type & _USER_UID) {
    libsqlite_add_to_query(&query, "%c uid=%d ", separator, user->uid);
    separator = ',';
  }
  if (mod_type & _USER_CREATOR) {
    libsqlite_add_to_query(&query, "%c creator=%d ", separator, user->creator);
    separator = ',';
  }
  if (mod_type & _USER_IDLE) {
    libsqlite_add_to_query(&query, "%c max_idle_time=%d ", separator, user->max_idle_time);
    separator = ',';
  }
  if (mod_type & _USER_PERMS) {
    libsqlite_add_to_query(&query, "%c perms=%lu ", separator, user->userperms);
    separator = ',';
  }
  if (mod_type & _USER_FLAGS) {
    libsqlite_add_to_query(&query, "%c flags='%q' ", separator, user->flags);
    separator = ',';
  }
  if (mod_type & _USER_MAX_ULS) {
    libsqlite_add_to_query(&query, "%c max_ul_speed=%u ", separator, user->max_ul_speed);
    separator = ',';
  }
  if (mod_type & _USER_MAX_DLS) {
    libsqlite_add_to_query(&query, "%c max_dl_speed=%u ",separator, user->max_dl_speed);
    separator = ',';
  }
  if (mod_type & _USER_NUMLOGINS) {
    libsqlite_add_to_query(&query, "%c num_logins=%d ", separator, user->num_logins);
    separator = ',';
  }
  if (mod_type & _USER_CREDITS) {
#ifndef WIN32
    libsqlite_add_to_query(&query, "%c credits=%"PRId64"", separator, user->credits);
#else
    libsqlite_add_to_query(&query, "%c credits='%I64u'", separator, user->credits);
#endif /* WIN32 */
    separator = ',';
  }
  if (mod_type & _USER_USERSLOTS) {
    libsqlite_add_to_query(&query, "%c user_slots=%d ", separator, user->user_slots);
    separator = ',';
  }
  if (mod_type & _USER_LEECHSLOTS) {
    libsqlite_add_to_query(&query, "%c leech_slots=%d ", separator, user->leech_slots);
    separator = ',';
  }
  if (mod_type & _USER_RATIO) {
    libsqlite_add_to_query(&query, "%c ratio=%d ", separator, user->ratio);
    separator = ',';
  }
  if (mod_type & _USER_IP) {
    libsqlite_user_update_ip(uid, user);
  }
  if (mod_type & _USER_GROUP) {
    libsqlite_user_update_group(uid, user);
  }
  if ((mod_type & _USER_BYTESDL) || (mod_type & _USER_BYTESUL)) {
    libsqlite_user_update_stats(uid, user);
  }

  if (separator == ',') {
    libsqlite_add_to_query(&query, " WHERE uid = %d;", uid);
 
    out_log(SQLITE_LOG_CHANNEL, "Backend sqlite update query: %s\n", query);
   
    sqlite3_exec(db, query, NULL, NULL, &errmsg);
    if (errmsg) {
      out_log(SQLITE_LOG_CHANNEL, "query error: %s\n", errmsg);
    }
  }

  libsqlite_close(&db);
  sqlite3_free(query);

  return 0;
}

/**
 * \brief used in Libsqlite_user_update to update user stats.
 * \param uid current database user id.
 * \param user struct who contains data modified.
 */
static void libsqlite_user_update_stats(uid_t uid, wzd_user_t *user)
{
  int uref;
  char *query=NULL;
  char *errmsg=NULL;
  sqlite3 *db=NULL;

  uref = libsqlite_user_get_ref_by_uid(uid);
  if (uref == -1) return; 

  db = libsqlite_open();
  if (db == NULL) return;

  libsqlite_add_to_query(&query, "UPDATE stats SET ");
#ifndef WIN32
  libsqlite_add_to_query(
    &query, "bytes_ul_total = %"PRId64", bytes_dl_total = %"PRId64"",
    user->stats.bytes_ul_total, user->stats.bytes_dl_total
  );
#else
  libsqlite_add_to_query(
    &query, "bytes_ul_total = %I64u, bytes_dl_total = %I64u",
    user->stats.bytes_ul_total, user->stats.bytes_dl_total
  );
#endif /* WIN32 */
  libsqlite_add_to_query(
    &query, ", files_ul_total = %d, files_dl_total = %d",
    user->stats.files_ul_total, user->stats.files_dl_total
  );
  libsqlite_add_to_query(&query, " WHERE uref = %d;", uref);

  sqlite3_exec(db, query, NULL, NULL, &errmsg);
  if (errmsg) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite query error: %s\n", errmsg);
  }
  sqlite3_free(query);

  libsqlite_close(&db);
}

/**
 * \brief used in libsqlite_user_update to update user's ip.
 * \param uid the current uid in database.
 * \param user struct who containt modification.
 */
static void libsqlite_user_update_ip(uid_t uid, wzd_user_t *user)
{
  int uref;
  char *query=NULL;
  char *errmsg=NULL;
  sqlite3 *db=NULL;

  wzd_user_t *db_user=NULL;
  struct wzd_ip_list_t *delete=NULL;
  struct wzd_ip_list_t *add=NULL;
  struct wzd_ip_list_t *curr;

  uref = libsqlite_user_get_ref_by_uid(uid);
  if (uref == -1) return;

  db = libsqlite_open();
  if (db == NULL) return;
 
  /* retrieve list in db */
  db_user = user_allocate();
  db_user->uid = uid;
  libsqlite_user_get_ip(db_user);

  /* retrieve add && update list */
  libsqlite_update_ip(db_user->ip_list, user->ip_list, &delete, &add);
  user_free(db_user); 

  /* delete */
  for (curr = delete; curr; curr = curr->next_ip) {
    query = sqlite3_mprintf("DELETE FROM userip WHERE uref=%d AND ip='%q';",
                            uref, curr->regexp);
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
    query = sqlite3_mprintf("INSERT INTO userip (uref, ip) VALUES (%d, '%q');",
                            uref, curr->regexp);
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
}

/**
 * \brief used by libsqlite_group_update to update user's group list.
 * \param uid current database user id.
 * \param user struct who containt user modification.
 */
static void libsqlite_user_update_group(uid_t uid, wzd_user_t *user)
{
  int uref, gref;
  unsigned int i, j, found;
  char *query=NULL;
  char *errmsg=NULL;
  sqlite3 *db=NULL;

  wzd_user_t *db_user=NULL;

  uref = libsqlite_user_get_ref_by_uid(uid);
  if (uref == -1) return;

  db = libsqlite_open();
  if (db == NULL) return;

  db_user = user_allocate();
  db_user->uid = uid;
  libsqlite_user_get_groups(db_user);

  /* search for deleted group */
  for(i=0; i < db_user->group_num; i++) {
    found = 0;
    for(j=0; j < user->group_num; j++) {
      if (db_user->groups[i] == user->groups[j]) {
        found = 1;
      }
      if (found == 0) {
        gref = libsqlite_group_get_ref_by_id(db_user->groups[i]);
        query = sqlite3_mprintf("DELETE FROM ugr WHERE uref=%d AND gref=%d;",
                                uref, gref);
        sqlite3_exec(db, query, NULL, NULL, &errmsg);
        if (errmsg) {
          out_log(SQLITE_LOG_CHANNEL, "Sqlite query error: %s\n", errmsg);
          sqlite3_free(errmsg);
          errmsg = NULL;
        }
        sqlite3_free(query);
      }
    }
  }

  /* search for added group */
  for(i=0; i < user->group_num; i++) { 
    found = 0;
    for(j=0; j < db_user->group_num; j++) {
      if (user->groups[i] == db_user->groups[j]) {
        found = 1;
      }
    }
    
    if (found == 0) {
      gref = libsqlite_group_get_ref_by_id(user->groups[i]);
      query = sqlite3_mprintf("INSERT INTO ugr VALUES (%d, %d);", uref, gref);

      sqlite3_exec(db, query, NULL, NULL, &errmsg);
      if (errmsg) {
        out_log(SQLITE_LOG_CHANNEL, "Sqlite query error: %s\n", errmsg);
        sqlite3_free(errmsg);
        errmsg = NULL;
      }
      sqlite3_free(query);
    }
  }

  user_free(db_user);

  libsqlite_close(&db);
}

/** @} */

