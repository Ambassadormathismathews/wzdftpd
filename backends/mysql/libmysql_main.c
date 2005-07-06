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

#ifdef WIN32
# include <winsock2.h>
# include <windows.h>
# define inline __inline
#else /* !WIN32 */
#include <unistd.h>
#endif

#include <mysql.h>

#include <wzd_backend.h>
#include <libwzd-auth/wzd_md5.h>
#include <libwzd-auth/wzd_md5crypt.h>
#include <wzd_debug.h>

#include "libmysql.h"

#define MYSQL_BACKEND_VERSION   121

/* IMPORTANT needed to check version */
BACKEND_NAME(mysql);
BACKEND_VERSION(MYSQL_BACKEND_VERSION);


MYSQL mysql;
static char *db_user, *db_passwd, *db_hostname, *db;

/*static int wzd_parse_arg(const char *arg);*/ /* parse arg (login:password@hostname:table) */
static int wzd_parse_arg(const char *arg);

/* get mysql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_long(long *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_uint(unsigned int *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_ulong(unsigned long *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_ullong(u64_t *dst, MYSQL_ROW row, unsigned int index);

static uid_t * wzd_mysql_get_user_list(void);
static gid_t * wzd_mysql_get_group_list(void);





void _wzd_mysql_error(const char *filename, const char  *func_name, int line)/*, const char *error)*/
{
  fprintf(stderr, "%s(%s):%d %s\n", filename, func_name, line, mysql_error(&mysql));
}

static int wzd_parse_arg(const char *arg)
{
  char *ptr;
  char * buffer;

  if (!arg) return -1;

  ptr = buffer = strdup(arg); /** \todo free buffer at backend exit ! (small memory leak) */

  db_user = strtok_r(buffer, ":", &ptr);
  if (!db_user) { free(buffer); return -1; }

  db_passwd = strtok_r(NULL,"@", &ptr);
  if (!db_passwd) { free(buffer); return -1; }

  db_hostname = strtok_r(NULL, ":\n", &ptr);
  if (!db_hostname) { free(buffer); return -1; }

  db = strtok_r(NULL, "\n", &ptr);
  if (!db) { free(buffer); return -1; }

  return 0;
}


int FCN_INIT(const char *arg)
{
  if ((wzd_parse_arg(arg)) != 0) {
    return -1;
  }

  mysql_init(&mysql);

  /** \todo XXX FIXME try using CLIENT_SSL for the last arg */
  if (!mysql_real_connect(&mysql, db_hostname, db_user, db_passwd, db, 0, NULL, 0)) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    mysql_close(&mysql);
    return -1;
  }

  return 0;
}

uid_t FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  char *query;
  uid_t uid;

  if (!wzd_mysql_check_name(login)) return (uid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return (uid_t)-1;
  }
  free(query);

  uid = (uid_t)-1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return (uid_t)-1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result  */
      mysql_free_result(res);
      return (uid_t)-1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);

#if 0 /* not working yet */
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath
    user->uid = atoi(row[3]);
#endif /* 0 */
    uid = atoi(row[UCOL_UID]);

    mysql_free_result(res);
  } /*else // user does not exist in table
    return -1; */

  return uid;
}

uid_t FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  char *query;
  char * cipher;
  uid_t uid;
  char buffer[128];

  if (!wzd_mysql_check_name(login)) return (uid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return (uid_t)-1;
  }

  free(query);
  uid = (uid_t)-1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;
    char stored_pass[MAX_PASS_LENGTH];

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return (uid_t)-1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result */
      mysql_free_result(res);
      return (uid_t)-1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);
#if 0 /* not working yet */
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->userpass, row[1], (MAX_PASS_LENGTH -1)); // userpass
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath

    user->uid = atoi(row[3]);
#endif /* 0 */
    uid = atoi(row[UCOL_UID]);

    if (row[UCOL_USERPASS])
      strncpy(stored_pass, row[UCOL_USERPASS], MAX_PASS_LENGTH);
    else
      stored_pass[0] = '\0';

    mysql_free_result(res);

    if (strlen(stored_pass) == 0)
    {
      fprintf(stderr,"WARNING: empty password field whould not be allowed !\n");
      fprintf(stderr,"WARNING: you should run: UPDATE users SET userpass='%%' WHERE userpass is NULL\n");
      return uid; /* passworldless login */
    }

    if (strcmp(stored_pass,"%")==0)
      return uid; /* passworldless login */

    cipher = (char*)md5_hash_r(pass, buffer, sizeof(buffer));
    if (!cipher) return (uid_t)-1;

    if (strncasecmp(cipher,stored_pass,32))
      return (uid_t)-1;

  } /* else // user does not exist in table
    return -1;*/


  return uid;
}

uid_t FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  char *query;
  uid_t uid;

  if (!wzd_mysql_check_name(name)) return (uid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", name);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return (uid_t)-1;
  }

  free(query);
  uid = (uid_t)-1;

  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return (uid_t)-1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result */
      mysql_free_result(res);
      return (uid_t)-1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);
#if 0 /* not working yet */
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->userpass, row[1], (MAX_PASS_LENGTH -1)); // userpass
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath
    user->uid = atoi(row[3]);
#endif /* 0 */
    uid = atoi(row[UCOL_UID]);

    mysql_free_result(res);

  }/* else  // no such user
    return -1;*/

  return uid;
}

int  FCN_COMMIT_CHANGES(void)
{
  return 0;
}

int FCN_FINI(void)
{
  mysql_close(&mysql);

  return 0;
}

wzd_user_t * FCN_GET_USER(uid_t uid)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int num_fields;
  wzd_user_t * user;
  unsigned int i,j;

  if (uid == (uid_t)-2) return (wzd_user_t*)wzd_mysql_get_user_list();

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE uid='%d'", uid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if ( (int)mysql_num_rows(res) != 1 ) {
    /* more than 1 result !!!! */
    /** \todo warn user */
    free(query);
    mysql_free_result(res);
    return NULL;
  }

  num_fields = mysql_num_fields(res);
  row = mysql_fetch_row(res);

  user = (wzd_user_t*)wzd_malloc(sizeof(wzd_user_t));
  memset(user, 0, sizeof(wzd_user_t));

  if ( wzd_row_get_uint(&user->uid, row, UCOL_UID) ) {
    free(query);
    wzd_free(user);
    mysql_free_result(res);
    return NULL;
  }
  wzd_row_get_string(user->username, HARD_USERNAME_LENGTH, row, UCOL_USERNAME);
  wzd_row_get_string(user->userpass, MAX_PASS_LENGTH, row, UCOL_USERPASS);
  wzd_row_get_string(user->rootpath, WZD_MAX_PATH, row, UCOL_ROOTPATH);
  wzd_row_get_string(user->tagline, MAX_TAGLINE_LENGTH, row, UCOL_TAGLINE);
  wzd_row_get_string(user->flags, MAX_FLAGS_NUM, row, UCOL_FLAGS);
  wzd_row_get_uint((unsigned int*)&user->max_idle_time, row, UCOL_MAX_IDLE_TIME);
  wzd_row_get_uint(&user->max_ul_speed, row, UCOL_MAX_UL_SPEED);
  wzd_row_get_uint(&user->max_dl_speed, row, UCOL_MAX_DL_SPEED);
  if (wzd_row_get_uint(&i, row, UCOL_NUM_LOGINS)==0) user->num_logins = i;
  wzd_row_get_uint(&user->ratio, row, UCOL_RATIO);
  if (wzd_row_get_uint(&i, row, UCOL_USER_SLOTS)==0) user->user_slots = i;
  if (wzd_row_get_uint(&i, row, UCOL_LEECH_SLOTS)==0) user->leech_slots = i;
  wzd_row_get_ulong(&user->userperms, row, UCOL_PERMS);
  wzd_row_get_ullong(&user->credits, row, UCOL_CREDITS);
  /* XXX FIXME last login */

  mysql_free_result(res);

  /* Now get IP */
  user->ip_allowed[0][0] = '\0';

  snprintf(query, 512, "SELECT userip.ip FROM userip,users WHERE users.uid='%d' AND users.ref=userip.ref", uid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }
  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }

  i =0;
  while ( (row = mysql_fetch_row(res)) ) {
    if (i >= HARD_IP_PER_USER) {
      fprintf(stderr,"Mysql: too many IP for user %s, dropping others\n",user->username);
      break;
    }
    wzd_row_get_string(user->ip_allowed[i], MAX_IP_LENGTH, row, 0 /* query asks only one column */);
    i++;
  }


  mysql_free_result(res);

  /* Now get Groups */

  snprintf(query, 512, "SELECT groups.gid FROM groups,users,ugr WHERE users.uid='%d' AND users.ref=ugr.uref AND groups.ref=ugr.gref", uid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }
  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }

  i =0;
  while ( (row = mysql_fetch_row(res)) ) {
    if (i >= HARD_IP_PER_USER) {
      fprintf(stderr,"Mysql: too many groups for user %s, dropping others\n",user->username);
      break;
    }
    if (wzd_row_get_uint(&j, row, 0 /* query asks only one column */)==0)
      user->groups[i++] = j;
  }
  user->group_num = i;

  mysql_free_result(res);

  /* Now get stats */
  snprintf(query, 512, "SELECT bytes_ul_total,bytes_dl_total,files_ul_total,files_dl_total FROM stats,users WHERE users.uid=%d AND users.ref=stats.ref", uid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }
  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }

  row = mysql_fetch_row(res);

  wzd_row_get_ullong(&user->stats.bytes_ul_total, row, SCOL_BYTES_UL);
  wzd_row_get_ullong(&user->stats.bytes_dl_total, row, SCOL_BYTES_DL);
  wzd_row_get_ulong(&user->stats.files_ul_total, row, SCOL_FILES_UL);
  wzd_row_get_ulong(&user->stats.files_dl_total, row, SCOL_FILES_DL);

  mysql_free_result(res);

  free(query);

  return user;
}


wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int num_fields;
  wzd_group_t * group;
  unsigned int i;

  if (gid == (gid_t)-2) return (wzd_group_t*)wzd_mysql_get_group_list();

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM groups WHERE gid='%d'", gid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }
  free(query);

  if (!(res = mysql_store_result(&mysql))) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if ( (int)mysql_num_rows(res) != 1 ) {
    /* more than 1 result !!!! */
    /** \todo warn user */
    mysql_free_result(res);
    return NULL;
  }

  num_fields = mysql_num_fields(res);
  row = mysql_fetch_row(res);

  /** XXX FIXME memory leak here !! */
  group = (wzd_group_t*)wzd_malloc(sizeof(wzd_group_t));
  memset(group, 0, sizeof(wzd_group_t));

  if ( wzd_row_get_uint(&group->gid, row, GCOL_GID) ) {
    wzd_free(group);
    mysql_free_result(res);
    return NULL;
  }
  wzd_row_get_string(group->groupname, HARD_GROUPNAME_LENGTH, row, GCOL_GROUPNAME);
  wzd_row_get_string(group->defaultpath, WZD_MAX_PATH, row, GCOL_DEFAULTPATH);
  wzd_row_get_string(group->tagline, MAX_TAGLINE_LENGTH, row, GCOL_TAGLINE);
  wzd_row_get_ulong(&group->groupperms, row, GCOL_GROUPPERMS);
  wzd_row_get_uint((unsigned int*)&group->max_idle_time, row, GCOL_MAX_IDLE_TIME);
  if (wzd_row_get_uint(&i, row, GCOL_NUM_LOGINS)==0) group->num_logins = i;
  wzd_row_get_uint(&group->max_ul_speed, row, GCOL_MAX_UL_SPEED);
  wzd_row_get_uint(&group->max_dl_speed, row, GCOL_MAX_DL_SPEED);
  wzd_row_get_uint(&group->ratio, row, GCOL_RATIO);

  mysql_free_result(res);

  /* Now get IP */
  group->ip_allowed[0][0] = '\0';

  query = malloc(512);
  snprintf(query, 512, "SELECT groupip.ip FROM groupip,groups WHERE groups.gid='%d' AND groups.ref=groupip.ref", gid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return group;
  }
  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return group;
  }

  i =0;
  while ( (row = mysql_fetch_row(res)) ) {
    if (i >= HARD_IP_PER_GROUP) {
#ifdef DEBUG
      fprintf(stderr,"Mysql: too many IP for group %s, dropping others\n",group->groupname);
#endif
      break;
    }
    wzd_row_get_string(group->ip_allowed[i], MAX_IP_LENGTH, row, 0 /* query asks only one column */);
    i++;
  }


  mysql_free_result(res);
  free(query);

  return group;
}







/* basic syntax checking to avoid injections */
/** \todo XXX FIXME use mysql_real_escape_string() */
int wzd_mysql_check_name(const char *name)
{
  if (strpbrk(name,"'\";"))
    return 0;
  return 1;
}

/* get mysql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, MYSQL_ROW row, unsigned int index)
{
  if (!dst || !row || row[index]==NULL) return 1;

  strncpy(dst, row[index], dst_len);

  return 0;
}

static inline int wzd_row_get_long(long *dst, MYSQL_ROW row, unsigned int index)
{
  char *ptr;
  long i;

  if (!dst || !row || row[index]==NULL) return 1;

  i = strtol(row[index], &ptr, 0);
  if (ptr && *ptr == '\0') {
    *dst = i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_uint(unsigned int *dst, MYSQL_ROW row, unsigned int index)
{
  char *ptr;
  unsigned long i;

  if (!dst || !row || row[index]==NULL) return 1;

  i = strtoul(row[index], &ptr, 0);
  if (ptr && *ptr == '\0') {
    *dst = (unsigned int)i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_ulong(unsigned long *dst, MYSQL_ROW row, unsigned int index)
{
  char *ptr;
  unsigned long i;

  if (!dst || !row || row[index]==NULL) return 1;

  i = strtoul(row[index], &ptr, 0);
  if (ptr && *ptr == '\0') {
    *dst = i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_ullong(u64_t *dst, MYSQL_ROW row, unsigned int index)
{
  char *ptr;
  u64_t i;

  if (!dst || !row || row[index]==NULL) return 1;

  i = strtoull(row[index], &ptr, 0);
  if (ptr && *ptr == '\0') {
    *dst = i;
    return 0;
  }

  return 1;
}


static uid_t * wzd_mysql_get_user_list(void)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  uid_t * uid_list;
  unsigned int index, i=0;
  my_ulonglong num_rows;

  query = malloc(512);
  snprintf(query, 512, "SELECT uid FROM users");

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  /* number of rows */
  num_rows = mysql_num_rows(res);

  uid_list = wzd_malloc(((u32_t)num_rows+1)*sizeof(uid_t));

  index = 0;
  while ( (row = mysql_fetch_row(res)) ) {
    wzd_row_get_uint(&i, row, 0 /* query asks only one column */);
    uid_list[index++] = (uid_t)i;
  }
  uid_list[index] = (uid_t)-1;
  uid_list[num_rows] = (uid_t)-1;

  mysql_free_result(res);
  free(query);

  return uid_list;
}

static gid_t * wzd_mysql_get_group_list(void)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  gid_t * gid_list;
  unsigned int index, i=0;
  my_ulonglong num_rows;

  query = malloc(512);
  snprintf(query, 512, "SELECT gid FROM groups");

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  /* number of rows */
  num_rows = mysql_num_rows(res);

  gid_list = wzd_malloc(((u32_t)num_rows+1)*sizeof(gid_t));

  index = 0;
  while ( (row = mysql_fetch_row(res)) ) {
    wzd_row_get_uint(&i, row, 0 /* query asks only one column */);
    gid_list[index++] = (gid_t)i;
  }
  gid_list[index] = (gid_t)-1;
  gid_list[num_rows] = (gid_t)-1;


  mysql_free_result(res);
  free(query);

  return gid_list;
}

int _wzd_run_delete_query(char * query, size_t length, const char * query_format, ...)
{
  MYSQL_RES   *res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  if (mysql_query(&mysql, query) != 0) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  res = mysql_store_result(&mysql);

  if (res) mysql_free_result(res);


  return 0;
}

int _wzd_run_insert_query(char * query, size_t length, const char * query_format, ...)
{
  MYSQL_RES   *res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  if (mysql_query(&mysql, query) != 0) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  res = mysql_store_result(&mysql);

  if (res) mysql_free_result(res);


  return 0;
}

int _wzd_run_update_query(char * query, size_t length, const char * query_format, ...)
{
  MYSQL_RES   *res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  if (mysql_query(&mysql, query) != 0) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  res = mysql_store_result(&mysql);

  if (res) mysql_free_result(res);


  return 0;
}

int wzd_backend_init(wzd_backend_t * backend)
{
  if (!backend) return -1;

  backend->name = wzd_strdup("mysql");
  backend->version = MYSQL_BACKEND_VERSION;

  backend->backend_init = FCN_INIT;
  backend->backend_exit = FCN_FINI;

  backend->backend_validate_login = FCN_VALIDATE_LOGIN;
  backend->backend_validate_pass = FCN_VALIDATE_PASS;

  backend->backend_get_user = FCN_GET_USER;
  backend->backend_get_group = FCN_GET_GROUP;

  backend->backend_find_user = FCN_FIND_USER;
  backend->backend_find_group = FCN_FIND_GROUP;

  backend->backend_mod_user = wmysql_mod_user;
  backend->backend_mod_group = wmysql_mod_group;

  backend->backend_chpass = NULL;
  backend->backend_commit_changes = FCN_COMMIT_CHANGES;

  return 0;
}

