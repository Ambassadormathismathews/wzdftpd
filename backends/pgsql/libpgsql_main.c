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

#ifdef _MSC_VER
# include <windows.h>
# define inline __inline
#else /* !_MSC_VER */
#include <unistd.h>
#endif

#include <libpq-fe.h>

#include <wzd_backend.h>
#include <libwzd-auth/wzd_md5.h>
#include <libwzd-auth/wzd_md5crypt.h>
#include <wzd_debug.h>

#include "libpgsql.h"

#define PGSQL_BACKEND_VERSION   101

/* IMPORTANT needed to check version */
BACKEND_NAME(pgsql);
BACKEND_VERSION(PGSQL_BACKEND_VERSION);


PGconn * pgconn = NULL;
static char *db_user, *db_passwd, *db_hostname, *db;

/*static int wzd_parse_arg(const char *arg);*/ /* parse arg (login:password@hostname:table) */
static int wzd_parse_arg(const char *arg);

/* get pgsql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, PGresult * res, unsigned int index);
static inline int wzd_row_get_string_offset(char *dst, unsigned int dst_len, PGresult * res, unsigned int row_number, unsigned int index);
static inline int wzd_row_get_long(long *dst, PGresult * res, unsigned int index);
static inline int wzd_row_get_uint(unsigned int *dst, PGresult * res, unsigned int index);
static inline int wzd_row_get_uint_offset(unsigned int *dst, PGresult * res, unsigned int row_number, unsigned int index);
static inline int wzd_row_get_ulong(unsigned long *dst, PGresult * res, unsigned int index);
static inline int wzd_row_get_ullong(u64_t *dst, PGresult * res, unsigned int index);

static uid_t * wzd_pgsql_get_user_list(void);
static gid_t * wzd_pgsql_get_group_list(void);





void _wzd_pgsql_error(const char *filename, const char  *func_name, int line)/*, const char *error)*/
{
  fprintf(stderr, "%s(%s):%d %s\n", filename, func_name, line, PQerrorMessage(pgconn));
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
  PGresult   *res;

  if ((wzd_parse_arg(arg)) != 0) {
    return -1;
  }

  pgconn = PQsetdbLogin(db_hostname, /* db_port */ NULL, /* pgoptions */ NULL,
      /* pgtty */ NULL, db, db_user, db_passwd);

  /** \todo XXX FIXME try using CLIENT_SSL for the last arg */
/*  if (!mysql_real_connect(&mysql, db_hostname, db_user, db_passwd, db, 0, NULL, 0)) {*/
  if (!pgconn) {
#if 0
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    mysql_close(&mysql);
#endif
    return -1;
  }

  res = PQexec(pgconn, "select ref from users;");
  PQclear(res);

  if (!res) {
    fprintf(stderr,"PG: could not connect to database %s on %s\n",db,db_hostname);
    fprintf(stderr,"PG: please check connections and tables status\n");
    PQfinish(pgconn);
    return -1;
  }

  return 0;
}

uid_t FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  char *query;
  uid_t uid;
  PGresult * res;

  if (!wzd_pgsql_check_name(login)) return (uid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return (uid_t)-1;
  }
  free(query);

  uid = (uid_t)-1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    int num_fields;

    if ( PQntuples(res) != 1 ) {
      /* 0 or more than 1 result  */
      PQclear(res);
      return (uid_t)-1;
    }

    num_fields = PQnfields(res);

#if 0 /* not working yet */
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath
    user->uid = atoi(row[3]);
#endif /* 0 */
    uid = atoi(PQgetvalue(res,0,UCOL_UID));

    PQclear(res);
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
  PGresult * res;

  if (!wzd_pgsql_check_name(login)) return (uid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return (uid_t)-1;
  }

  free(query);
  uid = (uid_t)-1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    int num_fields;
    char stored_pass[MAX_PASS_LENGTH];

    if ( PQntuples(res) != 1 ) {
      /* 0 or more than 1 result */
      PQclear(res);
      return (uid_t)-1;
    }

    num_fields = PQnfields(res);
#if 0 /* not working yet */
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->userpass, row[1], (MAX_PASS_LENGTH -1)); // userpass
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath

    user->uid = atoi(row[3]);
#endif /* 0 */
    uid = atoi(PQgetvalue(res,0,UCOL_UID));

    if (!PQgetisnull(res,0,UCOL_USERPASS))
      strncpy(stored_pass, PQgetvalue(res,0,UCOL_USERPASS), MAX_PASS_LENGTH);
    else
      stored_pass[0] = '\0';

    PQclear(res);

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
  PGresult * res;

  if (!wzd_pgsql_check_name(name)) return (uid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", name);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return (uid_t)-1;
  }

  free(query);
  uid = (uid_t)-1;

  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    int num_fields;

    if ( PQntuples(res) != 1 ) {
      /* 0 or more than 1 result */
      PQclear(res);
      return (uid_t)-1;
    }

    num_fields = PQnfields(res);
#if 0 /* not working yet */
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->userpass, row[1], (MAX_PASS_LENGTH -1)); // userpass
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath
    user->uid = atoi(row[3]);
#endif /* 0 */
    uid = atoi(PQgetvalue(res,0,UCOL_UID));

    PQclear(res);

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
  PQfinish(pgconn);

  return 0;
}

wzd_user_t * FCN_GET_USER(uid_t uid)
{
  char *query;
  int num_fields;
  wzd_user_t * user;
  unsigned int i,j;
  PGresult * res;

  if (uid == (uid_t)-2) return (wzd_user_t*)wzd_pgsql_get_user_list();

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE uid='%d'", uid);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if ( PQntuples(res) != 1 ) {
    /* more than 1 result !!!! */
    /** \todo warn user */
    free(query);
    PQclear(res);
    return NULL;
  }

  num_fields = PQnfields(res);

  user = (wzd_user_t*)wzd_malloc(sizeof(wzd_user_t));
  memset(user, 0, sizeof(wzd_user_t));

  if ( wzd_row_get_uint(&user->uid, res, UCOL_UID) ) {
    wzd_free(user);
    PQclear(res);
    return NULL;
  }

  wzd_row_get_string(user->username, HARD_USERNAME_LENGTH, res, UCOL_USERNAME);
  wzd_row_get_string(user->userpass, MAX_PASS_LENGTH, res, UCOL_USERPASS);
  wzd_row_get_string(user->rootpath, WZD_MAX_PATH, res, UCOL_ROOTPATH);
  wzd_row_get_string(user->flags, MAX_FLAGS_NUM, res, UCOL_FLAGS);
  wzd_row_get_uint((unsigned int*)&user->max_idle_time, res, UCOL_MAX_IDLE_TIME);
  wzd_row_get_uint(&user->max_ul_speed, res, UCOL_MAX_UL_SPEED);
  wzd_row_get_uint(&user->max_dl_speed, res, UCOL_MAX_DL_SPEED);
  if (wzd_row_get_uint(&i, res, UCOL_NUM_LOGINS)==0) user->num_logins = i;
  wzd_row_get_uint(&user->ratio, res, UCOL_RATIO);
  if (wzd_row_get_uint(&i, res, UCOL_USER_SLOTS)==0) user->user_slots = i;
  if (wzd_row_get_uint(&i, res, UCOL_LEECH_SLOTS)==0) user->leech_slots = i;
  wzd_row_get_ulong(&user->userperms, res, UCOL_PERMS);
  wzd_row_get_ullong(&user->credits, res, UCOL_CREDITS);
  /* XXX FIXME last login */

  PQclear(res);

  /* Now get IP */
  user->ip_allowed[0][0] = '\0';

  snprintf(query, 512, "select userip.ip from userip,users where users.uid='%d' AND users.ref=userip.ref", uid);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }

  for (i=0; (int)i<PQntuples(res); i++) {
    if (i >= HARD_IP_PER_USER) {
      fprintf(stderr,"PGsql: too many IP for user %s, dropping others\n",user->username);
      break;
    }
    wzd_row_get_string_offset(user->ip_allowed[i], MAX_IP_LENGTH, res, i, 0 /* query asks only one column */);
  }


  PQclear(res);

  /* Now get Groups */

  snprintf(query, 512, "select groups.gid from groups,users,ugr where users.uid='%d' AND users.ref=ugr.uref AND groups.ref=ugr.gref", uid);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }

  for (i=0; (int)i<PQntuples(res); i++) {
    if (i >= HARD_IP_PER_USER) {
      fprintf(stderr,"PGsql: too many groups for user %s, dropping others\n",user->username);
      break;
    }
    if (wzd_row_get_uint(&j, res, 0 /* query asks only one column */)==0)
      user->groups[i++] = j;
  }
  user->group_num = i;


  PQclear(res);

  free(query);

  return user;
}


wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  char *query;
  int num_fields;
  wzd_group_t * group;
  unsigned int i;
  int index;
  PGresult * res;

  if (gid == (gid_t)-2) return (wzd_group_t*)wzd_pgsql_get_group_list();

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM groups WHERE gid='%d'", gid);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }
  free(query);

  if ( PQntuples(res) != 1 ) {
    /* more than 1 result !!!! */
    /** \todo warn user */
    PQclear(res);
    return NULL;
  }

  num_fields = PQnfields(res);

  /** XXX FIXME memory leak here !! */
  group = (wzd_group_t*)wzd_malloc(sizeof(wzd_group_t));
  memset(group, 0, sizeof(wzd_group_t));

  if ( wzd_row_get_uint(&group->gid, res, GCOL_GID) ) {
    wzd_free(group);
    PQclear(res);
    return NULL;
  }
  wzd_row_get_string(group->groupname, HARD_GROUPNAME_LENGTH, res, GCOL_GROUPNAME);
  wzd_row_get_string(group->defaultpath, WZD_MAX_PATH, res, GCOL_DEFAULTPATH);
  wzd_row_get_string(group->tagline, MAX_TAGLINE_LENGTH, res, GCOL_TAGLINE);
  wzd_row_get_ulong(&group->groupperms, res, GCOL_GROUPPERMS);
  wzd_row_get_uint((unsigned int*)&group->max_idle_time, res, GCOL_MAX_IDLE_TIME);
  if (wzd_row_get_uint(&i, res, GCOL_NUM_LOGINS)==0) group->num_logins = i;
  wzd_row_get_uint(&group->max_ul_speed, res, GCOL_MAX_UL_SPEED);
  wzd_row_get_uint(&group->max_dl_speed, res, GCOL_MAX_DL_SPEED);
  wzd_row_get_uint(&group->ratio, res, GCOL_RATIO);

  PQclear(res);

  /* Now get ip */
  group->ip_allowed[0][0] = '\0';

  query = malloc(512);
  snprintf(query, 512, "SELECT groupip.ip FROM groupip,groups WHERE groups.gid='%d' AND groups.ref=groupip.ref", gid);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return group;
  }
  free(query);

  for (index=0; index<PQntuples(res); index++) {
    wzd_row_get_string(group->ip_allowed[index], MAX_IP_LENGTH, res, 0 /* query asks only one column */);
  }

  PQclear(res);

  return group;
}







/* basic syntax checking to avoid injections */
/** \todo XXX FIXME use PQescapeString() */
int wzd_pgsql_check_name(const char *name)
{
  if (strpbrk(name,"'\";"))
    return 0;
  return 1;
}

/* get pgsql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, PGresult * res, unsigned int index)
{
  if (!dst || !res || PQgetisnull(res,0,index)) return 1;

  strncpy(dst, PQgetvalue(res,0,index), dst_len);

  return 0;
}

static inline int wzd_row_get_string_offset(char *dst, unsigned int dst_len, PGresult * res, unsigned int row_number, unsigned int index)
{
  if (!dst || !res || PQgetisnull(res,row_number,index)) return 1;

  strncpy(dst, PQgetvalue(res,row_number,index), dst_len);

  return 0;
}

static inline int wzd_row_get_long(long *dst, PGresult * res, unsigned int index)
{
  char *ptr;
  long i;

  if (!dst || !res || PQgetisnull(res,0,index)) return 1;

  i = strtol(PQgetvalue(res,0,index), &ptr, 0);

  if (ptr && *ptr == '\0') {
    *dst = i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_uint(unsigned int *dst, PGresult * res, unsigned int index)
{
  char *ptr;
  unsigned long i;

  if (!dst || !res || PQgetisnull(res,0,index)) return 1;

  i = strtoul(PQgetvalue(res,0,index), &ptr, 0);

  if (ptr && *ptr == '\0') {
    *dst = (unsigned int)i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_uint_offset(unsigned int *dst, PGresult * res, unsigned int row_number, unsigned int index)
{
  char *ptr;
  unsigned long i;

  if (!dst || !res || PQgetisnull(res,row_number,index)) return 1;

  i = strtoul(PQgetvalue(res,row_number,index), &ptr, 0);

  if (ptr && *ptr == '\0') {
    *dst = (unsigned int)i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_ulong(unsigned long *dst, PGresult * res, unsigned int index)
{
  char *ptr;
  unsigned long i;

  if (!dst || !res || PQgetisnull(res,0,index)) return 1;

  i = strtoul(PQgetvalue(res,0,index), &ptr, 0);

  if (ptr && *ptr == '\0') {
    *dst = i;
    return 0;
  }

  return 1;
}

static inline int wzd_row_get_ullong(u64_t *dst, PGresult * res, unsigned int index)
{
  char *ptr;
  u64_t i;

  if (!dst || !res || PQgetisnull(res,0,index)) return 1;

  i = strtoull(PQgetvalue(res,0,index), &ptr, 0);

  if (ptr && *ptr == '\0') {
    *dst = i;
    return 0;
  }

  return 1;
}


static uid_t * wzd_pgsql_get_user_list(void)
{
  char *query;
  uid_t * uid_list;
  int index, i;
  int num_rows;
  PGresult * res;

  query = malloc(512);
  snprintf(query, 512, "SELECT uid FROM users");

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  /* number of rows */
  num_rows = PQntuples(res);

  uid_list = wzd_malloc((num_rows+1)*sizeof(uid_t));

  for (index=0; index<num_rows; index++) {
    wzd_row_get_uint_offset(&i, res, index, 0 /* query asks only one column */);
    uid_list[index] = (uid_t)i;
  }
  uid_list[index] = (uid_t)-1;
  uid_list[num_rows] = (uid_t)-1;

  PQclear(res);
  free(query);

  return uid_list;
}

static gid_t * wzd_pgsql_get_group_list(void)
{
  char *query;
  gid_t * gid_list;
  int index, i;
  int num_rows;
  PGresult * res;

  query = malloc(512);
  snprintf(query, 512, "SELECT gid FROM groups");

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  /* number of rows */
  num_rows = PQntuples(res);

  gid_list = wzd_malloc((num_rows+1)*sizeof(gid_t));

  for (index=0; index<num_rows; index++) {
    wzd_row_get_uint_offset(&i, res, index, 0 /* query asks only one column */);
    gid_list[index] = (gid_t)i;
  }
  gid_list[index] = (gid_t)-1;
  gid_list[num_rows] = (gid_t)-1;


  PQclear(res);
  free(query);

  return gid_list;
}

int _wzd_run_delete_query(char * query, size_t length, const char * query_format, ...)
{
  PGresult * res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  PQclear(res);

  return 0;
}

int _wzd_run_insert_query(char * query, size_t length, const char * query_format, ...)
{
  PGresult * res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  PQclear(res);

  return 0;
}

int _wzd_run_update_query(char * query, size_t length, const char * query_format, ...)
{
  PGresult * res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  PQclear(res);

  return 0;
}

int wzd_backend_init(wzd_backend_t * backend)
{
  if (!backend) return -1;

  backend->name = wzd_strdup("pgsql");
  backend->version = PGSQL_BACKEND_VERSION;

  backend->backend_init = FCN_INIT;
  backend->backend_exit = FCN_FINI;

  backend->backend_validate_login = FCN_VALIDATE_LOGIN;
  backend->backend_validate_pass = FCN_VALIDATE_PASS;

  backend->backend_get_user = FCN_GET_USER;
  backend->backend_get_group = FCN_GET_GROUP;

  backend->backend_find_user = FCN_FIND_USER;
  backend->backend_find_group = FCN_FIND_GROUP;

  backend->backend_mod_user = wpgsql_mod_user;
  backend->backend_mod_group = wpgsql_mod_group;

  backend->backend_chpass = NULL;
  backend->backend_commit_changes = FCN_COMMIT_CHANGES;

  return 0;
}

