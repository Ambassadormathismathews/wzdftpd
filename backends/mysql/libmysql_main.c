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
#ifndef BSD
#include <crypt.h>
#endif /* BSD */
#endif

#include <mysql.h>

#include <wzd_backend.h>
#include <wzd_md5.h>
#include <wzd_md5crypt.h>
#include <wzd_debug.h>

#include "libmysql.h"

/* IMPORTANT needed to check version */
BACKEND_NAME(mysql);
BACKEND_VERSION(111);


MYSQL mysql;
static char *db_user, *db_passwd, *db_hostname, *db;

/*static int wzd_parse_arg(const char *arg);*/ /* parse arg (login:password@hostname:table) */
static int wzd_parse_arg(char *arg);

/* get mysql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_long(long *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_uint(unsigned int *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_ulong(unsigned long *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_ullong(u64_t *dst, MYSQL_ROW row, unsigned int index);

static int * wzd_mysql_get_user_list(void);
static int * wzd_mysql_get_group_list(void);





void _wzd_mysql_error(const char *filename, const char  *func_name, int line)/*, const char *error)*/
{
  fprintf(stderr, "%s(%s):%d %s\n", filename, func_name, line, mysql_error(&mysql));
}

static int wzd_parse_arg(char *arg)
{
  char *ptr;

  ptr = arg;

  db_user = (char*)strtok_r(arg, ":", &ptr);
  if (!db_user) return -1;

  db_passwd = (char *)strtok_r(NULL,"@", &ptr);
  if (!db_passwd) return -1;

  db_hostname = (char *)strtok_r(NULL, ":\n", &ptr);
  if (!db_hostname) return -1;

  db = (char *)strtok_r(NULL, "\n", &ptr);
  if (!db) return -1;

  return 0;
}


int FCN_INIT(unsigned int user_max, unsigned int group_max, void *arg)
{
  if ((wzd_parse_arg((char *)arg)) != 0) {
    return -1;
  }

  mysql_init(&mysql);

  if (!mysql_real_connect(&mysql, db_hostname, db_user, db_passwd, db, 0, NULL, 0)) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    mysql_close(&mysql);
    return -1;
  }

  return 0;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  char *query;
  int uid;

  if (!wzd_mysql_check_name(login)) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) { 
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }
  free(query);

  uid = -1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result  */
      mysql_free_result(res);
      return -1;
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

int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  char *query;
  char * cipher;
  int uid;
  char buffer[128];

  if (!wzd_mysql_check_name(login)) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  free(query);
  uid = -1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;
    char stored_pass[MAX_PASS_LENGTH];

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result */
      mysql_free_result(res);
      return -1;
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
    if (!cipher) return -1;

    if (strncasecmp(cipher,stored_pass,32))
      return -1;

  } /* else // user does not exist in table
    return -1;*/


  return uid;
}

int FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  char *query;
  int uid;

  if (!wzd_mysql_check_name(name)) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", name);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  free(query);
  uid = -1;

  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result */
      mysql_free_result(res);
      return -1;
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

int FCN_FINI()
{
  mysql_close(&mysql);

  return 0;
}

wzd_user_t * FCN_GET_USER(int uid)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int num_fields;
  wzd_user_t * user;
  unsigned int i,j;

  if (uid == -2) return (wzd_user_t*)wzd_mysql_get_user_list();

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

  snprintf(query, 512, "select UserIP.ip from UserIP,users where users.uid='%d' AND users.ref=UserIP.ref", uid);

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

  snprintf(query, 512, "select groups.gid from groups,users,UGR where users.uid='%d' AND users.ref=UGR.uref AND groups.ref=UGR.gref", uid);

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

  free(query);

  return user;
}


wzd_group_t * FCN_GET_GROUP(int gid)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int num_fields;
  wzd_group_t * group;
  unsigned int i;

  if (gid == -2) return (wzd_group_t*)wzd_mysql_get_group_list();

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

  return group;
}







/* basic syntax checking to avoid injections */
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


static int * wzd_mysql_get_user_list(void)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int * uid_list;
  unsigned int index, i;
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

  uid_list = (int*)wzd_malloc((num_rows+1)*sizeof(int));

  index = 0;
  while ( (row = mysql_fetch_row(res)) ) {
    wzd_row_get_uint(&i, row, 0 /* query asks only one column */);
    uid_list[index++] = (int)i;
  }
  uid_list[index] = -1;
  uid_list[num_rows] = -1;

  mysql_free_result(res);
  free(query);

  return uid_list;
}

static int * wzd_mysql_get_group_list(void)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int * gid_list;
  unsigned int index, i;
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

  gid_list = (int*)wzd_malloc((num_rows+1)*sizeof(int));

  index = 0;
  while ( (row = mysql_fetch_row(res)) ) {
    wzd_row_get_uint(&i, row, 0 /* query asks only one column */);
    gid_list[index++] = (int)i;
  }
  gid_list[index] = -1;
  gid_list[num_rows] = -1;


  mysql_free_result(res);
  free(query);

  return gid_list;
}

int _wzd_run_update_query(char * query, size_t length, const char * query_format, ...)
{
  MYSQL_RES   *res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  res = mysql_store_result(&mysql);

  if (res) mysql_free_result(res);


  return 0;
}

