/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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
#include <mysql.h>

#include <wzd_backend.h>

enum {
  UCOL_REF=0,
  UCOL_USERNAME,
  UCOL_USERPASS,
  UCOL_ROOTPATH,
  UCOL_UID,
  UCOL_FLAGS,
  UCOL_MAX_UL_SPEED,
  UCOL_MAX_DL_SPEED,
  UCOL_NUM_LOGINS,
  UCOL_IP_ALLOWED,
  UCOL_RATIO,
  UCOL_USER_SLOTS,
  UCOL_LEECH_SLOTS,
  UCOL_LAST_LOGIN,
};

enum {
  GCOL_REF=0,
  GCOL_GROUPNAME,
  GCOL_GID,
};

enum {
  UIPCOL_REF=0,
  UIPCOL_IP,
};



static MYSQL mysql;
static char *db_user, *db_passwd, *db_hostname, *db;

static void wzd_mysql_error(const char *filename, const char  *func_name, int line); /*, const char *error); */
/*static int wzd_parse_arg(const char *arg);*/ /* parse arg (login:password@hostname:table) */
static int wzd_parse_arg(char *arg);

/* basic syntax checking to avoid injections */
static int wzd_mysql_check_name(const char *name);

/* get mysql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_long(long *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_uint(unsigned int *dst, MYSQL_ROW row, unsigned int index);
static inline int wzd_row_get_ulong(unsigned long *dst, MYSQL_ROW row, unsigned int index);




static void wzd_mysql_error(const char *filename, const char  *func_name, int line)/*, const char *error)*/
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


int FCN_INIT(int *backend_storage, wzd_user_t * user_list, unsigned int user_max, wzd_group_t * group_list, unsigned int group_max, void *arg)
{
  if ((wzd_parse_arg((char *)arg)) != 0) {
    return -1;
  }

#ifdef DEBUG
  fprintf(stderr, "User: %s\nHostname: %s\nDatabase name: %s\n", db_user, db_hostname, db);
#endif

  *backend_storage = 1;

  mysql_init(&mysql);

  if (!mysql_real_connect(&mysql, db_hostname, db_user, db_passwd, db, 0, NULL, 0)) {
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    mysql_close(&mysql);
    return -1;
  } 
#ifdef DEBUG
  else
    fprintf(stderr, "Connected to database");
#endif

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
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }
  free(query);

  uid = -1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row, end_row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* more than 1 result !!!! */
      /** \todo warn user */
      mysql_free_result(res);
      return 1;
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

  if (!wzd_mysql_check_name(login)) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  free(query);
  uid = -1;


  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row, end_row;
    int num_fields;
    char stored_pass[MAX_PASS_LENGTH];

    if (!(res = mysql_store_result(&mysql))) {
      wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* more than 1 result !!!! */
      /** \todo warn user */
      mysql_free_result(res);
      return 1;
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
      return uid;	// passworldless login
    /** NO ! The 'anything' pass is '%' ! */

    cipher = (char*)crypt(pass, stored_pass);

    if (!strcasecmp(cipher,stored_pass))
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
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  free(query);
  uid = -1;

  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row, end_row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* more than 1 result !!!! */
      /** \todo warn user */
      mysql_free_result(res);
      return 1;
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

int FCN_FIND_GROUP(int num, wzd_group_t * group)
{
  // XXX: forgot about it while  wzd_group_t->gid is not implemented

  return 0;
}

int FCN_CHPASS(const char *username, const char *new_pass)
{
  return 1;
}

/* if user does not exist, add it */
int FCN_MOD_USER(const char *name, wzd_user_t * user, unsigned long mod_type)
{
  return 1;
}

int FCN_MOD_GROUP(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  return 1;
}

int  FCN_COMMIT_CHANGES(void)
{
  return 0;
}

int FCN_FINI()
{
#ifdef DEBUG
  fprintf(stderr, "Closing connection");
#endif

  mysql_close(&mysql);

  return 0;
}

wzd_user_t * FCN_GET_USER(int uid)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row, end_row;
  int num_fields;
  wzd_user_t * user;
  unsigned int i,j;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM users WHERE uid='%d'", uid);

  if (mysql_query(&mysql, query) != 0) { 
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
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
  wzd_row_get_ulong(&user->max_ul_speed, row, UCOL_MAX_UL_SPEED);
  wzd_row_get_ulong(&user->max_dl_speed, row, UCOL_MAX_DL_SPEED);
  if (wzd_row_get_uint(&i, row, UCOL_NUM_LOGINS)==0) user->num_logins = i;
  wzd_row_get_uint(&user->ratio, row, UCOL_RATIO);
  if (wzd_row_get_uint(&i, row, UCOL_USER_SLOTS)==0) user->user_slots = i;
  if (wzd_row_get_uint(&i, row, UCOL_LEECH_SLOTS)==0) user->leech_slots = i;
  
  mysql_free_result(res);

  /* Now get IP */
  user->ip_allowed[0][0] = '\0';

  snprintf(query, 512, "select UserIP.ip from UserIP,users where users.uid='%d' AND users.ref=UserIP.ref", uid);

  if (mysql_query(&mysql, query) != 0) { 
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }
  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
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

  snprintf(query, 512, "select groups.gid from groups,users where users.uid='%d' AND users.ref=groups.ref", uid);

  if (mysql_query(&mysql, query) != 0) { 
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return user;
  }
  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
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

  /* FIXME */
/*  strncpy(user->ip_allowed[0],"*",MAX_IP_LENGTH);*/
  user->userperms = 0xffffffff;

  free(query);

  return user;
}

wzd_group_t * FCN_GET_GROUP(int gid)
{
  char *query = (char *)malloc(512);
  MYSQL_RES   *res;
  MYSQL_ROW    row, end_row;
  int num_fields;
  wzd_group_t * group;
  unsigned int i;

  snprintf(query, 512, "SELECT * FROM groups WHERE gid='%d'", gid);

  if (mysql_query(&mysql, query) != 0) { 
    free(query);
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }
  free(query);

  if (!(res = mysql_store_result(&mysql))) {
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
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
  
  mysql_free_result(res);

  return group;
}







/* basic syntax checking to avoid injections */
static int wzd_mysql_check_name(const char *name)
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

