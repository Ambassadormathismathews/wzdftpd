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
# include <winsock2.h>
# include <windows.h>
# define inline __inline
#else /* !_MSC_VER */
#include <unistd.h>
#endif

#include <libpq-fe.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
# ifndef HAVE_STRTOK_R
#  include "libwzd-base/wzd_strtok_r.h"
# endif
#endif

#include <libwzd-auth/wzd_auth.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_user.h>

#include <libwzd-core/wzd_debug.h>

#include "libpgsql.h"

/*
 * 106: SSL support
 * 105: use users/group registry
 * 104: reconnect if connection with server was interrupted
 */
#define PGSQL_BACKEND_VERSION   106

#define PGSQL_LOG_CHANNEL       (RESERVED_LOG_CHANNELS+17)

#define PGSQL_DEFAULT_PORT      5432
#define PGSQL_DEFAULT_SSLMODE   "disable"

/* IMPORTANT needed to check version */
BACKEND_NAME(pgsql);
BACKEND_VERSION(PGSQL_BACKEND_VERSION);


PGconn * pgconn = NULL;

static char *db_param;
static char *db_user, *db_passwd, *db_hostname, *db, *db_sslmode;
static unsigned int db_port;

/*static int wzd_parse_arg(const char *arg);*/ /* parse arg (login:password@hostname:table) */
static int wzd_parse_arg(const char *arg);

/* get pgsql value, in a more robust way than just a copy
 * return 0 if ok, non-zero otherwise (ex: value is NULL)
 */
static inline int wzd_row_get_string(char *dst, unsigned int dst_len, PGresult * res, unsigned int index);
static inline int wzd_row_get_string_offset(char *dst, unsigned int dst_len, PGresult * res, unsigned int row_number, unsigned int index);
static inline int wzd_row_get_long(long *dst, PGresult * res, unsigned int index);
static inline int wzd_row_get_uint_offset(unsigned int *dst, PGresult * res, unsigned int row_number, unsigned int index);
static inline int wzd_row_get_ulong(unsigned long *dst, PGresult * res, unsigned int index);
static inline int wzd_row_get_ullong(u64_t *dst, PGresult * res, unsigned int index);

static uid_t * wzd_pgsql_get_user_list(void);
static gid_t * wzd_pgsql_get_group_list(void);


/** \brief Allocates a new user and get informations from database
 * User must be freed using user_free()
 * \return A new user struct or NULL
 */
static wzd_user_t * get_user_from_db(const char * where_statement);

wzd_user_t * get_user_from_db_by_id(uid_t id);
static wzd_user_t * get_user_from_db_by_name(const char * name);

/** \brief Allocates a new group and get informations from database
 * User must be freed using group_free()
 * \return A new group struct or NULL
 */
static wzd_group_t * get_group_from_db(const char * where_statement);

static wzd_group_t * get_group_from_db_by_name(const char * name);





void _wzd_pgsql_error(const char *filename, const char  *func_name, int line)
{
  out_log(PGSQL_LOG_CHANNEL, "%s(%s):%d %s\n", filename, func_name, line, PQerrorMessage(pgconn));

}

static int wzd_parse_arg(const char *arg)
{
  char *ptr, *str_port;

  if (!arg) return -1;

  ptr = db_param = strdup(arg); 

  db_user = strtok_r(db_param, ":", &ptr);
  if (!db_user) { free(db_param); db_param = NULL; return -1; }

  db_passwd = strtok_r(NULL,"@", &ptr);
  if (!db_passwd) { free(db_param); db_param = NULL; return -1; }

  db_hostname = strtok_r(NULL, ":\n", &ptr);
  if (!db_hostname) { free(db_param); db_param = NULL; return -1; }

  str_port = strtok_r(NULL, "/", &ptr);
  if (! str_port) { free(db_param); db_param = NULL; return -1; }

  db_port = strtoul(str_port,NULL,0);
  if (db_port == 0) {
    db_port = PGSQL_DEFAULT_PORT;
  }

  db = strtok_r(NULL, "|\n", &ptr);
  if (!db) { free(db_param); db_param = NULL; return -1; }

  db_sslmode = strtok_r(NULL, "\n", &ptr);
  if (!db_sslmode) {
    db_sslmode = PGSQL_DEFAULT_SSLMODE; 
  }

  return 0;
}


static int FCN_INIT(const char *arg)
{
  PGresult   *res;

  if (arg == NULL) {
    out_log(PGSQL_LOG_CHANNEL, "%s(%s):%d no arguments given\n", __FILE__, __FUNCTION__, __LINE__);
    out_log(PGSQL_LOG_CHANNEL, "You MUST provide a parameter for the PostgreSQL connection\n");
    out_log(PGSQL_LOG_CHANNEL, "Add  param = user:pass@host:port/database[|sslmode] in [pgsql] section in your config file\n");
    out_log(PGSQL_LOG_CHANNEL, "See documentation for help\n");
    return -1;
  }

  if ((wzd_parse_arg(arg)) != 0) {
    out_log(PGSQL_LOG_CHANNEL, "%s(%s):%d could not parse arguments\n", __FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  {
    wzd_string_t * str = str_allocate();

    str_sprintf(str,"host=%s port=%u dbname=%s user=%s password=%s sslmode=%s",
        db_hostname, db_port, db, db_user, db_passwd, db_sslmode);

    pgconn = PQconnectdb(str_tochar(str));

    str_deallocate(str);
  }

  if (!pgconn || PQstatus(pgconn)!=CONNECTION_OK) {
    out_log(PGSQL_LOG_CHANNEL,"PG: could not connect to database %s on %s\n",db,db_hostname);
    out_log(PGSQL_LOG_CHANNEL,"PG: please check connections and tables status\n");
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    if (pgconn != NULL) {
      PQfinish(pgconn);
      pgconn = NULL;
    }
    return -1;
  }

  res = PQexec(pgconn, "select ref from users;");

  if (!res) {
    out_log(PGSQL_LOG_CHANNEL,"PG: could not find expected data in database %s on %s\n",db,db_hostname);
    out_log(PGSQL_LOG_CHANNEL,"PG: please check connections and tables status\n");
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    PQfinish(pgconn); pgconn = NULL;
    return -1;
  }
  PQclear(res);

  out_log(PGSQL_LOG_CHANNEL,"PG: backend version %d loaded\n",PGSQL_BACKEND_VERSION);

  return 0;
}

static uid_t FCN_VALIDATE_LOGIN(const char *login, UNUSED wzd_user_t * _ignored)
{
  wzd_user_t * user, * registered_user;
  uid_t reg_uid, uid;

  if (!wzd_pgsql_check_name(login)) return INVALID_USER;

  user = get_user_from_db_by_name(login);
  if (user == NULL) return INVALID_USER;

  registered_user = user_get_by_id(user->uid);
  if (registered_user != NULL) {
    out_log(LEVEL_FLOOD,"PGSQL updating registered user %s\n",user->username);

    if (user_update(registered_user->uid,user)) {
      out_log(LEVEL_HIGH,"ERROR PGSQL Could not update user %s %d\n",user->username,user->uid);
      /** \todo free user and return INVALID_USER */
    }
    uid = user->uid;
    /* free user, but not the dynamic lists inside, since they are used in registry */
    wzd_free(user);
  } else {
    /** \todo check if user is valid (uid != -1, homedir != NULL etc.) */

    if (user->uid != (uid_t)-1) {
      reg_uid = user_register(user,1 /* XXX backend id */);
      if (reg_uid != user->uid) {
        out_log(LEVEL_HIGH,"ERROR PGSQL Could not register user %s %d\n",user->username,user->uid);
        /** \todo free user and return INVALID_USER */
      }
    }
    uid = user->uid;
    /* do not free user, it will be kept in registry */
  }

  /** \todo update groups */

  return uid;
}

static uid_t FCN_VALIDATE_PASS(const char *login, const char *pass, UNUSED wzd_user_t * _unused)
{
  wzd_user_t * user;

  if (!wzd_pgsql_check_name(login)) return INVALID_USER;

  user = user_get_by_name(login);
  if (user == NULL) return INVALID_USER;

  if (strlen(user->userpass) == 0) {
    out_log(PGSQL_LOG_CHANNEL,"WARNING: empty password field whould not be allowed !\n");
    out_log(PGSQL_LOG_CHANNEL,"WARNING: you should run: UPDATE users SET userpass='%%' WHERE userpass is NULL\n");
    return user->uid; /* passworldless login */
  }

  if (strcmp(user->userpass,"%")==0)
    return user->uid; /* passworldless login */

  if (check_auth(login, pass, user->userpass)==1)
    return user->uid;

  return INVALID_USER;
}

static uid_t FCN_FIND_USER(const char *name, UNUSED wzd_user_t * _ignored)
{
  wzd_user_t * user;
  uid_t reg_uid;

  if (!wzd_pgsql_check_name(name)) return (uid_t)-1;

  user = user_get_by_name(name);
  if (user != NULL) return user->uid;

  user = get_user_from_db_by_name(name);
  if (user == NULL) return INVALID_USER;

  /** \todo check if user is valid (uid != -1, homedir != NULL etc.) */

  if (user->uid != (uid_t)-1) {
    reg_uid = user_register(user,1 /* XXX backend id */);
    if (reg_uid != user->uid) {
      out_log(LEVEL_HIGH,"ERROR PGSQL Could not register user %s %d\n",user->username,user->uid);
      /** \todo free user and return INVALID_USER */
    }
  }
  /* do not free user, it will be kept in registry */
  return user->uid;
}

static gid_t FCN_FIND_GROUP(const char *name, UNUSED wzd_group_t * _ignored)
{
  wzd_group_t * group;
  gid_t reg_gid;

  if (!wzd_pgsql_check_name(name)) return (gid_t)-1;

  group = group_get_by_name(name);
  if (group != NULL) return group->gid;

  group = get_group_from_db_by_name(name);
  if (group == NULL) return INVALID_USER;

  /** \todo check if group is valid (gid != -1, homedir != NULL etc.) */

  if (group->gid != (gid_t)-1) {
    reg_gid = group_register(group,1 /* XXX backend id */);
    if (reg_gid != group->gid) {
      out_log(LEVEL_HIGH,"ERROR PGSQL Could not register group %s %d\n",group->groupname,group->gid);
      /** \todo free group and return INVALID_USER */
    }
  }
  /* do not free group, it will be kept in registry */
  return group->gid;
}

static int  FCN_COMMIT_CHANGES(void)
{
  return 0;
}

static int FCN_FINI(void)
{
  if (pgconn != NULL) PQfinish(pgconn);
  if (db_param != NULL) free(db_param);

  return 0;
}

static wzd_user_t * FCN_GET_USER(uid_t uid)
{
  wzd_user_t * user;
  uid_t reg_uid;

  if (uid == GET_USER_LIST) return (wzd_user_t*)wzd_pgsql_get_user_list();

  user = user_get_by_id(uid);
  if (user != NULL) return user;

  user = get_user_from_db_by_id(uid);
  if (user == NULL) return NULL;

  /** \todo check if user is valid (uid != -1, homedir != NULL etc.) */

  if (user->uid != (uid_t)-1) {
    reg_uid = user_register(user,1 /* XXX backend id */);
    if (reg_uid != user->uid) {
      out_log(LEVEL_HIGH,"ERROR PGSQL Could not register user %s %d\n",user->username,user->uid);
      /** \todo free user and return INVALID_USER */
    }
  }
  /* do not free user, it will be kept in registry */
  return user;
}


static wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  wzd_group_t * group;
  gid_t reg_gid;

  if (gid == GET_GROUP_LIST) return (wzd_group_t*)wzd_pgsql_get_group_list();

  group = group_get_by_id(gid);
  if (group != NULL) return group;

  group = get_group_from_db_by_id(gid);
  if (group == NULL) return NULL;

  /** \todo check if group is valid (gid != -1, homedir != NULL etc.) */

  if (group->gid != (gid_t)-1) {
    reg_gid = group_register(group,1 /* XXX backend id */);
    if (reg_gid != group->gid) {
      out_log(LEVEL_HIGH,"ERROR PGSQL Could not register group %s %d\n",group->groupname,group->gid);
      /** \todo free group and return INVALID_USER */
    }
  }
  /* do not free group, it will be kept in registry */
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

int wzd_row_get_uint(unsigned int *dst, PGresult * res, unsigned int index)
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
  char query[512];
  uid_t * uid_list;
  int index;
  unsigned int i=0;
  int num_rows;
  PGresult * res;

  if ( (res = _wzd_run_select_query(query,512,"SELECT uid FROM users")) == NULL) return NULL;

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

  return uid_list;
}

static gid_t * wzd_pgsql_get_group_list(void)
{
  char query[512];
  gid_t * gid_list;
  int index;
  unsigned int i=0;
  int num_rows;
  PGresult * res;

  if ( (res = _wzd_run_select_query(query,512,"SELECT gid FROM groups")) == NULL) return NULL;

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

  return gid_list;
}

PGresult * _wzd_run_select_query(char * query, size_t length, const char * query_format, ...)
{
  PGresult * res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  res = PQexec(pgconn, query);

  if (!res) {
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return NULL;
  }
  if ((PQresultStatus(res) != PGRES_TUPLES_OK) && (PQstatus(pgconn) != CONNECTION_OK)) {
    PQreset(pgconn);
    if (PQstatus(pgconn) == CONNECTION_OK) {
      out_log(PGSQL_LOG_CHANNEL,"[PGSQL] WARNING query [%s] returned disconnect, reconnect succeeded.\n", query);
      res = PQexec(pgconn, query);
    } else {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return NULL;
    }
    if (!res) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      return NULL;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return NULL;
    }
  }

  return res;
}

int _wzd_run_delete_query(char * query, size_t length, const char * query_format, ...)
{
  PGresult * res;
  va_list argptr;

  va_start(argptr, query_format);
  vsnprintf(query, length, query_format, argptr);
  va_end(argptr);

  res = PQexec(pgconn, query);

  if (!res) {
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }
  if ((PQresultStatus(res) != PGRES_COMMAND_OK) && (PQstatus(pgconn) != CONNECTION_OK)) {
    PQreset(pgconn);
    if (PQstatus(pgconn) == CONNECTION_OK) {
      out_log(PGSQL_LOG_CHANNEL,"[PGSQL] WARNING query [%s] returned disconnect, reconnect succeeded.\n", query);
      res = PQexec(pgconn, query);
    } else {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return -1;
    }
    if (!res) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return -1;
    }
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

  if (!res) {
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }
  if ((PQresultStatus(res) != PGRES_COMMAND_OK) && (PQstatus(pgconn) != CONNECTION_OK)) {
    PQreset(pgconn);
    if (PQstatus(pgconn) == CONNECTION_OK) {
      out_log(PGSQL_LOG_CHANNEL,"[PGSQL] WARNING query [%s] returned disconnect, reconnect succeeded.\n", query);
      res = PQexec(pgconn, query);
    } else {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return -1;
    }
    if (!res) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return -1;
    }
  }

  PQclear(res);

  return 0;
}

/* Format and execute update statement.
 * If query == query_format, do not format string
 */
int _wzd_run_update_query(char * query, size_t length, const char * query_format, ...)
{
  PGresult * res;
  va_list argptr;

  if (query != query_format) {
    va_start(argptr, query_format);
    vsnprintf(query, length, query_format, argptr);
    va_end(argptr);
  }

  res = PQexec(pgconn, query);

  if (!res) {
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }
  if ((PQresultStatus(res) != PGRES_COMMAND_OK) && (PQstatus(pgconn) != CONNECTION_OK)) {
    PQreset(pgconn);
    if (PQstatus(pgconn) == CONNECTION_OK) {
      out_log(PGSQL_LOG_CHANNEL,"[PGSQL] WARNING query [%s] returned disconnect, reconnect succeeded.\n", query);
      res = PQexec(pgconn, query);
    } else {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return -1;
    }
    if (!res) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
      _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
      PQclear(res);
      return -1;
    }
  }

  PQclear(res);

  return 0;
}

/** \brief Allocates a new user and get informations from database
 * User must be freed using user_free()
 * \return A new user struct or NULL
 */
static wzd_user_t * get_user_from_db(const char * where_statement)
{
  char query[512];
  int num_fields;
  wzd_user_t * user;
  unsigned int i,j;
  PGresult * res;
  char ip_buffer[MAX_IP_LENGTH+1];

  if ( (res = _wzd_run_select_query(query,512,"SELECT * FROM users WHERE %s", where_statement)) == NULL) return NULL;

  if ( PQntuples(res) != 1 ) {
    /* more than 1 result !!!! */
    /** \todo warn user */
    PQclear(res);
    return NULL;
  }

  num_fields = PQnfields(res);

  out_log(LEVEL_FLOOD,"PGSQL allocating new user %s\n",where_statement);
  user = user_allocate();

  if ( wzd_row_get_uint(&user->uid, res, UCOL_UID) ) {
    wzd_free(user);
    PQclear(res);
    return NULL;
  }

  wzd_row_get_string(user->username, HARD_USERNAME_LENGTH, res, UCOL_USERNAME);
  wzd_row_get_string(user->userpass, MAX_PASS_LENGTH, res, UCOL_USERPASS);
  wzd_row_get_string(user->rootpath, WZD_MAX_PATH, res, UCOL_ROOTPATH);
  wzd_row_get_string(user->tagline, MAX_TAGLINE_LENGTH, res, UCOL_TAGLINE);
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

  if ( (res = _wzd_run_select_query(query,512,"SELECT userip.ip FROM userip,users WHERE %s AND users.ref=userip.ref", where_statement)) == NULL) return user;

  for (i=0; (int)i<PQntuples(res); i++) {
    if (i >= HARD_IP_PER_USER) {
      out_log(PGSQL_LOG_CHANNEL,"PGsql: too many IP for user %s, dropping others\n",user->username);
      break;
    }
    wzd_row_get_string_offset(ip_buffer, MAX_IP_LENGTH, res, i, 0 /* query asks only one column */);
    ip_add_check(&user->ip_list, ip_buffer, 1 /* allowed */);
  }


  PQclear(res);

  /* Now get Groups */

  if ( (res = _wzd_run_select_query(query,512,"SELECT groups.gid FROM groups,users,ugr WHERE %s AND users.ref=ugr.uref AND groups.ref=ugr.gref", where_statement)) == NULL) return user;

  for (i=0; (int)i<PQntuples(res); i++) {
    if (i >= HARD_IP_PER_USER) {
      out_log(PGSQL_LOG_CHANNEL,"PGsql: too many groups for user %s, dropping others\n",user->username);
      break;
    }
    if (wzd_row_get_uint_offset(&j, res, i, 0 /* query asks only one column */)==0)
      user->groups[i] = j;
  }
  user->group_num = i;

  PQclear(res);

  /* Now get Stats */

  if ( (res = _wzd_run_select_query(query,512,"SELECT bytes_ul_total,bytes_dl_total,files_ul_total,files_dl_total FROM stats,users WHERE %s AND users.ref=stats.ref", where_statement)) == NULL) return user;

  wzd_row_get_ullong(&user->stats.bytes_ul_total, res, SCOL_BYTES_UL);
  wzd_row_get_ullong(&user->stats.bytes_dl_total, res, SCOL_BYTES_DL);
  wzd_row_get_ulong(&user->stats.files_ul_total, res, SCOL_FILES_UL);
  wzd_row_get_ulong(&user->stats.files_dl_total, res, SCOL_FILES_DL);

  PQclear(res);

  return user;
}

wzd_user_t * get_user_from_db_by_id(uid_t id)
{
  char where[128];

  snprintf(where,sizeof(where)-1,"users.uid = '%d'",id);

  return get_user_from_db(where);
}

static wzd_user_t * get_user_from_db_by_name(const char * name)
{
  char where[128];

  snprintf(where,sizeof(where)-1,"users.username = '%s'",name);

  return get_user_from_db(where);
}

/** \brief Allocates a new group and get informations from database
 * User must be freed using group_free()
 * \return A new group struct or NULL
 */
static wzd_group_t * get_group_from_db(const char * where_statement)
{
  char query[512];
  int num_fields;
  wzd_group_t * group;
  unsigned int i;
  int index;
  PGresult * res;
  char ip_buffer[MAX_IP_LENGTH+1];

  if ( (res = _wzd_run_select_query(query,512,"SELECT * FROM groups WHERE %s", where_statement)) == NULL) return NULL;

  if ( PQntuples(res) != 1 ) {
    /* more than 1 result !!!! */
    /** \todo warn user */
    PQclear(res);
    return NULL;
  }

  num_fields = PQnfields(res);

  group = group_allocate();

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

  if ( (res = _wzd_run_select_query(query,512,"SELECT groupip.ip FROM groupip,groups WHERE %s AND groups.ref=groupip.ref", where_statement)) == NULL) return NULL;

  for (index=0; index<PQntuples(res); index++) {
    wzd_row_get_string_offset(ip_buffer, MAX_IP_LENGTH, res, index, 0 /* query asks only one column */);
    ip_add_check(&group->ip_list, ip_buffer, 1 /* allowed */);
  }

  PQclear(res);

  return group;
}

wzd_group_t * get_group_from_db_by_id(gid_t id)
{
  char where[128];

  snprintf(where,sizeof(where)-1,"groups.gid = '%d'",id);

  return get_group_from_db(where);
}

static wzd_group_t * get_group_from_db_by_name(const char * name)
{
  char where[128];

  snprintf(where,sizeof(where)-1,"groups.groupname = '%s'",name);

  return get_group_from_db(where);
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

