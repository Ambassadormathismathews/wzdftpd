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
#else
# include <unistd.h>
#endif

#include <mysql.h>

#include <libwzd-auth/wzd_auth.h>

#include <libwzd-base/wzd_strlcat.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_misc.h> /* win_normalize */

#include <libwzd-core/wzd_debug.h>

#include "libmysql.h"

int _user_update_ip(uid_t ref, wzd_user_t * user);
int _user_update_stats(uid_t ref, wzd_user_t * user);

static uid_t _mysql_get_next_uid();

uid_t user_get_ref(const char * name, unsigned int ref);

char * _append_safely_mod(char *query, unsigned int *query_length, char *mod, unsigned int modified)
{
  if (strlen(query) + strlen(mod) +2 >= *query_length) {
      *query_length = strlen(query) + strlen(mod) + 256;
      query = realloc(query, *query_length);
    }
    if (modified) strlcat(query, ",", *query_length);
    strlcat(query, mod, *query_length);

    return query;
}

#define APPEND_STRING_TO_QUERY(format, s, query, query_length, mod, modified) \
  do { \
    snprintf(mod, 512, format, s); \
    query = _append_safely_mod(query, &(query_length), mod, modified); \
    modified = 1; \
  } while (0);

/* if user does not exist, add it */
int wmysql_mod_user(const char *name, wzd_user_t * user, unsigned long mod_type)
{
  char *query, *mod;
  MYSQL_RES   *res;
  int modified = 0;
  unsigned int query_length = 512;
  uid_t ref = 0;
  unsigned int i;

  if (!user) { /* delete user permanently */
    query = malloc(2048);
    /* we don't care about the results of the queries */
    ref = user_get_ref(name, 0);
    if (ref) {
      _wzd_run_update_query(query, 2048, "DELETE FROM stats WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM userip WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE uref=%d", ref);
    }
    _wzd_run_update_query(query, 2048, "DELETE FROM users WHERE username='%s'", name);
    free(query);

    return 0;
  }

  /* search if user exists, if not, create it */
  ref = user_get_ref(name,0);

  if (ref) { /* user exists, just modify fields */
    query = malloc(query_length);
    mod = malloc(512);
    snprintf(query, query_length, "UPDATE users SET ");

    if (mod_type & _USER_USERNAME) {
      if (!wzd_mysql_check_name(user->username)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("username='%s' ", user->username, query, query_length, mod, modified);
    }

    if (mod_type & _USER_USERPASS) {
      char passbuffer[MAX_PASS_LENGTH];

      if (changepass(user->username,user->userpass, passbuffer, MAX_PASS_LENGTH-1)) {
          memset(user->userpass,0,MAX_PASS_LENGTH);
          goto error_mod_user_free;
        }
      memset(user->userpass,0,MAX_PASS_LENGTH);
      APPEND_STRING_TO_QUERY("userpass='%s' ", passbuffer, query, query_length, mod, modified);
    }

    if (mod_type & _USER_ROOTPATH) {
      DIRNORM(user->rootpath,strlen(user->rootpath),0);
      if (!wzd_mysql_check_name(user->rootpath)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("rootpath='%s' ", user->rootpath, query, query_length, mod, modified);
    }

    if (mod_type & _USER_TAGLINE) {
      if (!wzd_mysql_check_name(user->tagline)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("tagline='%s' ", user->tagline, query, query_length, mod, modified);
    }
    if (mod_type & _USER_UID)
      APPEND_STRING_TO_QUERY("uid='%u' ", user->uid, query, query_length, mod, modified);
    if (mod_type & _USER_IDLE)
      APPEND_STRING_TO_QUERY("max_idle_time='%u' ", user->max_idle_time, query, query_length, mod, modified);

    /* XXX FIXME GROUP and GROUPNUM must be treated separately .. */

    if (mod_type & _USER_PERMS)
      APPEND_STRING_TO_QUERY("perms='%lx' ", user->userperms, query, query_length, mod, modified);
    if (mod_type & _USER_FLAGS) {
      if (!wzd_mysql_check_name(user->flags)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("flags='%s' ", user->flags, query, query_length, mod, modified);
    }
    if (mod_type & _USER_MAX_ULS)
      APPEND_STRING_TO_QUERY("max_ul_speed='%u' ", user->max_ul_speed, query, query_length, mod, modified);
    if (mod_type & _USER_MAX_DLS)
      APPEND_STRING_TO_QUERY("max_dl_speed='%u' ", user->max_dl_speed, query, query_length, mod, modified);
    if (mod_type & _USER_NUMLOGINS)
      APPEND_STRING_TO_QUERY("num_logins='%u' ", user->num_logins, query, query_length, mod, modified);

    if ((mod_type & _USER_BYTESDL) || (mod_type & _USER_BYTESUL))
      _user_update_stats(ref,user); /** \todo FIXME test return ! */

    if (mod_type & _USER_IP)
      _user_update_ip(ref,user); /** \todo FIXME use return ! */

    if (mod_type & _USER_CREDITS)
#ifndef WIN32
      APPEND_STRING_TO_QUERY("credits='%llu' ", user->credits, query, query_length, mod, modified);
#else
      APPEND_STRING_TO_QUERY("credits='%I64u' ", user->credits, query, query_length, mod, modified);
#endif
    if (mod_type & _USER_USERSLOTS)
      APPEND_STRING_TO_QUERY("user_slots='%u' ", user->user_slots, query, query_length, mod, modified);
    if (mod_type & _USER_LEECHSLOTS)
      APPEND_STRING_TO_QUERY("leech_slots='%u' ", user->leech_slots, query, query_length, mod, modified);
    if (mod_type & _USER_RATIO)
      APPEND_STRING_TO_QUERY("ratio='%u' ", user->ratio, query, query_length, mod, modified);


    if (modified)
    {
      snprintf(mod, 512, " WHERE username='%s'", name);
      query = _append_safely_mod(query, &query_length, mod, 0);

      if (mysql_query(&mysql, query) != 0) {
        _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
        goto error_mod_user_free;
      }

      res = mysql_store_result(&mysql);


      if (res) mysql_free_result(res);
      free(mod); free(query);
      return 0;
    } /* if (modified) */

    free(mod); free(query);
    return -1;

  }

  /* create new user */

  /* Part 1, User */
  mod = NULL;

  /* find a free uid */
  user->uid = _mysql_get_next_uid();
  if (user->uid == (uid_t)-1) return -1;

  query = malloc(2048);

  {
    char passbuffer[MAX_PASS_LENGTH];

    if (changepass(user->username,user->userpass, passbuffer, MAX_PASS_LENGTH-1)) {
      memset(user->userpass,0,MAX_PASS_LENGTH);
      goto error_user_add;
    }
    memset(user->userpass,0,MAX_PASS_LENGTH);

    if (_wzd_run_update_query(query, 2048, "INSERT INTO users (username,userpass,rootpath,uid,flags,max_idle_time,max_ul_speed,max_dl_speed,num_logins,ratio,user_slots,leech_slots,perms,credits) VALUES ('%s','%s','%s',%u,'%s',%u,%lu,%lu,%u,%u,%u,%u,0x%lx,%" PRIu64 ")",
          user->username, passbuffer,
          user->rootpath,
          user->uid,
          user->flags,
          (unsigned int)user->max_idle_time, user->max_ul_speed, user->max_dl_speed,
          user->num_logins, user->ratio, user->user_slots, user->leech_slots,
          user->userperms, user->credits
          ))
      goto error_user_add;
  }

  ref = user_get_ref(user->username,0);
  if (!ref) goto error_user_add;

  /* Part 2, ugr */
  /* INSERT into ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.uid=154 AND groups.gid=1; */
  for ( i=0; i<user->group_num; i++ )
    if (_wzd_run_update_query(query, 2048, "INSERT INTO ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.ref=%u AND groups.gid=%u",
          ref, user->groups[i]))
      goto error_user_add;

  /* Part 3, IP */
  for ( i=0; i<HARD_IP_PER_USER; i++ )
    if (user->ip_allowed[i][0] != '\0') {
      if (_wzd_run_update_query(query, 2048, "INSERT INTO userip (ref,ip) VALUES (%u,'%s')",
            ref, user->ip_allowed[i]))
        goto error_user_add;
    }

  /* Part 4, stats */
  if (_wzd_run_update_query(query, 2048, "INSERT INTO stats (ref) VALUES (%u)",
        ref))
    goto error_user_add;

  free(query);

  return 0;

error_user_add:
  /* we don't care about the results of the queries */
  ref = user_get_ref(user->username,0);
  if (ref) {
    _wzd_run_update_query(query, 2048, "DELETE FROM stats WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM userip WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE uref=%d", ref);
  }
  _wzd_run_update_query(query, 2048, "DELETE FROM users WHERE username='%s'", user->username);
  free(query);

  return -1;

error_mod_user_free:
  free(mod);
  free(query);

  return -1;
}

int _user_update_ip(uid_t ref, wzd_user_t * user)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  unsigned int i;
  char ip_list[HARD_IP_PER_USER][MAX_IP_LENGTH];
  int ret;

  if (!ref) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT userip.ip FROM userip WHERE ref=%d", ref);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  for (i=0; i<HARD_IP_PER_USER; i++)
    ip_list[i][0] = '\0';

  i = 0;
  while ( (row = mysql_fetch_row(res)) ) {
    if (!row || row[0]==NULL) break;

    strncpy(ip_list[i],row[0],MAX_IP_LENGTH);
    i++;
    if (i >= HARD_IP_PER_USER) {
      /** too many ip in db ?! - ignoring others */
      break;
    }
  }


  /* compare the two sets of ip */
  for (i=0; i<HARD_IP_PER_USER; i++) {
    ret = 1;
    if (strcmp(user->ip_allowed[i],ip_list[i])!=0) {
      /* check for injections in ip */
      if (!wzd_mysql_check_name(ip_list[i]) || !wzd_mysql_check_name(user->ip_allowed[i])) {
        /* print error message ? */
        break;
      }
      if (user->ip_allowed[i][0]=='\0')
        ret = _wzd_run_delete_query(query,512,"DELETE FROM userip WHERE userip.ref=%d AND userip.ip='%s'",ref,ip_list[i]);
      else {
        if (ip_list[i][0]=='\0')
          ret = _wzd_run_insert_query(query,512,"INSERT INTO userip (ref,ip) VALUES (%d,'%s')",ref,user->ip_allowed[i]);
        else
          ret = _wzd_run_update_query(query,512,"UPDATE userip SET ip='%' WHERE userip.ref=%d AND userip.ip='%s'",ip_list[i],ref,user->ip_allowed[i]);
      }
    }
    else
      ret = 0;
    if (ret) {
      /* print error message ? */
      break;
    }
  }

  mysql_free_result(res);
  free(query);

  return ret;
}

int _user_update_stats(uid_t ref, wzd_user_t * user)
{
  char *query;
  MYSQL_RES   *res;
  int ret;
  int numrows;

  if (!ref) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM stats WHERE ref=%d", ref);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  numrows = (unsigned int)mysql_num_rows(res);
  mysql_free_result(res);

  switch (numrows) {
  case 0:
    ret = _wzd_run_insert_query(query,512,"INSERT INTO stats VALUES (%d,%" PRIu64 ",%" PRIu64 ",%lu,%lu)",
        ref,user->stats.bytes_ul_total,user->stats.bytes_dl_total,
        user->stats.files_ul_total,user->stats.files_dl_total);
    break;
  case 1:
    ret = _wzd_run_update_query(query,512,"UPDATE stats SET bytes_ul_total=%" PRIu64 ", bytes_dl_total=%" PRIu64 ",files_ul_total=%lu,files_dl_total=%lu WHERE ref=%d",
        user->stats.bytes_ul_total,user->stats.bytes_dl_total,
        user->stats.files_ul_total,user->stats.files_dl_total,
        ref);
    break;
  default:
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  free(query);
  return ret;
}

uid_t user_get_ref(const char * name, unsigned int ref)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  unsigned int uid=0;
  unsigned long ul;
  char *ptr;

  if (!wzd_mysql_check_name(name)) return 0;

  if (ref) return ref;

  query = malloc(512);
  snprintf(query, 512, "SELECT users.ref FROM users WHERE username='%s'", name);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  while ( (row = mysql_fetch_row(res)) ) {
    if (!row || row[0]==NULL) return 1;

    ul = strtoul(row[0], &ptr, 0);
    if (ptr && *ptr == '\0') {
      uid = (unsigned int)ul;
    }

  }

  mysql_free_result(res);
  free(query);

  return uid;
}

static uid_t _mysql_get_next_uid()
{
  uid_t uid=-1;
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  unsigned long ul;
  char *ptr;

  query = malloc(512);
  snprintf(query, 512, "SELECT LAST_INSERT_ID(uid+1) FROM users");

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  mysql_free_result(res);


  snprintf(query, 512, "SELECT LAST_INSERT_ID()");

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if ( (row = mysql_fetch_row(res)) ) {
    if (row && row[0]!=NULL) {
      ul = strtoul(row[0], &ptr, 0);
      if (ptr && *ptr == '\0') {
        uid = (uid_t)ul;
      }
    }
  }

  mysql_free_result(res);

  free(query);

  return uid;
}

