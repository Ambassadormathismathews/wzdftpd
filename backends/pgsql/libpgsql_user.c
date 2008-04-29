/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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
#else
# include <unistd.h>
#endif

#include <libpq-fe.h>

#include <libwzd-auth/wzd_auth.h>

#include <libwzd-base/wzd_strlcat.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h> /* win_normalize */
#include <libwzd-core/wzd_user.h>

#include <libwzd-core/wzd_debug.h>

#include "libpgsql.h"

static int _user_update_groups(uid_t ref, wzd_user_t * user);
static int _user_update_ip(uid_t ref, wzd_user_t * user);
static int _user_update_stats(uid_t ref, wzd_user_t * user);

static unsigned int user_get_ref(uid_t uid, unsigned int ref);

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
int wpgsql_mod_user(uid_t uid, wzd_user_t * user, unsigned long mod_type)
{
  char *query, *mod;
  int modified = 0, update_registry = 0;
  unsigned int query_length = 512;
  uid_t ref = 0, reg_uid;
  unsigned int i;
  wzd_user_t * registered_user;
  struct wzd_ip_list_t * current_ip;

  if (!user) { /* delete user permanently */
    query = malloc(2048);
    /* we don't care about the results of the queries */
    ref = user_get_ref(uid, 0);
    if (ref) {
      _wzd_run_update_query(query, 2048, "DELETE FROM stats WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM userip WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE uref=%d", ref);
    }
    _wzd_run_update_query(query, 2048, "DELETE FROM users WHERE uid='%d'", uid);
    free(query);

    /** \todo use user_get_id_by_name */
    registered_user = user_get_by_id(uid);
    if (registered_user != NULL) {
      registered_user = user_unregister(registered_user->uid);
      user_free(registered_user);
    }

    return 0;
  }

  /* search if user exists, if not, create it */
  ref = user_get_ref(uid,0);

  if (ref) { /* user exists, just modify fields */
    query = malloc(query_length);
    mod = malloc(512);
    snprintf(query, query_length, "UPDATE users SET ");

    if (mod_type & _USER_USERNAME) {
      if (!wzd_pgsql_check_name(user->username)) goto error_mod_user_free;
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
      memcpy(user->userpass, passbuffer, MAX_PASS_LENGTH);
    }

    if (mod_type & _USER_ROOTPATH) {
      DIRNORM(user->rootpath,strlen(user->rootpath),0);
      if (!wzd_pgsql_check_name(user->rootpath)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("rootpath='%s' ", user->rootpath, query, query_length, mod, modified);
    }

    if (mod_type & _USER_TAGLINE) {
      if (!wzd_pgsql_check_name(user->tagline)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("tagline='%s' ", user->tagline, query, query_length, mod, modified);
    }
    if (mod_type & _USER_UID)
      APPEND_STRING_TO_QUERY("uid='%u' ", user->uid, query, query_length, mod, modified);
    if (mod_type * _USER_CREATOR)
      APPEND_STRING_TO_QUERY("creator='%u' ", user->creator, query, query_length, mod, modified);
    if (mod_type & _USER_IDLE)
      APPEND_STRING_TO_QUERY("max_idle_time='%u' ", user->max_idle_time, query, query_length, mod, modified);

    /* XXX FIXME GROUP and GROUPNUM must be treated separately .. */
    if (mod_type & _USER_GROUP) {
      _user_update_groups(ref,user); /** \todo FIXME use return ! */
      update_registry = 1;
    }

    if (mod_type & _USER_PERMS)
      APPEND_STRING_TO_QUERY("perms='%lx' ", user->userperms, query, query_length, mod, modified);
    if (mod_type & _USER_FLAGS) {
      if (!wzd_pgsql_check_name(user->flags)) goto error_mod_user_free;
      APPEND_STRING_TO_QUERY("flags='%s' ", user->flags, query, query_length, mod, modified);
    }
    if (mod_type & _USER_MAX_ULS)
      APPEND_STRING_TO_QUERY("max_ul_speed='%u' ", user->max_ul_speed, query, query_length, mod, modified);
    if (mod_type & _USER_MAX_DLS)
      APPEND_STRING_TO_QUERY("max_dl_speed='%u' ", user->max_dl_speed, query, query_length, mod, modified);
    if (mod_type & _USER_NUMLOGINS)
      APPEND_STRING_TO_QUERY("num_logins='%u' ", user->num_logins, query, query_length, mod, modified);
    if (mod_type & _USER_LOGINSPERIP)
      APPEND_STRING_TO_QUERY("logins_per_ip='%u' ", user->logins_per_ip, query, query_length, mod, modified);

    if ((mod_type & _USER_BYTESDL) || (mod_type & _USER_BYTESUL)) {
      _user_update_stats(ref,user); /** \todo FIXME test return ! */
      update_registry = 1;
    }

    if (mod_type & _USER_IP) {
      _user_update_ip(ref,user); /** \todo FIXME use return ! */
      update_registry = 1;
    }

    if (mod_type & _USER_CREDITS)
#ifndef WIN32
      APPEND_STRING_TO_QUERY("credits='%" PRIu64 "' ", user->credits, query, query_length, mod, modified);
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
      snprintf(mod, 512, " WHERE uid='%d'", uid);
      query = _append_safely_mod(query, &query_length, mod, 0);

      if (_wzd_run_update_query(query,query_length,query) != 0)
        goto error_mod_user_free;

      free(mod); free(query);

      update_registry = 1;
    }

    if (update_registry) {
      registered_user = user_get_by_id(user->uid);
      if (registered_user != NULL) {
        out_log(LEVEL_FLOOD,"PGSQL updating registered user %s\n",user->username);

        if (user_update(registered_user->uid,user)) {
          out_log(LEVEL_HIGH,"ERROR PGSQL Could not update user %s %d\n",user->username,user->uid);
          return -1;
        }
      } else {
        if (user->uid != (uid_t)-1) {
          reg_uid = user_register(user,1 /* XXX backend id */);
          if (reg_uid != user->uid) {
            out_log(LEVEL_HIGH,"ERROR PGSQL Could not register user %s %d\n",user->username,user->uid);
            return -1;
          }
        }
      }


      return 0;
    } /* if (update_registry) */

    free(mod); free(query);
    return -1;

  }

  /* create new user */

  registered_user = user_get_by_id(uid);
  if (registered_user) {
    out_log(LEVEL_INFO,"WARNING: user %s is not present in DB but already registered\n",user->username);
    return -1;
  }

  /* Part 1, User */
  query = malloc(2048);
  mod = NULL;

  /* sequence will find a free uid */
  user->uid = INVALID_USER;

  {
    char passbuffer[MAX_PASS_LENGTH];

    if (changepass(user->username,user->userpass, passbuffer, MAX_PASS_LENGTH-1)) {
      memset(user->userpass,0,MAX_PASS_LENGTH);
      goto error_user_add;
    }
    memset(user->userpass,0,MAX_PASS_LENGTH);
    memcpy(user->userpass, passbuffer, MAX_PASS_LENGTH);

    if (_wzd_run_update_query(query, 2048, "INSERT INTO users (username,userpass,rootpath,uid,creator,flags,max_idle_time,max_ul_speed,max_dl_speed,num_logins,logins_per_ip,ratio,user_slots,leech_slots,perms,credits) VALUES ('%s','%s','%s',nextval('users_uid_seq'),'%u','%s',%u,%lu,%lu,%u,%u,%u,%u,%u,CAST (X'%lx' as integer),% " PRIu64 ")",
          user->username, passbuffer,
          user->rootpath,
	  user->creator,
          user->flags,
          (unsigned int)user->max_idle_time, user->max_ul_speed, user->max_dl_speed,
          user->num_logins, user->logins_per_ip, user->ratio, user->user_slots,
          user->leech_slots, user->userperms, user->credits
          ))
      goto error_user_add;
  }

  ref = user_get_ref(user->uid,0);
  if (!ref) goto error_user_add;

  /* Part 2, ugr */
  /* INSERT into ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.uid=154 AND groups.gid=1; */
  for ( i=0; i<user->group_num; i++ )
    if (_wzd_run_update_query(query, 2048, "INSERT INTO ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.ref=%u AND groups.gid=%u",
          ref, user->groups[i]))
      goto error_user_add;

  /* Part 3, IP */
  for (current_ip=user->ip_list; current_ip != NULL; current_ip=current_ip->next_ip) {
    if (_wzd_run_update_query(query, 2048, "INSERT INTO userip (ref,ip) VALUES (%u,'%s')",
          ref, current_ip->regexp))
      goto error_user_add;
  }

  /* Part 4, stats */
  if (_wzd_run_update_query(query, 2048, "INSERT INTO stats (ref) VALUES (%u)",
        ref))
    goto error_user_add;

  /* get generated uid from DB */
  {
    PGresult * res;
    if ( (res = _wzd_run_select_query(query,2048,"SELECT users.uid FROM users WHERE ref='%d'",ref)) == NULL )
      goto error_user_add;
    if ( PQntuples(res) != 1 ) {
      PQclear(res);
      goto error_user_add;
    }
    if ( wzd_row_get_uint(&user->uid, res, 0 /* only 1 column */) ) {
      PQclear(res);
      goto error_user_add;
    }
    PQclear(res);
  }

  /** \todo check values and register user */

  reg_uid = user_register(user,1 /* XXX backend id */);
  if (reg_uid != user->uid) {
    out_log(LEVEL_HIGH,"ERROR PGSQL Could not register user %s %d\n",user->username,user->uid);
    /** \todo free user and return INVALID_USER */
    goto error_user_add;
  }

  free(query);

  return 0;

error_user_add:
  /* we don't care about the results of the queries */
  ref = user_get_ref(user->uid,0);
  if (ref) {
    _wzd_run_update_query(query, 2048, "DELETE FROM stats WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM userip WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE uref=%d", ref);
  }
  _wzd_run_update_query(query, 2048, "DELETE FROM users WHERE username='%s'", user->username);
  free(query);

  /** \todo use user_get_id_by_name */
  registered_user = user_get_by_id(uid);
  if (registered_user != NULL) {
    registered_user = user_unregister(registered_user->uid);
    user_free(registered_user);
  }

  return -1;

error_mod_user_free:
  free(mod);
  free(query);

  return -1;
}

/** Update groups for a specific user using the following:
 * get stored group. For each group of modified user, try to find it
 * for the stored user: if not present, add it. For each group of the
 * stored user, try to find it in the modified user: if not present,
 * delete it.
 * \return O if ok
 */
static int _user_update_groups(uid_t ref, wzd_user_t * user)
{
  char query[512];
  PGresult * res;
  int g_stored, g_mod;
  int found = 0;
  long l;
  char *ptr;
  gid_t gid;
  int ret;
  int gref;

  if (!ref) return -1;

  /* extract groups for user */
  if ( (res = _wzd_run_select_query(query,512,"SELECT groups.gid,groups.ref FROM groups,ugr WHERE ugr.uref=%d AND ugr.gref = groups.ref",ref)) == NULL) return -1;

  /* find NEW groups */
  for (g_mod = 0; g_mod < (int)user->group_num; g_mod++) {
    found = 0;
    for (g_stored = 0; g_stored < PQntuples(res); g_stored++) {
      l = strtol(PQgetvalue(res,g_stored,0), &ptr, 0);
      if (ptr && *ptr == '\0') {
        gid = (gid_t)l;
        if (user->groups[g_mod] == gid) {
          found = 1;
          break;
        }
      }
    }
    if (found == 0) {
      ret = _wzd_run_insert_query(query,512,"INSERT INTO ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.uid=%d and groups.gid=%d",user->uid,user->groups[g_mod]);
      if (ret) {
        PQclear(res);
        return -1;
      }
    }
  }

  /* find DELETED groups */
  for (g_stored = 0; g_stored < PQntuples(res); g_stored++) {
    l = strtol(PQgetvalue(res,g_stored,0), &ptr, 0);
    if (ptr && *ptr == '\0') {
      gid = (gid_t)l;
      for (g_mod = 0; g_mod < (int)user->group_num; g_mod++) {
        found = 0;
        if (user->groups[g_mod] == gid) {
          found = 1;
          break;
        }
      }
      if (found == 0) {
        gref = (int)strtol(PQgetvalue(res,g_stored,1), NULL, 0);
        ret = _wzd_run_delete_query(query,512,"DELETE FROM ugr WHERE uref=%d AND gref=%d",ref,gref);
        if (ret) {
          PQclear(res);
          return -1;
        }
      }
    }
  }

  PQclear(res);
  return 0;
}

/** Update ip for a specific user using the following:
 * get stored ip list For each ip of modified user, try to find it
 * for the stored user: if not present, add it. For each ip of the
 * stored user, try to find it in the modified user: if not present,
 * delete it.
 * \return O if ok
 */
static int _user_update_ip(uid_t ref, wzd_user_t * user)
{
  char query[512];
  PGresult * res;
  int i_stored;
  int found = 0;
  int ret;
  const char *ip_stored;
  struct wzd_ip_list_t * current_ip;

  if (!ref) return -1;

  /* extract ip list for user */
  if ( (res = _wzd_run_select_query(query,512,"SELECT userip.ip FROM userip WHERE ref=%d",ref)) == NULL) return 0;

  /* find NEW ip */
  for (current_ip=user->ip_list; current_ip != NULL; current_ip=current_ip->next_ip) {
    found = 0;
    for (i_stored=0; i_stored<PQntuples(res); i_stored++) {
      ip_stored = PQgetvalue(res,i_stored,0);
      if (strcmp(current_ip->regexp,ip_stored)==0) {
        found = 1;
        break;
      }
    }
    if (found == 0) {
      ret = _wzd_run_insert_query(query,512,"INSERT INTO userip (ref,ip) VALUES (%d,'%s')",ref,current_ip->regexp);
      if (ret) {
        PQclear(res);
        return -1;
      }
    }
  }

  /* find DELETED ip */
  for (i_stored=0; i_stored<PQntuples(res); i_stored++) {
    ip_stored = PQgetvalue(res,i_stored,0);
    for (current_ip=user->ip_list; current_ip != NULL; current_ip=current_ip->next_ip) {
      found = 0;
      if (strcmp(current_ip->regexp,ip_stored)==0) {
        found = 1;
        break;
      }
    }
    if (found == 0) {
      ret = _wzd_run_delete_query(query,512,"DELETE FROM userip WHERE userip.ref=%d AND userip.ip='%s'",ref,ip_stored);
      if (ret) {
        PQclear(res);
        return -1;
      }
    }
  }

  PQclear(res);
  return 0;
}

static int _user_update_stats(uid_t ref, wzd_user_t * user)
{
  char query[512];
  PGresult * res;
  int ret;
  int numrows;

  if (!ref) return -1;

  if ( (res = _wzd_run_select_query(query,512,"SELECT * FROM stats WHERE ref=%d",ref)) == NULL) return 0;

  numrows = PQntuples(res);
  PQclear(res);

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
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }


  return 0;
}


static unsigned int user_get_ref(uid_t uid, unsigned int ref)
{
  char query[512];
  unsigned int ret_ref=0;
  unsigned long ul;
  int index;
  char *ptr;
  PGresult * res;

  /** \bug XXX FIXME 0 is a valid uid - should it be -1 ( for return value on error) ? */

  if (ref) return ref;

  if ( (res = _wzd_run_select_query(query,512,"SELECT users.ref FROM users WHERE uid='%d'",uid)) == NULL) return 0;

  for (index=0; index<PQntuples(res); index++) {
    ul = strtoul(PQgetvalue(res,index,0), &ptr, 0);
    if (ptr && *ptr == '\0') {
      ret_ref = (unsigned int)ul;
    }

  }

  PQclear(res);

  return ret_ref;
}

