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
#include <mysql.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#include <wzd_backend.h>
#include <wzd_strlcat.h>

#include <wzd_debug.h>

#include "libmysql.h"

static char * _append_safely_mod(char *query, unsigned int *query_length, char *mod, unsigned int modified)
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
int FCN_MOD_USER(const char *name, wzd_user_t * user, unsigned long mod_type)
{
  char *query, *mod;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int * uid_list;
  unsigned int index, i;
  int modified = 0;
  unsigned int query_length = 512;

  /* XXX FIXME search if user exists, if not, create it */

  query = malloc(query_length);
  mod = malloc(512);
  snprintf(query, query_length, "UPDATE users SET ");

  if (mod_type & _USER_USERNAME) {
    if (!wzd_mysql_check_name(user->username)) goto error_mod_user_free;
    APPEND_STRING_TO_QUERY("username='%s' ", user->username, query, query_length, mod, modified);
  }

  if (mod_type & _USER_USERPASS) {
    if (!wzd_mysql_check_name(user->userpass)) goto error_mod_user_free;
    APPEND_STRING_TO_QUERY("userpass=MD5('%s') ", user->userpass, query, query_length, mod, modified);
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

  if (modified)
  {
    snprintf(mod, 512, " WHERE username='%s'", name);
    query = _append_safely_mod(query, &query_length, mod, 0);

    if (mysql_query(&mysql, query) != 0) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      goto error_mod_user_free;
    }

    res = mysql_store_result(&mysql);

#if 0

  uid_list = (int*)wzd_malloc((HARD_DEF_USER_MAX+1)*sizeof(int));

  index = 0;
  while ( (row = mysql_fetch_row(res)) ) {
    wzd_row_get_uint(&i, row, 0 /* query asks only one column */);
    uid_list[index++] = (int)i;
  }
  uid_list[index] = -1;
  uid_list[HARD_DEF_USER_MAX] = -1;

#endif
    if (res) mysql_free_result(res);
    free(mod); free(query);
    return 0;
  } /* if (modified) */

  free(mod); free(query);
  return -1;


#if 0
  unsigned int count;
  int found;
  char * cipher;
  char salt[3];

  count=0;
  found = 0;
  while (count<user_count_max) {
    if (strcmp(name,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }

  if (found) { /* user exist */
/*    fprintf(stderr,"User %s exist\n",name);*/
    if (!user) { /* delete user permanently */
      /* FIXME
       * 1- it is not very stable
       * 2- we do not decrement user_count ...
       * 3- we can't shift all users, because contexts have id, and
       *   in middle of functions it will cause unstability
       */
      memset(&user_pool[count],0,sizeof(wzd_user_t));
      return 0;
    }
    /* basic verification: trying to commit on self ? then ok */
    if (&user_pool[count] == user) {
      return 0;
    }
    if (mod_type & _USER_USERNAME) strcpy(user_pool[count].username,user->username);
    if (mod_type & _USER_USERPASS) {
      if (strcasecmp(user->userpass,"%")==0) {
        /* special case: if user_pool[count].userpass == "%" then any pass
         *  is accepted */
        strcpy(user_pool[count].userpass,user->userpass);
      } else {
        /* TODO choose encryption func ? */
        salt[0] = 'a' + (char)(rand()%26);
        salt[1] = 'a' + (char)((rand()*72+3)%26);
        /* FIXME - crypt is NOT reentrant */
        /* XXX - md5 hash in crypt function does NOT work with cygwin */
        cipher = crypt(user->userpass, salt);
        strncpy(user_pool[count].userpass,cipher,MAX_PASS_LENGTH-1);
      }
    }
    if (mod_type & _USER_ROOTPATH) {
      DIRNORM(user->rootpath,strlen(user->rootpath),0);
      strcpy(user_pool[count].rootpath,user->rootpath);
    }
    if (mod_type & _USER_TAGLINE) strcpy(user_pool[count].tagline,user->tagline);
    if (mod_type & _USER_UID) user_pool[count].uid = user->uid;
    if (mod_type & _USER_GROUPNUM) user_pool[count].group_num = user->group_num;
    if (mod_type & _USER_IDLE) user_pool[count].max_idle_time = user->max_idle_time;
    if (mod_type & _USER_GROUP) memcpy(user_pool[count].groups,user->groups,MAX_GROUPS_PER_USER);
    if (mod_type & _USER_PERMS) user_pool[count].userperms = user->userperms;
    if (mod_type & _USER_FLAGS) memcpy(user_pool[count].flags,user->flags,MAX_FLAGS_NUM);
    if (mod_type & _USER_MAX_ULS) user_pool[count].max_ul_speed = user->max_ul_speed;
    if (mod_type & _USER_MAX_DLS) user_pool[count].max_dl_speed = user->max_dl_speed;
    if (mod_type & _USER_NUMLOGINS) user_pool[count].num_logins = user->num_logins;
    if (mod_type & _USER_IP) {
      int i;
      for ( i=0; i<HARD_IP_PER_USER; i++ )
        strcpy(user_pool[count].ip_allowed[i],user->ip_allowed[i]);
    }
    if (mod_type & _USER_BYTESUL) user_pool[count].stats.bytes_ul_total = user->stats.bytes_ul_total;
    if (mod_type & _USER_BYTESDL) user_pool[count].stats.bytes_dl_total = user->stats.bytes_dl_total;
    if (mod_type & _USER_CREDITS) user_pool[count].credits = user->credits;
    if (mod_type & _USER_USERSLOTS) user_pool[count].user_slots = user->user_slots;
    if (mod_type & _USER_LEECHSLOTS) user_pool[count].leech_slots = user->leech_slots;
    if (mod_type & _USER_RATIO) user_pool[count].ratio = user->ratio;
  } else { /* user not found, add it */
    if (user_count >= user_count_max) return -1;
/*    fprintf(stderr,"Add user %s\n",name);*/
    DIRNORM(user->rootpath,strlen(user->rootpath),0);
    memcpy(&user_pool[user_count],user,sizeof(wzd_user_t));
    if (strcasecmp(user->userpass,"%")==0) {
      /* special case: if user_pool[count].userpass == "%" then any pass
       *  is accepted */
      strcpy(user_pool[user_count].userpass,user->userpass);
    } else {
      /* TODO choose encryption func ? */
      salt[0] = 'a' + (char)(rand()%26);
      salt[1] = 'a' + (char)((rand()*72+3)%26);
      /* FIXME - crypt is NOT reentrant */
      /* XXX - md5 hash in crypt function does NOT work with cygwin */
      cipher = crypt(user->userpass, salt);
      strncpy(user_pool[user_count].userpass,cipher,MAX_PASS_LENGTH-1);
    }
    /* find a free uid */
    user_pool[user_count].uid = find_free_uid(1);

    user_count++;
  } /* if (found) */

  write_user_file();
#endif

error_mod_user_free:
  free(mod);
  free(query);

  return 1;
}

