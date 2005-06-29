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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#ifndef _MSC_VER
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <regex.h>
#else
#include "../../visual/gnu_regex_dist/regex.h"
#endif

#include <libwzd-auth/wzd_auth.h>

#include "wzd_backend.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_debug.h"

#include "libplaintext_file.h"
#include "libplaintext_main.h"

#define	MAX_LINE		1024


#define PLAINTEXT_BACKEND_VERSION 143

#define PLAINTEXT_LOG_CHANNEL (RESERVED_LOG_CHANNELS+11)

/* IMPORTANT needed to check version */
BACKEND_NAME(plaintext);
BACKEND_VERSION(PLAINTEXT_BACKEND_VERSION);

#define	HARD_DEF_USER_MAX	640
#define	HARD_DEF_GROUP_MAX	640

char * USERS_FILE = NULL;

List user_list;
unsigned int user_count, user_count_max=0;

List group_list;
unsigned int group_count, group_count_max=0;




gid_t FCN_FIND_GROUP(const char *name, wzd_group_t * group);


void plaintext_log(const char * error, const char * filename, const char * func_name, int line)
{
  out_log(PLAINTEXT_LOG_CHANNEL, "%s(%s):%d %s",filename,func_name,line,error);
}


static uid_t find_free_uid(uid_t start)
{
  uid_t uid = start;
  unsigned int found;
  unsigned int uid_is_free = 0;
  ListElmt * elmnt;
  wzd_user_t * user;

  while (!uid_is_free) {
    found = 0;
    for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt))
    {
      user = list_data(elmnt);
      if (user && user->uid == uid) { found=1; break; }
    }
    if (!found) return uid;
    uid ++;
    if (uid == (uid_t)-1) return (uid_t)-1; /* we have too many users ! */
  }

  /* we should never be here */
  return (uid_t)-1;
}

static gid_t find_free_gid(gid_t start)
{
  gid_t gid = start;
  unsigned int found;
  unsigned int gid_is_free = 0;
  ListElmt * elmnt;
  wzd_group_t * group;

  while (!gid_is_free) {
    found = 0;
    for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt))
    {
      group = list_data(elmnt);
      if (group && group->gid == gid) { found=1; break; }
    }
    if (!found) return gid;
    gid ++;
    if (gid == (gid_t)-1) return (gid_t)-1; /* we have too many groups ! */
  }

  /* we should never be here */
  return (gid_t)-1;
}


static wzd_user_t * _get_user_from_uid(uid_t uid)
{
  ListElmt * elmnt;
  wzd_user_t * user;

  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
    user = list_data(elmnt);
    if (user && user->uid == uid) return user;
  }
  return NULL;
}

wzd_group_t * plaintext_get_group_from_gid(gid_t gid)
{
  ListElmt * elmnt;
  wzd_group_t * group;

  for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt)) {
    group = list_data(elmnt);
    if (group && group->gid == gid) return group;
  }
  return NULL;
}

static void user_init_struct(wzd_user_t * user)
{
  if (!user) return;

  memset(user,0,sizeof(wzd_user_t));

  user->uid = (uid_t)-1;
}

wzd_user_t * user_allocate_new(void)
{
  wzd_user_t * user;

  user = wzd_malloc(sizeof(wzd_user_t));
  if (!user) return NULL;
  user_init_struct(user);

  return user;
}

static void group_init_struct(wzd_group_t * group)
{
  if (!group) return;

  memset(group,0,sizeof(wzd_group_t));

  group->gid = (gid_t)-1;
}


wzd_group_t * group_allocate_new(void)
{
  wzd_group_t * group;

  group = wzd_malloc(sizeof(wzd_group_t));
  if (!group) return NULL;
  group_init_struct(group);

  return group;
}




int FCN_INIT(const char *arg)
{
  int ret;

  USERS_FILE = malloc(256);

  user_count_max = HARD_DEF_USER_MAX; /* XXX FIXME remove me */
  group_count_max = HARD_DEF_GROUP_MAX; /* XXX FIXME remove me */

  list_init(&user_list, wzd_free);
  list_init(&group_list, wzd_free);

  ret = read_files( (const char *)arg);

  /* TODO check user definitions (no missing fields, etc) */
  ERRLOG("Backend plaintext initialized\n");

  return ret;
}

int FCN_FINI(void)
{
  ERRLOG("Backend plaintext unloading\n");
  list_destroy(&user_list);
  list_destroy(&group_list);

  free(USERS_FILE);
  USERS_FILE = NULL;

  return 0;
}

uid_t FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  int found;
  ListElmt * elmnt;
  wzd_user_t * loop_user;

  found = 0;

  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
    if (!(loop_user = list_data(elmnt))) continue;
    if (strcmp(login,loop_user->username)==0)
      { found = 1; break; }
  }

  if (!found) return (uid_t)-1;
  return loop_user->uid;
}

uid_t FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  int found;
  ListElmt * elmnt;
  wzd_user_t * loop_user;

  found = 0;
  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
    if (!(loop_user = list_data(elmnt))) continue;
    if (strcmp(login,loop_user->username)==0)
      { found = 1; break; }
  }

  if (!found) {
#ifdef DEBUG
out_err(LEVEL_HIGH," plaintext: User %s not found\n",login);
#endif
    return (uid_t)-1;
  }

  /* special case: if loop_user->userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(loop_user->userpass,"%")==0) {
  }
  /* authentication is delegated to libwzd-auth */
  else {
    if (check_auth(login, pass, loop_user->userpass)==1)
      return loop_user->uid;
    return (uid_t)-1;
  }

  return loop_user->uid;
}

uid_t FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  int found;
  ListElmt * elmnt;
  wzd_user_t * loop_user;

  found = 0;
  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
    if (!(loop_user = list_data(elmnt))) continue;
    if (strcmp(name,loop_user->username)==0)
      { found = 1; break; }
  }

  if (!found) return (uid_t)-1;
  else return loop_user->uid;
}

gid_t FCN_FIND_GROUP(const char *name, wzd_group_t * group)
{
  int found;
  ListElmt * elmnt;
  wzd_group_t * loop_group;

  if (!name || strlen(name)<=0) return -1;

  found = 0;
  for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt)) {
    if (!(loop_group = list_data(elmnt))) continue;
    if (strcmp(name,loop_group->groupname)==0)
      { found = 1; break; }
  }

  return (found) ? loop_group->gid : (gid_t)-1;
}


/* if user does not exist, add it */
int FCN_MOD_USER(const char *name, wzd_user_t * user, unsigned long mod_type)
{
  int found;
  ListElmt * elmnt;
  wzd_user_t * loop_user;
  void * data;

  found = 0;
  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
    if (!(loop_user = list_data(elmnt))) continue;
    if (strcmp(name,loop_user->username)==0)
      { found = 1; break; }
  }

  if (found) { /* user exist */
/*    fprintf(stderr,"User %s exist\n",name);*/
    if (!user) { /* delete user permanently */
      if (list_size(&user_list)==0) return -1;

      loop_user = list_data(user_list.head);
      if ( strcmp(loop_user->username,name)==0 ) {
        list_rem_next(&user_list, NULL, &data);
        wzd_free( (wzd_user_t*)data );
        return 0;
      }

      for (elmnt=user_list.head; list_next(elmnt); elmnt=list_next(elmnt)) {
        loop_user = list_data(list_next(elmnt));
        if (loop_user && loop_user->username[0] != '\0') {
          /* test entry */
          if ( strcmp(loop_user->username,name)==0 ) {
            list_rem_next(&user_list, elmnt, &data);
            wzd_free( (wzd_user_t*)data );
            return 0;
          }
        }
      } /* for */

      return 0;
    }
    /* basic verification: trying to commit on self ? then ok */
    if (loop_user == user) {
      return 0;
    }
    if (mod_type & _USER_USERNAME) strcpy(loop_user->username,user->username);
    if (mod_type & _USER_USERPASS) {
      if (strcasecmp(user->userpass,"%")==0) {
        /* special case: if loop_user->userpass == "%" then any pass
         *  is accepted */
        strcpy(loop_user->userpass,user->userpass);
      } else {
        /* TODO choose encryption func ? */
        if (changepass_crypt(user->userpass, loop_user->userpass, MAX_PASS_LENGTH-1)) {
          return -1;
        }
      }
    }
    if (mod_type & _USER_ROOTPATH) {
      DIRNORM(user->rootpath,strlen(user->rootpath),0);
      strcpy(loop_user->rootpath,user->rootpath);
    }
    if (mod_type & _USER_TAGLINE) strcpy(loop_user->tagline,user->tagline);
    if (mod_type & _USER_UID) loop_user->uid = user->uid;
    if (mod_type & _USER_GROUPNUM) loop_user->group_num = user->group_num;
    if (mod_type & _USER_IDLE) loop_user->max_idle_time = user->max_idle_time;
    if (mod_type & _USER_GROUP) memcpy(loop_user->groups,user->groups,MAX_GROUPS_PER_USER);
    if (mod_type & _USER_PERMS) loop_user->userperms = user->userperms;
    if (mod_type & _USER_FLAGS) memcpy(loop_user->flags,user->flags,MAX_FLAGS_NUM);
    if (mod_type & _USER_MAX_ULS) loop_user->max_ul_speed = user->max_ul_speed;
    if (mod_type & _USER_MAX_DLS) loop_user->max_dl_speed = user->max_dl_speed;
    if (mod_type & _USER_NUMLOGINS) loop_user->num_logins = user->num_logins;
    if (mod_type & _USER_IP) {
      int i;
      for ( i=0; i<HARD_IP_PER_USER; i++ )
        strcpy(loop_user->ip_allowed[i],user->ip_allowed[i]);
    }
    if (mod_type & _USER_BYTESUL) loop_user->stats.bytes_ul_total = user->stats.bytes_ul_total;
    if (mod_type & _USER_BYTESDL) loop_user->stats.bytes_dl_total = user->stats.bytes_dl_total;
    if (mod_type & _USER_CREDITS) loop_user->credits = user->credits;
    if (mod_type & _USER_USERSLOTS) loop_user->user_slots = user->user_slots;
    if (mod_type & _USER_LEECHSLOTS) loop_user->leech_slots = user->leech_slots;
    if (mod_type & _USER_RATIO) loop_user->ratio = user->ratio;
  } else { /* user not found, add it */
    if (!user) return -1;
    if (user_count >= user_count_max) return -1;
/*    fprintf(stderr,"Add user %s\n",name);*/
    DIRNORM(user->rootpath,strlen(user->rootpath),0);
    loop_user = wzd_malloc(sizeof(wzd_user_t));
    memcpy(loop_user,user,sizeof(wzd_user_t));
    if (strcasecmp(user->userpass,"%")==0) {
      /* special case: if loop_user->userpass == "%" then any pass
       *  is accepted */
      strcpy(loop_user->userpass,user->userpass);
    } else {
      /* TODO choose encryption func ? */
      if (changepass_crypt(user->userpass, loop_user->userpass, MAX_PASS_LENGTH-1)) {
        return -1;
      }
    }
    /* find a free uid */
    loop_user->uid = find_free_uid(1);

    list_ins_next(&user_list,list_tail(&user_list),loop_user);

    user_count++;
  } /* if (found) */

  write_user_file();

  return 0;
}

int FCN_MOD_GROUP(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  int found;
  ListElmt * elmnt;
  wzd_group_t * loop_group;
  void * data;

  found = 0;
  for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt)) {
    if (!(loop_group = list_data(elmnt))) continue;
    if (strcmp(name,loop_group->groupname)==0)
      { found = 1; break; }
  }

  if (found) { /* user exist */
/*    fprintf(stderr,"User %s exist\n",name);*/
    if (!group) { /* delete group permanently */
      if (list_size(&group_list)==0) return -1;

      loop_group = list_data(group_list.head);
      if ( strcmp(loop_group->groupname,name)==0 ) {
        list_rem_next(&group_list, NULL, &data);
        wzd_free( (wzd_group_t*)data );
        return 0;
      }

      for (elmnt=group_list.head; list_next(elmnt); elmnt=list_next(elmnt)) {
        loop_group = list_data(list_next(elmnt));
        if (loop_group && loop_group->groupname[0] != '\0') {
          /* test entry */
          if ( strcmp(loop_group->groupname,name)==0 ) {
            list_rem_next(&group_list, elmnt, &data);
            wzd_free( (wzd_group_t*)data );
            return 0;
          }
        }
      } /* for */

      return 0;
    }
    /* basic verification: trying to commit on self ? then ok */
    if (loop_group == group) {
      return 0;
    }
    if (mod_type & _GROUP_GROUPNAME) strcpy(loop_group->groupname,group->groupname);
    if (mod_type & _GROUP_GROUPPERMS) loop_group->groupperms = group->groupperms;
    if (mod_type & _GROUP_IDLE) loop_group->max_idle_time = group->max_idle_time;
    if (mod_type & _GROUP_MAX_ULS) loop_group->max_ul_speed = group->max_ul_speed;
    if (mod_type & _GROUP_MAX_DLS) loop_group->max_dl_speed = group->max_dl_speed;
    if (mod_type & _GROUP_RATIO) loop_group->ratio = group->ratio;
    if (mod_type & _GROUP_TAGLINE) strcpy(loop_group->tagline,group->tagline);
    if (mod_type & _GROUP_DEFAULTPATH) {
      DIRNORM(group->defaultpath,strlen(group->defaultpath),0);
      strcpy(loop_group->defaultpath,group->defaultpath);
    }
    if (mod_type & _GROUP_NUMLOGINS) loop_group->num_logins = group->num_logins;
    if (mod_type & _GROUP_IP) {
      int i;
      for ( i=0; i<HARD_IP_PER_GROUP; i++ )
        strcpy(loop_group->ip_allowed[i],group->ip_allowed[i]);
    }
  } else { /* group not found, add it */
    if (!group) return -1;
    if (group_count >= group_count_max) return -1;
/*    fprintf(stderr,"Add group %s\n",name);*/
    DIRNORM(group->defaultpath,strlen(group->defaultpath),0);
    loop_group = wzd_malloc(sizeof(wzd_group_t));
    memcpy(loop_group,group,sizeof(wzd_group_t));
    loop_group->gid = find_free_gid(1);

    list_ins_next(&group_list,list_tail(&group_list),loop_group);

    group_count++;
  } /* if (found) */

  write_user_file();

  return 0;
}

int FCN_COMMIT_CHANGES(void)
{
  return write_user_file();
}

wzd_user_t * FCN_GET_USER(uid_t uid)
{
  int index;
  wzd_user_t * user;
  ListElmt * elmnt;
  wzd_user_t * loop_user;

  if (uid == (uid_t)-2) {
    uid_t * uid_list = NULL;
    int size;

    size = list_size(&user_list);

    uid_list = (uid_t*)wzd_malloc((size+1)*sizeof(uid_t));
    index = 0;
    for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
      loop_user = list_data(elmnt);
      if (loop_user && loop_user->username[0]!='\0' && loop_user->uid!=(uid_t)-1)
        uid_list[index++] = loop_user->uid;
    }
    uid_list[index] = (uid_t)-1;
    uid_list[size] = (uid_t)-1;

    return (wzd_user_t*)uid_list;
  }

  if (uid == (uid_t)-1) return NULL;

  loop_user =  _get_user_from_uid(uid);
  if (loop_user)
  {
    if (loop_user->username[0] == '\0') return NULL;
    user = wzd_malloc(sizeof(wzd_user_t));
    if (!user) return NULL;
    memcpy(user, loop_user, sizeof(wzd_user_t));
    return user;
  }
  return NULL;
}

wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  gid_t index;
  wzd_group_t * group;
  ListElmt * elmnt;
  wzd_group_t * loop_group;

  if (gid == (gid_t)-2) {
    gid_t * gid_list = NULL;
    int size;

    size = list_size(&group_list);

    gid_list = (gid_t*)wzd_malloc((size+1)*sizeof(gid_t));
    index = 0;
    for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt)) {
      loop_group = list_data(elmnt);
      if (loop_group && loop_group->groupname[0]!='\0' && loop_group->gid!=(gid_t)-1)
        gid_list[index++] = loop_group->gid;
    }
    gid_list[index] = (gid_t)-1;
    gid_list[size] = (gid_t)-1;

    return (wzd_group_t*)gid_list;
  }

  if (gid == (gid_t)-1) return NULL;

  loop_group =  plaintext_get_group_from_gid(gid);
  if (loop_group)
  {
    if (loop_group->groupname[0] == '\0') return NULL;
    group = wzd_malloc(sizeof(wzd_group_t));
    if (!group) return NULL;
    memcpy(group, loop_group, sizeof(wzd_group_t));
    return group;
  }
  return NULL;
}

int wzd_backend_init(wzd_backend_t * backend)
{
  if (!backend) return -1;

  backend->name = wzd_strdup("plaintext");
  backend->version = PLAINTEXT_BACKEND_VERSION;

  backend->backend_init = FCN_INIT;
  backend->backend_exit = FCN_FINI;

  backend->backend_validate_login = FCN_VALIDATE_LOGIN;
  backend->backend_validate_pass = FCN_VALIDATE_PASS;

  backend->backend_get_user = FCN_GET_USER;
  backend->backend_get_group = FCN_GET_GROUP;

  backend->backend_find_user = FCN_FIND_USER;
  backend->backend_find_group = FCN_FIND_GROUP;

  backend->backend_mod_user = FCN_MOD_USER;
  backend->backend_mod_group = FCN_MOD_GROUP;

  backend->backend_chpass = NULL;
  backend->backend_commit_changes = FCN_COMMIT_CHANGES;

  return 0;
}

