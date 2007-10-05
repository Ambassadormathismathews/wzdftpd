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

#ifndef WIN32
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <regex.h>
#else
#include "../../gnu_regex/regex.h"
#endif

#include <libwzd-auth/wzd_auth.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_debug.h>

#include "libplaintext_file.h"
#include "libplaintext_main.h"

#define	MAX_LINE		1024

/*
 * 144 Use user/group registry
 */
#define PLAINTEXT_BACKEND_VERSION 144

#define PLAINTEXT_LOG_CHANNEL (RESERVED_LOG_CHANNELS+11)

/* IMPORTANT needed to check version */
BACKEND_NAME(plaintext);
BACKEND_VERSION(PLAINTEXT_BACKEND_VERSION);

#define	HARD_DEF_USER_MAX	640
#define	HARD_DEF_GROUP_MAX	640

char * USERS_FILE = NULL;

unsigned int user_count, user_count_max=0;

unsigned int group_count, group_count_max=0;




void plaintext_log(const char * error, const char * filename, const char * func_name, int line)
{
  out_log(PLAINTEXT_LOG_CHANNEL, "%s(%s):%d %s",filename,func_name,line,error);
}



static int FCN_INIT(const char *arg)
{
  int ret;

  /* defaults to the standard log */
  if (log_get(PLAINTEXT_LOG_CHANNEL) == -1)
    log_set(PLAINTEXT_LOG_CHANNEL,log_get(LEVEL_NORMAL));

  USERS_FILE = malloc(256);

  user_count_max = HARD_DEF_USER_MAX; /* XXX FIXME remove me */
  group_count_max = HARD_DEF_GROUP_MAX; /* XXX FIXME remove me */

  ret = read_files( (const char *)arg);

  /* TODO check user definitions (no missing fields, etc) */
  if (!ret)
    ERRLOG("Backend plaintext initialized\n");

  return ret;
}

static int FCN_FINI(void)
{
  ERRLOG("Backend plaintext unloading\n");

  free(USERS_FILE);
  USERS_FILE = NULL;

  return 0;
}

static uid_t FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  wzd_user_t * loop_user;

  if ( (loop_user = user_get_by_name(login)) != NULL )
    return loop_user->uid; /** \todo update registered user from backend data, or at least
                             check if backend file was not modified ! */

  return INVALID_USER;
}

static uid_t FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  wzd_user_t * loop_user;

  loop_user = user_get_by_name(login);

  if (loop_user == NULL) {
#ifdef DEBUG
out_err(LEVEL_HIGH," plaintext: User %s not found\n",login);
#endif
    return INVALID_USER;
  }

  /* special case: if loop_user->userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(loop_user->userpass,"%")==0) {
  }
  /* authentication is delegated to libwzd-auth */
  else {
    if (check_auth(login, pass, loop_user->userpass)==1)
      return loop_user->uid;
    return INVALID_USER;
  }

  return loop_user->uid;
}

static uid_t FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  wzd_user_t * loop_user;

  if ( (loop_user = user_get_by_name(name)) != NULL )
    return loop_user->uid;

  return INVALID_USER;
}

static gid_t FCN_FIND_GROUP(const char *name, wzd_group_t * group)
{
  wzd_group_t * loop_group;

  if ( (loop_group = group_get_by_name(name)) != NULL )
    return loop_group->gid;

  return INVALID_GROUP;
}


/* if user does not exist, add it */
static int FCN_MOD_USER(uid_t uid, wzd_user_t * user, unsigned long mod_type)
{
  wzd_user_t * loop_user;

  if (mod_type == _USER_CREATE) { /* user not found, add it */
    char buffer[MAX_PASS_LENGTH];

    if (!user) return -1;

    /** \todo check if user is valid (homedir != NULL etc.) */

    loop_user = user_get_by_name(user->username);
    if (loop_user != NULL) return -2; /* user already exists */

    if (user_count >= user_count_max) return -1;
/*    fprintf(stderr,"Add user %s\n",name);*/
    DIRNORM(user->rootpath,strlen(user->rootpath),0);

    memcpy(buffer, user->userpass, MAX_PASS_LENGTH);
    if (strcasecmp(buffer,"%")==0) {
      /* special case: if loop_user->userpass == "%" then any pass
       *  is accepted */
      strcpy(buffer,user->userpass);
    } else {
      /* TODO choose encryption func ? */
      if (changepass(user->username,buffer,user->userpass, MAX_PASS_LENGTH-1)) {
        memset(buffer,0,MAX_PASS_LENGTH);
        return -1;
      }
    }
    memset(buffer,0,MAX_PASS_LENGTH);
    /* find a free uid */
    user->uid = user_find_free_uid(1);

    if (user->uid != (uid_t)-1) {
      int err;
      err = user_register(user,1 /* XXX backend id */);
      if ((uid_t)err != user->uid) {
        char errbuf[1024];
        snprintf(errbuf,sizeof(errbuf),"ERROR Could not register user %s\n",user->username);
        ERRLOG(errbuf);
      }
    }

    user_count++;
  } else { /* modification */

    loop_user = user_get_by_id(uid);

/*    fprintf(stderr,"User %s exist\n",name);*/
    if (!user) { /* delete user permanently */

      loop_user = user_unregister(uid);
      user_free(loop_user);

      return 0;
    }
    /* basic verification: trying to commit on self ? then ok */
    if (loop_user == user) {
      if (mod_type & _USER_USERPASS) {
        char buffer[MAX_PASS_LENGTH];
        memcpy(buffer, user->userpass, MAX_PASS_LENGTH);
        if (strcasecmp(buffer,"%")==0) {
          /* special case: if loop_user->userpass == "%" then any pass
           *  is accepted */
          strcpy(buffer,user->userpass);
        } else {
          /* TODO choose encryption func ? */
          if (changepass(user->username,buffer,user->userpass, MAX_PASS_LENGTH-1)) {
            memset(buffer,0,MAX_PASS_LENGTH);
            return -1;
          }
        }
        memset(buffer,0,MAX_PASS_LENGTH);
      }
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
        if (changepass(loop_user->username,user->userpass, loop_user->userpass, MAX_PASS_LENGTH-1)) {
          memset(user->userpass,0,MAX_PASS_LENGTH);
          return -1;
        }
        memset(user->userpass,0,MAX_PASS_LENGTH);
      }
    }
    if (mod_type & _USER_ROOTPATH) {
      DIRNORM(user->rootpath,strlen(user->rootpath),0);
      strcpy(loop_user->rootpath,user->rootpath);
    }
    if (mod_type & _USER_TAGLINE) strcpy(loop_user->tagline,user->tagline);
    if (mod_type & _USER_UID) loop_user->uid = user->uid;
    if (mod_type & _USER_CREATOR) loop_user->creator = user->creator;
    if (mod_type & _USER_GROUPNUM) loop_user->group_num = user->group_num;
    if (mod_type & _USER_IDLE) loop_user->max_idle_time = user->max_idle_time;
    if (mod_type & _USER_GROUP) memcpy(loop_user->groups,user->groups,MAX_GROUPS_PER_USER);
    if (mod_type & _USER_PERMS) loop_user->userperms = user->userperms;
    if (mod_type & _USER_FLAGS) memcpy(loop_user->flags,user->flags,MAX_FLAGS_NUM);
    if (mod_type & _USER_MAX_ULS) loop_user->max_ul_speed = user->max_ul_speed;
    if (mod_type & _USER_MAX_DLS) loop_user->max_dl_speed = user->max_dl_speed;
    if (mod_type & _USER_NUMLOGINS) loop_user->num_logins = user->num_logins;
    if (mod_type & _USER_IP) {
      /* replace old list by the new one */
      struct wzd_ip_list_t * old_list;

      if (loop_user->ip_list != user->ip_list) {
        old_list = loop_user->ip_list;
        loop_user->ip_list = user->ip_list;
        ip_list_free(old_list);
      }
    }
    if (mod_type & _USER_BYTESUL) loop_user->stats.bytes_ul_total = user->stats.bytes_ul_total;
    if (mod_type & _USER_BYTESDL) loop_user->stats.bytes_dl_total = user->stats.bytes_dl_total;
    if (mod_type & _USER_CREDITS) loop_user->credits = user->credits;
    if (mod_type & _USER_USERSLOTS) loop_user->user_slots = user->user_slots;
    if (mod_type & _USER_LEECHSLOTS) loop_user->leech_slots = user->leech_slots;
    if (mod_type & _USER_RATIO) loop_user->ratio = user->ratio;
  } /* if (mod_type == _USER_CREATE) */

  write_user_file();

  return 0;
}

static int FCN_MOD_GROUP(gid_t gid, wzd_group_t * group, unsigned long mod_type)
{
  wzd_group_t * loop_group;

  if (mod_type == _GROUP_CREATE) { /* group not found, add it */
    if (!group) return -1;

    /** \todo check if group is valid (homedir != NULL etc.) */

    loop_group = group_get_by_name(group->groupname);
    if (loop_group != NULL) return -2; /* group already exists */

    if (group_count >= group_count_max) return -1;
/*    fprintf(stderr,"Add group %s\n",name);*/
    DIRNORM(group->defaultpath,strlen(group->defaultpath),0);

    group->gid = group_find_free_gid(1);

    if (group->gid != (gid_t)-1) {
      int err;
      err = group_register(group,1 /* XXX backend id */);
      if ((gid_t)err != group->gid) {
        char errbuf[1024];
        snprintf(errbuf,sizeof(errbuf),"ERROR Could not register group %s\n",group->groupname);
        ERRLOG(errbuf);
      }
    }

    group_count++;
  } else { /* modification */
    loop_group = group_get_by_id(gid);

/*    fprintf(stderr,"User %s exist\n",name);*/
    if (!group) { /* delete group permanently */

      loop_group = group_unregister(loop_group->gid);
      group_free(loop_group);

      return 0;
    }
    /* basic verification: trying to commit on self ? then ok */
    if (loop_group == group) {
      return 0;
    }
    if (mod_type & _GROUP_GROUPNAME) strcpy(loop_group->groupname,group->groupname);
    if (mod_type & _GROUP_GROUPPERMS) loop_group->groupperms = group->groupperms;
    if (mod_type & _GROUP_FLAGS) memcpy(loop_group->flags,group->flags,MAX_FLAGS_NUM);
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
      /* replace old list by the new one */
      struct wzd_ip_list_t * old_list;

      if (loop_group->ip_list != group->ip_list) {
        old_list = loop_group->ip_list;
        loop_group->ip_list = group->ip_list;
        ip_list_free(old_list);
      }
    }
  } /* if (mod_type == _GROUP_CREATE) */

  write_user_file();

  return 0;
}

static int FCN_COMMIT_CHANGES(void)
{
  return write_user_file();
}

static wzd_user_t * FCN_GET_USER(uid_t uid)
{
  if (uid == (uid_t)GET_USER_LIST) {
    return (wzd_user_t*)user_get_list(1 /* backend id */);
  }

  if (uid == (uid_t)-1) return NULL;

  return user_get_by_id(uid);
}

static wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  if (gid == (gid_t)GET_GROUP_LIST) {
    return (wzd_group_t*)group_get_list(1 /* backend id */);
  }

  if (gid == (gid_t)-1) return NULL;

  return group_get_by_id(gid);
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

