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
#include <string.h>

#include <sys/stat.h>

#include "wzd_structs.h"

#include "wzd_misc.h"

#include "wzd_vars.h"
#include "wzd_log.h"

int vars_get(const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  if (!config) return 1;

  if (strcasecmp(varname,"bw")==0) {
    snprintf(data,datalength,"%lu",get_bandwidth());
    return 0;
  }
  if (strcmp(varname,"login_pre_ip_check")==0) {
    snprintf(data,datalength,"%d",config->login_pre_ip_check);
    return 0;
  }
  if (strcmp(varname,"loglevel")==0) {
    snprintf(data,datalength,"%s",loglevel2str(config->loglevel));
    return 0;
  }
  if (strcasecmp(varname,"max_dl")==0) {
    snprintf(data,datalength,"%d",config->global_dl_limiter.maxspeed);
    return 0;
  }
  if (strcasecmp(varname,"max_threads")==0) {
    snprintf(data,datalength,"%d",config->max_threads);
    return 0;
  }
  if (strcasecmp(varname,"max_ul")==0) {
    snprintf(data,datalength,"%d",config->global_ul_limiter.maxspeed);
    return 0;
  }
  if (strcasecmp(varname,"pasv_low")==0) {
    snprintf(data,datalength,"%d",config->pasv_low_range);
    return 0;
  }
  if (strcasecmp(varname,"pasv_high")==0) {
    snprintf(data,datalength,"%d",config->pasv_high_range);
    return 0;
  }
  if (strcasecmp(varname,"port")==0) {
    snprintf(data,datalength,"%d",config->port);
    return 0;
  }
  if (strcmp(varname,"uptime")==0) {
    time_t t;

    time(&t);
    t = t - config->server_start;
    snprintf(data,datalength,"%ld",t);
    return 0;
  }

  return 1;
}

int vars_set(const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  int i;
  unsigned long ul;

  if (!data || !config) return 1;

  if (strcasecmp(varname,"deny_access_files_uploaded")==0) {
    ul = strtoul(data,NULL,0);
    if (ul==1) { CFG_SET_OPTION(config,CFG_OPT_DENY_ACCESS_FILES_UPLOADED); return 0; }
    if (ul==0) { CFG_CLR_OPTION(config,CFG_OPT_DENY_ACCESS_FILES_UPLOADED); return 0; }
    return 1;
  }
  if (strcasecmp(varname,"hide_dotted_files")==0) {
    ul = strtoul(data,NULL,0);
    if (ul==1) { CFG_SET_OPTION(config,CFG_OPT_HIDE_DOTTED_FILES); return 0; }
    if (ul==0) { CFG_CLR_OPTION(config,CFG_OPT_HIDE_DOTTED_FILES); return 0; }
    return 1;
  }
  if (strcasecmp(varname,"loglevel")==0) {
    i = str2loglevel(data);
    if (i==-1) {
      return 1;
    }
    config->loglevel = i;
    return 0;
  }
  return 1;
}

int vars_user_get(const char *username, const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  wzd_user_t * user;
  wzd_group_t * group;

  if (!username || !varname) return 1;

  user = GetUserByName(username);
  if (!user) return 1;

  if (strcasecmp(varname,"group")==0) {
    if (user->group_num > 0) {
      group = GetGroupByID(user->groups[0]);
      snprintf(data,datalength,"%s",group->groupname);
    } else
      snprintf(data,datalength,"no group");
    return 0;
  }
  if (strcasecmp(varname,"home")==0) {
    snprintf(data,datalength,"%s",user->rootpath);
    return 0;
  }
  if (strcasecmp(varname,"maxdl")==0) {
    snprintf(data,datalength,"%ld",user->max_dl_speed);
    return 0;
  }
  if (strcasecmp(varname,"maxul")==0) {
    snprintf(data,datalength,"%ld",user->max_ul_speed);
    return 0;
  }
  if (strcasecmp(varname,"name")==0) {
    snprintf(data,datalength,"%s",user->username);
    return 0;
  }
  if (strcasecmp(varname,"tag")==0) {
    if (user->tagline[0] != '\0')
      snprintf(data,datalength,"%s",user->tagline);
    else
      snprintf(data,datalength,"no tagline set");
    return 0;
  }

  return 1;
}

int vars_user_addip(const char *username, const char *ip, wzd_config_t *config)
{
  wzd_user_t *user;
  int i;

  if (!username || !ip) return 1;

  user = GetUserByName(username);
  if (!user) return -1;

  do {

    /* check if ip is already present or included in list, or if it shadows one present */
    for (i=0; i<HARD_IP_PER_USER; i++)
    {
      if (user->ip_allowed[i][0]=='\0') continue;
      if (my_str_compare(ip, user->ip_allowed[i])==1) {
        /* ip is already included in list */
        return 1;
      }
      if (my_str_compare(user->ip_allowed[i],ip)==1) {
        /* ip will shadow one ore more ip in list */
        return 2;
      }
    }

    /* update user */
    for (i=0; i<HARD_IP_PER_USER; i++)
      if (user->ip_allowed[i][0]=='\0') break;

    /* no more slots ? */
    if (i==HARD_IP_PER_USER) {
      /* no more slots available - either recompile with more slots, or use them more cleverly */
      return 3;
    }
    /* TODO check ip validity */
    strncpy(user->ip_allowed[i],ip,MAX_IP_LENGTH-1);

/*    ip = strtok_r(NULL," \t\r\n",&ptr);*/
    ip = NULL; /** \todo add only one ip (for the moment) */
  } while (ip);

  /* commit to backend */
  /* FIXME backend name hardcoded */
  return backend_mod_user("plaintext", username, user, _USER_IP);
}

int vars_user_delip(const char *username, const char *ip, wzd_config_t *config)
{
  char *ptr_ul;
  wzd_user_t *user;
  int i;
  unsigned long ul;
  int found;

  if (!username || !ip) return 1;

  user = GetUserByName(username);
  if (!user) return -1;

  do {

    /* try to take argument as a slot number */
    ul = strtoul(ip,&ptr_ul,0);
    if (*ptr_ul=='\0') {
      if (ul <= 0 || ul >= HARD_IP_PER_USER) {
        /* Invalid ip slot number */
        return 1;
      }
      ul--; /* to index slot number from 1 */
      if (user->ip_allowed[ul][0] == '\0') {
        /* Slot is already empty */
        return 2;
      }
      user->ip_allowed[ul][0] = '\0';
    } else { /* if (*ptr=='\0') */

      /* try to find ip in list */
      found = 0;
      for (i=0; i<HARD_IP_PER_USER; i++)
      {
        if (user->ip_allowed[i][0]=='\0') continue;
        if (strcmp(ip,user->ip_allowed[i])==0) {
          user->ip_allowed[i][0] = '\0';
          found = 1;
        }
      }

      if (!found) {
        /* IP not found */
        return 3;
      }
    } /* if (*ptr=='\0') */

/*    ip = strtok_r(NULL," \t\r\n",&ptr);*/
    ip = NULL; /** \todo add only one ip (for the moment) */
  } while (ip);

  /* commit to backend */
  /* FIXME backend name hardcoded */
  return backend_mod_user("plaintext", username, user, _USER_IP);
}

int vars_user_set(const char *username, const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  wzd_user_t * user;
  unsigned long mod_type;
  unsigned long ul;
  char *ptr;
  int ret;

  if (!username || !varname) return 1;

  user = GetUserByName(username);
  if (!user) return -1;

  /* find modification type */
  mod_type = _USER_NOTHING;

  /* addip */
  if (strcmp(varname, "addip")==0) {
    return vars_user_addip(username, data, config);
  }
  /* bytes_ul and bytes_dl should never be changed ... */
  /* delip */
  else if (strcmp(varname, "delip")==0) {
    return vars_user_delip(username, data, config);
  }
  /* flags */ /* TODO accept modifications style +f or -f */
  else if (strcmp(varname, "flags")==0) {
    mod_type = _USER_FLAGS;
    strncpy(user->flags, data, MAX_FLAGS_NUM-1);
  }
  /* homedir */
  else if (strcmp(varname, "homedir")==0) {
    /* check if homedir exist */
    {
      struct stat s;
      if (stat(data,&s) || !S_ISDIR(s.st_mode)) {
        /* Homedir does not exist */
        return 1;
      }
    }
    mod_type = _USER_ROOTPATH;
    strncpy(user->rootpath, data, WZD_MAX_PATH);
  }
  /* leech_slots */
  else if (strcmp(varname, "leech_slots")==0) {
    ul=strtoul(data, &ptr, 0);
    /* TODO compare with USHORT_MAX */
    if (*ptr) return -1;
    mod_type = _USER_LEECHSLOTS; user->leech_slots = (unsigned short)ul;
  }
  /* max_dl */
  else if (strcmp(varname, "max_dl")==0) {
    ul=strtoul(data, &ptr, 0);
    if (*ptr) return -1;
    mod_type = _USER_MAX_DLS; user->max_dl_speed = ul;
  }
  /* max_idle */
  else if (strcmp(varname, "max_idle")==0) {
    ul=strtoul(data, &ptr, 0);
    if (*ptr) return -1;
    mod_type = _USER_IDLE; user->max_idle_time = ul;
  }
  /* max_ul */
  else if (strcmp(varname, "max_ul")==0) {
    ul=strtoul(data, &ptr, 0);
    if (*ptr) return -1;
    mod_type = _USER_MAX_ULS; user->max_ul_speed = ul;
  }
  /* num_logins */
  else if (strcmp(varname, "num_logins")==0) {
    ul=strtoul(data, &ptr,0);
    if (*ptr) return -1;
    mod_type = _USER_NUMLOGINS; user->num_logins = (unsigned short)ul;
  }
  /* pass */
  else if (strcmp(varname, "pass")==0) {
    mod_type = _USER_USERPASS;
    strncpy(user->userpass, data, sizeof(user->userpass));
  }
  /* perms */
  else if (strcmp(varname, "perms")==0) {
    ul=strtoul(data, &ptr, 0);
    if (*ptr) return -1;
    mod_type = _USER_PERMS; user->userperms = ul;
  }
  /* ratio */
  else if (strcmp(varname, "ratio")==0) {
    ul=strtoul(data, &ptr,0);
    if (*ptr) return -1;
    mod_type = _USER_RATIO; user->ratio = ul;
  }
  /* tagline */
  else if (strcmp(varname, "tagline")==0) {
    mod_type = _USER_TAGLINE;
    strncpy(user->tagline, data, sizeof(user->tagline));
  }
  /* uid */ /* FIXME useless ? */
  /* username (?) */
  else if (strcmp(varname, "name")==0) {
    mod_type = _USER_USERNAME;
    strncpy(user->username, data, sizeof(user->username));
  }
  /* user_slots */
  else if (strcmp(varname, "user_slots")==0) {
    ul=strtoul(data, &ptr, 0);
    /* TODO compare with USHORT_MAX */
    if (*ptr) return -1;
    mod_type = _USER_USERSLOTS; user->user_slots = (unsigned short)ul;
  }

  /* commit to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_user("plaintext", username, user, mod_type);

  return ret;
}

int vars_user_new(const char *username, const char *pass, const char *groupname, wzd_config_t * config)
{
  wzd_user_t user, *test_user;
  wzd_group_t *group;
  unsigned int ratio = 3; /* TODO XXX FIXME default ratio value hardcoded */
  char *homedir;
  int i, ret;

  if (!username || !groupname || !config) return -1;

  test_user = GetUserByName(username);
  if (test_user) return 1; /* user exists with same name */

  if (groupname) {
    group = GetGroupByName(groupname);
  }
  if (!group) return 2;

  homedir = group->defaultpath;
  ratio = group->ratio;

  /* check if homedir exist */
  {
    struct stat s;
    if (stat(homedir,&s) || !S_ISDIR(s.st_mode)) {
      return 3;
    }
  }

  /* create new user */
  strncpy(user.username, username, sizeof(user.username));
  strncpy(user.userpass, pass, sizeof(user.userpass));
  strncpy(user.rootpath,homedir,WZD_MAX_PATH);
  user.tagline[0]='\0';
  user.uid=0;
  user.group_num=0;
  if (groupname) {
    user.groups[0] = GetGroupIDByName(groupname);
    if (user.groups[0]) user.group_num=1;
  }
  user.max_idle_time=0;
  user.userperms=0xffffffff;
  user.flags[0]='\0';
  user.max_ul_speed=0;
  user.max_dl_speed=0;
  user.num_logins=0;
  for (i=0; i<HARD_IP_PER_USER; i++)
    user.ip_allowed[i][0]='\0';
  user.stats.bytes_ul_total=0;
  user.stats.bytes_dl_total=0;
  user.stats.files_ul_total=0;
  user.stats.files_dl_total=0;
  user.credits = 0;
  user.ratio = ratio;
  user.user_slots=0;
  user.leech_slots=0;

  /* add it to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_user("plaintext",username,&user,_USER_ALL);

  return ret;
}

int vars_group_get(const char *groupname, const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  wzd_group_t * group;

  if (!groupname || !varname) return 1;

  group = GetGroupByName(groupname);
  if (!group) return 1;

  if (strcasecmp(varname,"home")==0) {
    snprintf(data,datalength,"%s",group->defaultpath);
    return 0;
  }
  if (strcasecmp(varname,"maxdl")==0) {
    snprintf(data,datalength,"%ld",group->max_dl_speed);
    return 0;
  }
  if (strcasecmp(varname,"maxul")==0) {
    snprintf(data,datalength,"%ld",group->max_ul_speed);
    return 0;
  }
  if (strcasecmp(varname,"name")==0) {
    snprintf(data,datalength,"%s",group->groupname);
    return 0;
  }
  if (strcasecmp(varname,"tag")==0) {
    if (group->tagline[0] != '\0')
      snprintf(data,datalength,"%s",group->tagline);
    else
      snprintf(data,datalength,"no tagline set");
    return 0;
  }

  return 1;
}

int vars_group_set(const char *groupname, const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  wzd_group_t * group;
  unsigned long mod_type;
  unsigned long ul;
  char *ptr;
  int ret;

  if (!groupname || !varname) return 1;

  group = GetGroupByName(groupname);
  if (!group) return -1;

  /* find modification type */
  mod_type = _GROUP_NOTHING;

  /* groupname */
  if (strcmp(varname,"name")==0) {
    mod_type = _GROUP_GROUPNAME;
    strncpy(group->groupname,data,sizeof(group->groupname));
    /* NOTE: we do not need to iterate through users, group is referenced
     * by id, not by name
     */
  }
  /* tagline */
  else if (strcmp(varname,"tagline")==0) {
    mod_type = _GROUP_TAGLINE;
    strncpy(group->tagline,data,sizeof(group->tagline));
  }
  /* homedir */
  else if (strcmp(varname,"homedir")==0) {
    /* check if homedir exist */
    {
      struct stat s;
      if (stat(data,&s) || !S_ISDIR(s.st_mode)) {
        /* Homedir does not exist */
        return 2;
      }
    }
    mod_type = _GROUP_DEFAULTPATH;
    strncpy(group->defaultpath,data,WZD_MAX_PATH);
  }
  /* max_idle */
  else if (strcmp(varname,"max_idle")==0) {
    ul=strtoul(data,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_IDLE; group->max_idle_time = ul; }
  }
  /* perms */
  else if (strcmp(varname,"perms")==0) {
    ul=strtoul(data,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_GROUPPERMS; group->groupperms = ul; }
  }
  /* max_ul */
  else if (strcmp(varname,"max_ul")==0) {
    ul=strtoul(data,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_MAX_ULS; group->max_ul_speed = ul; }
  }
  /* max_dl */
  else if (strcmp(varname,"max_dl")==0) {
    ul=strtoul(data,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_MAX_DLS; group->max_dl_speed = ul; }
  }
  /* num_logins */
  else if (strcmp(varname,"num_logins")==0) {
    ul=strtoul(data,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_NUMLOGINS; group->num_logins = (unsigned short)ul; }
  }
  /* ratio */
  else if (strcmp(varname,"ratio")==0) {
    ul=strtoul(data,&ptr,0);
    if (!*ptr) {
      mod_type = _GROUP_RATIO; group->ratio = ul;
    }
  }

  /* commit to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_group("plaintext", groupname, group, mod_type);

  return ret;
}
