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
#include "wzd_misc.h"
#include "wzd_debug.h"

/*#define	USERS_FILE		"users"*/

#define	MAX_LINE		1024

/* IMPORTANT needed to check version */
BACKEND_NAME(plaintext);
BACKEND_VERSION(131);

#define	HARD_DEF_USER_MAX	640
#define	HARD_DEF_GROUP_MAX	640

static char USERS_FILE[256]="/etc/wzdftpd/users";

static List user_list;
static unsigned int user_count, user_count_max=0;

static List group_list;
static unsigned int group_count, group_count_max=0;

static regex_t reg_line;
static regmatch_t regmatch[3];

static char varname[2048];
static char value[2048];

/* directives */
#define	D_NONE		0
#define D_PRIVGROUP	1

#define	D_NUM		1




int FCN_FIND_GROUP(const char *name, wzd_group_t * group);

static wzd_user_t * user_allocate_new(void);
static wzd_group_t * group_allocate_new(void);



static const char *tab_directives[] = {
  "privgroup"
};

static unsigned int find_directive(const char *name)
{
  int i=0;

  while (i<D_NUM) {
    if (strncasecmp(tab_directives[i],name,strlen(tab_directives[i]))==0) return i+1;
    i++;
  }
  return D_NONE;
}

static unsigned int find_free_uid(unsigned int start)
{
  unsigned int uid = start;
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
    if (uid == (unsigned int)-1) return (unsigned int)-1; /* we have too many users ! */
  }

  /* we should never be here */
  return (unsigned int)-1;
}

static unsigned int find_free_gid(unsigned int start)
{
  unsigned int gid = start;
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
    if (gid == (unsigned int)-1) return (unsigned int)-1; /* we have too many groups ! */
  }

  /* we should never be here */
  return (unsigned int)-1;
}


/* IP allowing */
static int user_ip_add(wzd_user_t * user, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (user == NULL || newip==NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  /* tail insertion, be aware that order is important */
  for (i=0; i<HARD_IP_PER_USER; i++) {
    if (user->ip_allowed[i][0] == '\0') {
      strncpy(user->ip_allowed[i],newip,MAX_IP_LENGTH-1);
      return 0;
    }
  }
  return 1; /* full */
}

static int group_ip_add(wzd_group_t * group, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (group == NULL || newip==NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  /* tail insertion, be aware that order is important */
  for (i=0; i<HARD_IP_PER_GROUP; i++) {
    if (group->ip_allowed[i][0] == '\0') {
      strncpy(group->ip_allowed[i],newip,MAX_IP_LENGTH-1);
      return 0;
    }
  }
  return 1; /* full */
}

static wzd_user_t * _get_user_from_uid(unsigned int uid)
{
  ListElmt * elmnt;
  wzd_user_t * user;

  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
    user = list_data(elmnt);
    if (user && user->uid == uid) return user;
  }
  return NULL;
}

static wzd_group_t * _get_group_from_gid(unsigned int gid)
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
  register int i;

  memset(user->username,0,HARD_USERNAME_LENGTH);
  user->userpass[0]='\0';
  user->rootpath[0]='\0';
  user->tagline[0]='\0';
  user->uid = -1;
  memset(user->groups,0,MAX_GROUPS_PER_USER*sizeof(unsigned int));
  memset(user->tagline,0,256);
  user->max_idle_time = 0;
  user->userperms = 0;
  user->group_num = 0;
  user->flags[0] = '\0';
  user->max_ul_speed = 0;
  user->max_dl_speed = 0;
  user->num_logins = 0;
  for (i=0; i<HARD_IP_PER_USER; i++)
    user->ip_allowed[i][0] = '\0';
  user->stats.bytes_ul_total = 0;
  user->stats.bytes_dl_total = 0;
  user->stats.files_ul_total = 0;
  user->stats.files_dl_total = 0;
  user->credits = 0;
  user->ratio = 0;
  user->user_slots = 0;
  user->leech_slots = 0;
  user->last_login = 0;
}

static wzd_user_t * user_allocate_new(void)
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
}

static wzd_group_t * group_allocate_new(void)
{
  wzd_group_t * group;

  group = wzd_malloc(sizeof(wzd_group_t));
  if (!group) return NULL;
  group_init_struct(group);

  return group;  
}

static int write_user_file(void)
{
#ifndef _MSC_VER
  sigset_t mask;
#endif
  char filename[256];
  char filenamenew[256];
  char filenameold[256];
  FILE *file, *fileold;
  unsigned int i,j;
  char buffer[4096];
  const char * const file_header[] = {
    "# general considerations:",
    "#",
    "# comment lines begin by #",
    "# empty lines are removed",
    "#",
    "# directives have format: <tagname>=<value>",
    "# with the regexp: ^([a-zA-Z0-9_]+)[ \\t]*=[ \\t]*(.+)",
    "#",
    "# directives are grouped into sections",
    "# section begins by [SECTIONNAME]",
    NULL /* you MUST keep this array NULL-ended ! */
  };
  ListElmt * elmnt;
  wzd_user_t * loop_user;
  wzd_group_t * loop_group;

  /* this loop has no real interest ...
   * it is only used to access each struct once, to provoque SEGFAULT
   * before we start to erase file in case there is a memory corruption.
   * But of course, this should never happens - uh ?
   */
  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt))
  {
    loop_user = list_data(elmnt);
    if (!loop_user) {
      fprintf(stderr,"plaintext: EMPTY node in user list !!!\n");
    }
    j = loop_user->username[0];
  }

  strcpy (filename,USERS_FILE);
  strcpy (filenamenew,USERS_FILE);
  strcat (filenamenew,".NEW");
  strcpy (filenameold,USERS_FILE);
  strcat (filenameold,".OLD");

/*  file = fopen(filenamenew,"w");*/

  /* FIXME i need to get a mutex here ? */
  file = fopen(filename,"r");
  if (!file) {
    fprintf(stderr,"Could not open file %s !\n",filename);
    return -1;
  }
  fileold = fopen(filenameold,"w+");
  if (!fileold) {
    fprintf(stderr,"Could not open file %s !\n",filenameold);
    return -1;
  }

  /* first copy file to .old */
  {
    while ( (i=fread(buffer,1,4096,file)) > 0 )
    {
      j = fwrite(buffer,1,i,fileold);
      if (!j) { fprintf(stderr,"ERROR writing to %s\n",filenameold); return -1; }
    }
  }
  fclose(fileold);

  /* from this point we block signals, to avoid being interrupted when
   * file is not fully written.
   */
#ifndef _MSC_VER
  sigemptyset(&mask);
  sigaddset(&mask,SIGINT);
  if (sigprocmask(SIG_BLOCK,&mask,NULL)<0) {
    fprintf(stderr,"Unable to block SIGINT with sigprocmask\n");
  }
#endif

  file = freopen(filename,"w+",file);
  if (!file) {
    fprintf(stderr,"ERROR: unable to reopen users file (%s:%d)\n",__FILE__,__LINE__);
    return -1;
  }
  fseek(file,SEEK_SET,0);

  i=0;
  while (file_header[i]) {
    fprintf(file,"%s\n",file_header[i]);
    i++;
  }
  fprintf(file,"\n");

  fprintf(file,"# groups definitions\n");
  fprintf(file,"[GROUPS]\n");
  for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt))
  {
    if (!(loop_group = list_data(elmnt))) {
      fprintf(stderr,"plaintext: EMPTY NODE IN GROUP LIST !\n");
      continue;
    }
    if (loop_group->groupname[0]=='\0') continue;
    if (strcmp(loop_group->groupname,"nogroup")==0) continue;
    fprintf(file,"privgroup\t%s\n",loop_group->groupname);
    if (loop_group->max_idle_time)
      fprintf(file,"max_idle_time=%u\n",loop_group->max_idle_time);
    if (loop_group->num_logins)
      fprintf(file,"num_logins=%d\n",loop_group->num_logins);
    if (loop_group->max_ul_speed)
      fprintf(file,"max_ul_speed=%u\n",loop_group->max_ul_speed);
    if (loop_group->max_dl_speed)
      fprintf(file,"max_dl_speed=%u\n",loop_group->max_dl_speed);
    if (strlen(loop_group->tagline)>0)
      fprintf(file,"tagline=%s\n",loop_group->tagline);
    fprintf(file,"gid=%d\n",loop_group->gid);
    for (j=0; j<HARD_IP_PER_GROUP; j++)
    {
      if (loop_group->ip_allowed[j][0] != '\0')
        fprintf(file,"ip_allowed=%s\n",loop_group->ip_allowed[j]);
    }
    if (strlen(loop_group->defaultpath)>0)
      fprintf(file,"default_home=%s\n",loop_group->defaultpath);
    if (loop_group->ratio)
      fprintf(file,"ratio=%d\n",loop_group->ratio);
    fprintf(file,"\n");
  }

  fprintf(file,"# users definitions\n");
  fprintf(file,"# users MUST begin by line name=<>\n");
  fprintf(file,"[USERS]\n");
  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt))
  {
    if (!(loop_user = list_data(elmnt))) {
      fprintf(stderr,"plaintext: EMPTY NODE IN USER LIST !\n");
      continue;
    }
    if (loop_user->username[0]=='\0') continue;
    if (strcmp(loop_user->username,"nobody")==0) continue;
    fprintf(file,"name=%s\n",loop_user->username);
    fprintf(file,"pass=%s\n",loop_user->userpass);
    fprintf(file,"home=%s\n",loop_user->rootpath);
    fprintf(file,"uid=%d\n",loop_user->uid);
    /* write ALL groups */
    /* TODO check buffer overflow */
    if (loop_user->group_num>0) {
      /** FIXME does not work, we must find group by gid */
      loop_group = _get_group_from_gid(loop_user->groups[0]);
      if (!loop_user) {
        /* FIXME warn user */
#ifdef DEBUG
        fprintf(stderr,"Invalid MAIN group %u for user %s\n",loop_user->groups[0],loop_user->username);
#endif
      } else {
        strcpy(buffer,loop_group->groupname);
        for (j=1; j<loop_user->group_num; j++) {
          strcat(buffer,",");
          loop_group = _get_group_from_gid(loop_user->groups[j]);
          if (!loop_group) {
            /* FIXME warn user */
#ifdef DEBUG
        fprintf(stderr,"Invalid group %u for user %s\n",loop_user->groups[j],loop_user->username);
#endif
          } else {
            strcat(buffer,loop_group->groupname);
          }
        }
        fprintf(file,"groups=%s\n",buffer);
      }
    }
    fprintf(file,"rights=0x%lx\n",loop_user->userperms);
    if (strlen(loop_user->tagline)>0)
      fprintf(file,"tagline=%s\n",loop_user->tagline);
    for (j=0; j<HARD_IP_PER_USER; j++)
    {
      if (loop_user->ip_allowed[j][0] != '\0')
        fprintf(file,"ip_allowed=%s\n",loop_user->ip_allowed[j]);
    }
    if (loop_user->max_ul_speed)
      fprintf(file,"max_ul_speed=%u\n",loop_user->max_ul_speed);
    if (loop_user->max_dl_speed)
      fprintf(file,"max_dl_speed=%u\n",loop_user->max_dl_speed);
#ifndef WIN32
    fprintf(file,"credits=%llu\n",loop_user->credits);
    fprintf(file,"bytes_ul_total=%llu\n",loop_user->stats.bytes_ul_total);
    fprintf(file,"bytes_dl_total=%llu\n",loop_user->stats.bytes_dl_total);
#else
    fprintf(file,"credits=%I64u\n",loop_user->credits);
    fprintf(file,"bytes_ul_total=%I64u\n",loop_user->stats.bytes_ul_total);
    fprintf(file,"bytes_dl_total=%I64u\n",loop_user->stats.bytes_dl_total);
#endif
    if (loop_user->stats.files_ul_total)
      fprintf(file,"files_ul_total=%lu\n",loop_user->stats.files_ul_total);
    if (loop_user->stats.files_dl_total)
      fprintf(file,"files_dl_total=%lu\n",loop_user->stats.files_dl_total);
    if (loop_user->ratio)
      fprintf(file,"ratio=%d\n",loop_user->ratio);
    if (loop_user->num_logins)
      fprintf(file,"num_logins=%d\n",loop_user->num_logins);
    if (loop_user->max_idle_time)
      fprintf(file,"max_idle_time=%u\n",loop_user->max_idle_time);
    if (loop_user->flags && strlen(loop_user->flags)>0)
      fprintf(file,"flags=%s\n",loop_user->flags);
    if (loop_user->user_slots)
      fprintf(file,"user_slots=%hd\n",(unsigned short)loop_user->user_slots);
    if (loop_user->leech_slots)
      fprintf(file,"leech_slots=%hd\n",(unsigned short)loop_user->leech_slots);
    if (loop_user->last_login)
      fprintf(file,"last_login=%ld\n",(unsigned long)loop_user->last_login);
    fprintf(file,"\n");
  }

  fprintf(file,"# per hosts rights\n");
  fprintf(file,"[HOSTS]\n");
  fprintf(file,"all = *\n");
  fprintf(file,"\n");

  fclose(file);

  /* unblock signals - if a SIGINT is pending, it should be harmless now */
#ifndef _MSC_VER
  if (sigprocmask(SIG_UNBLOCK,&mask,NULL)<0) {
    fprintf(stderr,"Unable to unblock SIGINT with sigprocmask\n");
  }
#endif

  /* FIXME need to release mutex */

#if 0
  /* and now, the (as most as possible) atomic operation for the userfile */
  {
    if (rename(filename,filenameold)) return -1;
    if (rename(filenamenew,filename)) return -1;
  }
#endif

  return 0;
}

static int read_section_users(FILE * file_user, char * line)
{
  char c;
  int err;
  long num;
  unsigned long u_num;
  u64_t ul_num;
  char *ptr;
  wzd_user_t * user_new = NULL;

#if 0
fprintf(stderr,"Entering section USERS\n");
#endif
  while ( (c = getc(file_user)) != (char)EOF ) {
    if (c=='\n') continue;
    if (c=='#') { fgets(line+1,MAX_LINE-2,file_user); continue; } /* comment */
    if (c == '[') { /* another section */
      ungetc(c,file_user);
      return 0;
    }
    line[0] = c; /* we avoid a stupid ungetc */
    fgets(line+1,MAX_LINE-2,file_user);
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */

    if (line[0]=='\0') continue; /* empty line */

    err = regexec(&reg_line,line,3,regmatch,0);
    if (err) {
fprintf(stderr,"Line '%s' does not respect config line format - ignoring\n",line);
      continue;
    }
    memcpy(varname,line+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
    varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
    memcpy(value,line+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
    value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

    if (strcmp("name",varname)==0) {
      /* begin a new user */
      user_new = user_allocate_new();
      list_ins_next(&user_list, list_tail(&user_list), user_new);

      if (++user_count >= user_count_max) {
        fprintf(stderr,"Too many users defined %d\n",user_count);
        continue;
      }
      strncpy(user_new->username,value,HARD_USERNAME_LENGTH-1);
    }
    else if (strcmp("home",varname)==0) {
      if (!user_count || !user_new) break;
      /* remove trailing / */
      if (value[strlen(value)-1] == '/' && strcmp(value,"/")!=0)
        value[strlen(value)-1] = '\0';
      DIRNORM(value,strlen(value),0);
      strncpy(user_new->rootpath,value,WZD_MAX_PATH);
    }
    else if (strcmp("pass",varname)==0) {
      if (!user_count || !user_new) break;
      strncpy(user_new->userpass,value,MAX_PASS_LENGTH-1);
    }
    else if (strcmp("flags",varname)==0) {
      if (!user_count || !user_new) break;
      num = strlen(value);
      if (num <= 0 || num >= MAX_FLAGS_NUM) { /* suspicious length ! */
        continue;
      }
      strncpy(user_new->flags,value,MAX_FLAGS_NUM);
    } /* flags */
    else if (strcmp("uid",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid uid %s\n",value);
        continue;
      }
      user_new->uid = num;
    }
    else if (strcmp("rights",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtoul(value, &ptr, 0);
      /* FIXME by default all users have CWD right FIXME */
      user_new->userperms = num | RIGHT_CWD;
    }
    else if (strcmp("groups",varname)==0) {
      unsigned int _gid;
      char * group_ptr;

      if (!user_new) continue;
      /* first group */
      ptr = strtok_r(value,",",&group_ptr);
      if (!ptr) continue;
      /* we use exported function: FCN_FIND_GROUP */
      _gid = FCN_FIND_GROUP(ptr,NULL);
      if (_gid != -1) {
        user_new->groups[user_new->group_num++] = _gid; /* ouch */
      }

      while ( (ptr = strtok_r(NULL,",",&group_ptr)) )
      {
        _gid = FCN_FIND_GROUP(ptr,NULL);
        if (_gid != -1) {
          user_new->groups[user_new->group_num++] = _gid; /* ouch */
        }
      }
    } /* "groups" */
    else if (strcmp("tagline",varname)==0) {
      if (!user_new) continue;
      strncpy(user_new->tagline,value,MAX_TAGLINE_LENGTH);
    } /* tagline */
    else if (strcmp("max_ul_speed",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_ul_speed %s\n",value);
        continue;
      }
      user_new->max_ul_speed = num;
    } /* max_ul_speed */
    else if (strcmp("last_login",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid last_login %s\n",value);
        continue;
      }
      user_new->last_login = num;
    } /* last_login */
    else if (strcmp("max_dl_speed",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_dl_speed %s\n",value);
        continue;
      }
      user_new->max_dl_speed = num;
    } /* max_dl_speed */
    else if (strcmp("bytes_ul_total",varname)==0) {
      if (!user_count || !user_new) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid bytes_ul_total %s\n",value);
        continue;
      }
      user_new->stats.bytes_ul_total = ul_num;
    } /* bytes_ul_total */
    else if (strcmp("bytes_dl_total",varname)==0) {
      if (!user_count || !user_new) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid bytes_dl_total %s\n",value);
        continue;
      }
      user_new->stats.bytes_dl_total = ul_num;
    } /* bytes_dl_total */
    else if (strcmp("files_dl_total",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid files_dl_total %s\n",value);
        continue;
      }
      user_new->stats.files_dl_total = u_num;
    } /* files_dl_total */
    else if (strcmp("files_ul_total",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid files_ul_total %s\n",value);
        continue;
      }
      user_new->stats.files_ul_total = u_num;
    } /* files_ul_total */
   else if (strcmp("credits",varname)==0) {
      if (!user_count || !user_new) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid credits %s\n",value);
        continue;
      }
      user_new->credits = ul_num;
    } /* credits */

    else if (strcmp("num_logins",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid num_logins %s\n",value);
        continue;
      }
      user_new->num_logins = (unsigned short)num;
    } /* else if (strcmp("num_logins",... */
    else if (strcmp("ratio",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid ratio %s\n",value);
        continue;
      }
      user_new->ratio = num;
    } /* else if (strcmp("ratio",... */
    else if (strcmp("user_slots",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid user_slots %s\n",value);
        continue;
      }
      user_new->user_slots = (unsigned short)u_num;
    } /* else if (strcmp("user_slots",... */
    else if (strcmp("leech_slots",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid leech_slots %s\n",value);
        continue;
      }
      user_new->leech_slots = (unsigned short)u_num;
    } /* else if (strcmp("user_slots",... */
    else if (strcmp("max_idle_time",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_idle_time %s\n",value);
        continue;
      }
      user_new->max_idle_time = num;
    } /* max_idle_time */
    else if (strcmp("ip_allowed",varname)==0) {
      if (!user_new) continue;
      user_ip_add(user_new,value);
    } /* ip_allowed */
  }
  return 0;
}


static int read_section_groups(FILE * file_user, char * line)
{
  char c;
  char *token, *ptr;
  unsigned int directive;
  int err;
  long num;
  unsigned int gid=1; /* default gid counter */
  wzd_group_t * group_new = NULL;

#if 0
fprintf(stderr,"Entering section GROUPS\n");
#endif
  while ( (c = getc(file_user)) != (char)EOF ) {
    if (c=='\n') continue;
    if (c=='#') { fgets(line+1,MAX_LINE-2,file_user); continue; } /* comment */
    if (c == '[') { /* another section */
      ungetc(c,file_user);
      return 0;
    }
    line[0] = c; /* we avoid a stupid ungetc */
    fgets(line+1,MAX_LINE-2,file_user);
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */
    /* read config directive name */
    /* NO NO NO if we use strtok, we will certainly destroy line if a space is present ! */
#if 0
    token = strtok(line," \t");
    if (!token) continue;
#endif
    directive = find_directive(line);
    switch (directive) {
    case D_PRIVGROUP:
      token = strtok(line," \t");
      if (!token) continue;
      token = strtok(NULL," \t\n");
      if (!token) {
        fprintf(stderr,"privgroup should be followed by the group name !\n");
        continue;
      }
#if 0
fprintf(stderr,"Defining new private group %s\n",token);
#endif
/*
      if ((++group_count % 256)==0) {
	group_pool = realloc(group_pool,group_count+256);
      }*/
      if (++group_count >= group_count_max) {
        fprintf(stderr,"Too many groups: %d\n",group_count);
        continue;
      }
      group_new = group_allocate_new();
      list_ins_next(&group_list, list_tail(&group_list), group_new);

      strncpy(group_new->groupname,token,HARD_GROUPNAME_LENGTH-1);
      group_new->gid = gid++; /* default value for gid */

      break;
    case D_NONE:
      err = regexec(&reg_line,line,3,regmatch,0);
      if (err) {
fprintf(stderr,"Line '%s' does not respect config line format - ignoring\n",line);
        continue;
      }
      memcpy(varname,line+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
      varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
      memcpy(value,line+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
      value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

      if (!group_new) break;

      if (strcmp("gid",varname)==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid gid %s\n",value);
          continue;
        }
        group_new->gid = num;
      }
      else if (strcasecmp(varname,"max_idle_time")==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_idle_time %s\n",value);
          continue;
        }
        group_new->max_idle_time = num;
      } /* max_idle_time */
      else if (strcmp("num_logins",varname)==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid num_logins %s\n",value);
          continue;
        }
        group_new->num_logins = (unsigned short)num;
      } /* else if (strcmp("num_logins",... */

      else if (strcmp("ip_allowed",varname)==0) {
        group_ip_add(group_new,value);
      } /* ip_allowed */
      else if (strcmp("default_home",varname)==0) {
        strncpy(group_new->defaultpath,value,WZD_MAX_PATH);
      } /* default_home */
      else if (strcmp("ratio",varname)==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
          fprintf(stderr,"Invalid ratio %s\n",value);
          continue;
        }
        group_new->ratio = num;
      } /* else if (strcmp("ratio",... */
      else if (strcmp("max_dl_speed",varname)==0) {
        if (!group_count || !group_new) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_dl_speed %s\n",value);
          continue;
        }
        group_new->max_dl_speed = num;
      } /* max_dl_speed */
      else if (strcmp("max_ul_speed",varname)==0) {
        if (!group_count || !group_new) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_ul_speed %s\n",value);
          continue;
        }
        group_new->max_ul_speed = num;
      } /* max_ul_speed */
      else if (strcmp("tagline",varname)==0) {
        strncpy(group_new->tagline,value,MAX_TAGLINE_LENGTH);
      } /* tagline */
      break;
    default:
fprintf(stderr,"Houston, we have a problem\n");
      break;
    }
  }
  return 0;
}


static int read_section_hosts(FILE * file_user, char * line)
{
  char c;

#if 0
fprintf(stderr,"Entering section HOSTS\n");
#endif
  while ( (c = getc(file_user)) != (char)EOF ) {
    if (c=='\n') continue;
    if (c=='#') { fgets(line+1,MAX_LINE-2,file_user); continue; } /* comment */
    if (c == '[') { /* another section */
      ungetc(c,file_user);
      return 0;
    }
    line[0] = c; /* we avoid a stupid ungetc */
    fgets(line+1,MAX_LINE-2,file_user);
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */
/*fprintf(stderr,"i read '%s'\n",line);*/
  }
  return 0;
}


static int read_files(const char *filename)
{
  FILE *file_user;
  char * line, * token, *ptr;
  int ret;
  wzd_user_t * user;
  wzd_group_t * group;

  if (!filename || strlen(filename)>=256) return -1;
  strncpy(USERS_FILE,filename,256);
  file_user = fopen(USERS_FILE,"r");

  if (file_user == NULL) {
    fprintf(stderr,"********************************************\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"This is backend plaintext speaking:\n");
    fprintf(stderr,"Could not open file %s\n",USERS_FILE);
    fprintf(stderr,"die die die !\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"********************************************\n");
    return -1;
  }

  line = malloc(MAX_LINE);
  if (!line) {
    fprintf(stderr,"Could not malloc %d bytes (%s:%d)\n",
        MAX_LINE,__FILE__,__LINE__);
    return -1;
  }

  /* prepare regexp */
  reg_line.re_nsub = 2;
  ret = regcomp (&reg_line, "^([a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)", REG_EXTENDED);
  if (ret) return 1; /* regexp could not be compiled */

  /* initial size of user_pool */
  user_count=0;
/*  user_pool = malloc(256*sizeof(wzd_user_t));*/
  group_count=0;
/*  group_pool = malloc(256*sizeof(wzd_group_t));*/

  /* XXX We always add a user nobody and a group nogroup */
  user = user_allocate_new();
  list_ins_next(&user_list,NULL,user);
  strcpy(user->username,"nobody");
  strcpy(user->userpass,"------");
  strcpy(user->rootpath,"/no/home");
  strcpy(user->tagline,"nobody");
  user->uid = 65535;
  user->userperms = RIGHT_CWD; /* should be enough ! */
  user->group_num = 1;
  user->groups[0] = 0; /* 0 == nogroup ! */
  user->max_ul_speed = 1; /* at this rate, even if you can download it will be ... slow ! */
  user->max_dl_speed = 1;
  user_count++;

  group = group_allocate_new();
  list_ins_next(&group_list,NULL,group);
  strcpy(group->groupname,"nogroup");
  group->groupperms = 0; /* should be enough ! */
  group_count++;

  while (1) {
    ptr = fgets(line,MAX_LINE-1,file_user);
    if (!ptr) { fclose(file_user); free(line); regfree(&reg_line); return 0; }
    while ( strlen(line)>0 && (line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n'))
      line[strlen(line)-1] = '\0'; /* clear trailing \n */

    if (line[0] == '\0' || line[0] == '#') { /* ignore empty lines & comments */
      continue;
    }

    if (line[0] == '[') { /* we are beginning a section */
      token = strtok_r(line+1,"]",&ptr);
      if (strcasecmp("USERS",token)==0) ret = read_section_users(file_user,line);
      else if (strcasecmp("GROUPS",token)==0) ret = read_section_groups(file_user,line);
      else if (strcasecmp("HOSTS",token)==0) ret = read_section_hosts(file_user,line);
      else {
fprintf(stderr,"Unkown section %s\n",token);
        regfree(&reg_line);
        return 1;
      }
      continue;
    } /* line begins by [ */
    else { /* directive without section */
fprintf(stderr,"directive without section in line '%s'\n",line);
      regfree(&reg_line);
      return 1;
    }
  }
  while (ptr);

  /* end */
  fclose(file_user);
  free(line);
  regfree(&reg_line);
  return 0;
}


int FCN_INIT(unsigned int user_max, unsigned int group_max, void *arg)
{
  int ret;

  user_count_max = HARD_DEF_USER_MAX; /* XXX FIXME remove me */
  group_count_max = HARD_DEF_GROUP_MAX; /* XXX FIXME remove me */

  list_init(&user_list, wzd_free);
  list_init(&group_list, wzd_free);

  ret = read_files( (const char *)arg);

  /* TODO check user definitions (no missing fields, etc) */

  return ret;
}

int FCN_FINI(void)
{
/*  fprintf(stderr,"Backend plaintext unloading\n");*/
  list_destroy(&user_list);
  list_destroy(&group_list);
  return 0;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
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

  if (!found) return -1;
  return loop_user->uid;

#if 0
  if (!found) {
fprintf(stderr,"User %s not found\n",login);
    return 1;
  }

  memcpy(user,&user_pool[count],sizeof(wzd_user_t));
  /* XXX we erase password (more security ?!) */
  memset(user->userpass,0,MAX_PASS_LENGTH);
  /* FIXME duplicate ip_allow list ? */
  
  return 0;
#endif
}

int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
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
fprintf(stderr,"User %s not found\n",login);
    return -1;
  }

  /* special case: if loop_user->userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(loop_user->userpass,"%")==0) {
  }
  /* authentication is delegated to libwzd-auth */
  else {
    if (check_auth(login, pass, loop_user->userpass)==1)
      return loop_user->uid;
    return -1;
  }

  return loop_user->uid;

#if 0
/*
  strncpy(user->username,user_pool[count].username,255);
  strncpy(user->rootpath,user_pool[count].rootpath,1023);
  user->uid = user_pool[count].uid;
  user->group_num = user_pool[count].group_num;
  for (i=0; i<user->group_num; i++)
  {
    user->groups[i]=user_pool[count].groups[i];
  }
  memcpy(&user->userperms,&user_pool[count].userperms,sizeof(wzd_perm_t));
  user->max_ul_speed = user_pool[count].max_ul_speed;
  user->max_dl_speed = user_pool[count].max_dl_speed;
  user->max_idle_time = user_pool[count].max_idle_time;
  strncpy(user->tagline,user_pool[count].tagline,255);
*/

  memcpy(user,&user_pool[count],sizeof(wzd_user_t));
  /* XXX we erase password (more security ?!) */
  memset(user->userpass,0,MAX_PASS_LENGTH);
  /* FIXME duplicate ip_allow list ? */

  return 0;
#endif
}

int FCN_FIND_USER(const char *name, wzd_user_t * user)
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

  if (!found) return -1;
  else return loop_user->uid;

#if 0
  if (!found) {
fprintf(stderr,"User %s not found\n",name);
    return 1;
  }
/*fprintf(stderr,"found user at index: %d\n",count);*/
/*
  strncpy(user->username,user_pool[count].username,255);
  strncpy(user->rootpath,user_pool[count].rootpath,1023);
  user->uid = user_pool[count].uid;
  user->group_num = user_pool[count].group_num;
  for (i=0; i<user->group_num; i++)
  {
    user->groups[i]=user_pool[count].groups[i];
  }
  memcpy(&user->userperms,&user_pool[count].userperms,sizeof(wzd_perm_t));
  user->max_ul_speed = user_pool[count].max_ul_speed;
  user->max_dl_speed = user_pool[count].max_dl_speed;
  user->max_idle_time = user_pool[count].max_idle_time;
  strncpy(user->tagline,user_pool[count].tagline,255);
*/

  memcpy(user,&user_pool[count],sizeof(wzd_user_t));
  /* XXX we erase password (more security ?!) */
  memset(user->userpass,0,MAX_PASS_LENGTH);

  return 0;
#endif
}

int FCN_FIND_GROUP(const char *name, wzd_group_t * group)
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

  return (found) ? loop_group->gid : -1;
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

int  FCN_COMMIT_CHANGES(void)
{
  return write_user_file();
}

wzd_user_t * FCN_GET_USER(int uid)
{
  int index;
  wzd_user_t * user;
  ListElmt * elmnt;
  wzd_user_t * loop_user;

  if (uid == -2) {
    int * uid_list = NULL;
    int size;

    size = list_size(&user_list);

    uid_list = (int*)wzd_malloc((size+1)*sizeof(int));
    index = 0;
    for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt)) {
      loop_user = list_data(elmnt);
      if (loop_user && loop_user->username[0]!='\0' && loop_user->uid!=-1)
        uid_list[index++] = loop_user->uid;
    }
    uid_list[index] = -1;
    uid_list[size] = -1;

    return (wzd_user_t*)uid_list;
  }

  if (uid < 0) return NULL;

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

wzd_group_t * FCN_GET_GROUP(int gid)
{
  int index;
  wzd_group_t * group;
  ListElmt * elmnt;
  wzd_group_t * loop_group;

  if (gid == -2) {
    int * gid_list = NULL;
    int size;

    size = list_size(&group_list);

    gid_list = (int*)wzd_malloc((size+1)*sizeof(int));
    index = 0;
    for (elmnt=list_head(&group_list); elmnt; elmnt=list_next(elmnt)) {
      loop_group = list_data(elmnt);
      if (loop_group && loop_group->groupname[0]!='\0' && loop_group->gid!=-1)
        gid_list[index++] = loop_group->gid;
    }
    gid_list[index] = -1;
    gid_list[size] = -1;

    return (wzd_group_t*)gid_list;
  }

  if (gid < 0) return NULL;

  loop_group =  _get_group_from_gid(gid);
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
