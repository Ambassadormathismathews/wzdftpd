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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#ifndef _MSC_VER
#include <unistd.h>
#include <sys/param.h>
#ifndef BSD
#include <crypt.h>
#endif /* BSD */
#include <sys/time.h>
#include <regex.h>
#else
#include "../../visual/gnu_regex_dist/regex.h"
#endif

#include "wzd_backend.h"

/*#define	USERS_FILE		"users"*/

#define	MAX_LINE		1024

/* IMPORTANT needed to check version */
MODULE_NAME(plaintext);
MODULE_VERSION(124);

static char USERS_FILE[256]="/etc/wzdFTPd/users";

static wzd_user_t * user_pool;
static unsigned int user_count, user_count_max=0;

static wzd_group_t * group_pool;
static unsigned int group_count, group_count_max=0;

static regex_t reg_line;
static regmatch_t regmatch[3];

static char varname[2048];
static char value[2048];

/* directives */
#define	D_NONE		0
#define D_PRIVGROUP	1

#define	D_NUM		1

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

  /* this loop has no real interest ...
   * it is only used to access each struct once, to provoque SEGFAULT
   * before we start to erase file in case there is a memory corruption.
   * But of course, this should never happens - uh ?
   */
  for (i=0; i<user_count; i++)
  {
    j = user_pool[i].username[0];
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
  for (i=0; i<group_count; i++)
  {
    if (strcmp(group_pool[i].groupname,"nogroup")==0) continue;
    fprintf(file,"privgroup\t%s\n",group_pool[i].groupname);
    if (group_pool[i].max_idle_time)
      fprintf(file,"max_idle_time=%ld\n",group_pool[i].max_idle_time);
    if (group_pool[i].num_logins)
      fprintf(file,"num_logins=%d\n",group_pool[i].num_logins);
    if (strlen(group_pool[i].tagline)>0)
      fprintf(file,"tagline=%s\n",group_pool[i].tagline);
    fprintf(file,"gid=%d\n",group_pool[i].gid);
    for (j=0; j<HARD_IP_PER_GROUP; j++)
    {
      if (group_pool[i].ip_allowed[j][0] != '\0')
        fprintf(file,"ip_allowed=%s\n",group_pool[i].ip_allowed[j]);
    }
    if (strlen(group_pool[i].defaultpath)>0)
      fprintf(file,"default_home=%s\n",group_pool[i].defaultpath);
    if (group_pool[i].ratio)
      fprintf(file,"ratio=%d\n",group_pool[i].ratio);
    fprintf(file,"\n");
  }

  fprintf(file,"# users definitions\n");
  fprintf(file,"# users MUST begin by line name=<>\n");
  fprintf(file,"[USERS]\n");
  for (i=0; i<user_count; i++)
  {
    if (user_pool[i].username[0]=='\0') continue;
    if (strcmp(user_pool[i].username,"nobody")==0) continue;
    fprintf(file,"name=%s\n",user_pool[i].username);
    fprintf(file,"pass=%s\n",user_pool[i].userpass);
    fprintf(file,"home=%s\n",user_pool[i].rootpath);
    fprintf(file,"uid=%d\n",user_pool[i].uid);
    /* write ALL groups */
    /* TODO check buffer overflow */
    if (user_pool[i].group_num>0) {
      strcpy(buffer,group_pool[user_pool[i].groups[0]].groupname);
      for (j=1; j<user_pool[i].group_num; j++) {
        strcat(buffer,",");
        strcat(buffer,group_pool[user_pool[i].groups[j]].groupname);
      }
      fprintf(file,"groups=%s\n",buffer);
    }
    fprintf(file,"rights=0x%lx\n",user_pool[i].userperms);
    if (strlen(user_pool[i].tagline)>0)
      fprintf(file,"tagline=%s\n",user_pool[i].tagline);
    for (j=0; j<HARD_IP_PER_USER; j++)
    {
      if (user_pool[i].ip_allowed[j][0] != '\0')
        fprintf(file,"ip_allowed=%s\n",user_pool[i].ip_allowed[j]);
    }
    if (user_pool[i].max_ul_speed)
      fprintf(file,"max_ul_speed=%ld\n",user_pool[i].max_ul_speed);
    if (user_pool[i].max_dl_speed)
      fprintf(file,"max_dl_speed=%ld\n",user_pool[i].max_dl_speed);
    fprintf(file,"bytes_ul_total=%llu\n",user_pool[i].stats.bytes_ul_total);
    fprintf(file,"bytes_dl_total=%llu\n",user_pool[i].stats.bytes_dl_total);
    if (user_pool[i].stats.files_ul_total)
      fprintf(file,"files_ul_total=%llu\n",user_pool[i].stats.files_ul_total);
    if (user_pool[i].stats.files_dl_total)
      fprintf(file,"files_dl_total=%llu\n",user_pool[i].stats.files_dl_total);
    fprintf(file,"credits=%llu\n",user_pool[i].credits);
    if (user_pool[i].ratio)
      fprintf(file,"ratio=%d\n",user_pool[i].ratio);
    if (user_pool[i].num_logins)
      fprintf(file,"num_logins=%d\n",user_pool[i].num_logins);
    if (user_pool[i].max_idle_time)
      fprintf(file,"max_idle_time=%ld\n",user_pool[i].max_idle_time);
    if (user_pool[i].flags && strlen(user_pool[i].flags)>0)
      fprintf(file,"flags=%s\n",user_pool[i].flags);
    if (user_pool[i].user_slots)
      fprintf(file,"user_slots=%hd\n",(unsigned short)user_pool[i].user_slots);
    if (user_pool[i].leech_slots)
      fprintf(file,"leech_slots=%hd\n",(unsigned short)user_pool[i].leech_slots);
    if (user_pool[i].last_login)
      fprintf(file,"last_login=%ld\n",(unsigned long)user_pool[i].last_login);
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
  unsigned long i;

#if 0
fprintf(stderr,"Entering section USERS\n");
#endif
  while ( (c = getc(file_user)) != EOF ) {
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
/*
        if ( (++user_count % 256)==0 ) {
          user_pool = realloc(user_pool,(user_count+256)*sizeof(wzd_user_t));
        }*/
      if (++user_count >= user_count_max) {
	fprintf(stderr,"Too many users defined %d\n",user_count);
        continue;
      }
      user_init_struct(&user_pool[user_count-1]);
      strncpy(user_pool[user_count-1].username,value,HARD_USERNAME_LENGTH-1);
      for (i=0; i<HARD_IP_PER_USER; i++)
        user_pool[user_count-1].ip_allowed[i][0] = '\0';
      user_pool[user_count-1].flags[0] = '\0';
    }
    else if (strcmp("home",varname)==0) {
      if (!user_count) break;
      /* remove trailing / */
      if (value[strlen(value)-1] == '/' && strcmp(value,"/")!=0)
	value[strlen(value)-1] = '\0';
	  DIRNORM(value,strlen(value));
      strncpy(user_pool[user_count-1].rootpath,value,WZD_MAX_PATH);
    }
    else if (strcmp("pass",varname)==0) {
      if (!user_count) break;
      strncpy(user_pool[user_count-1].userpass,value,MAX_PASS_LENGTH-1);
    }
    else if (strcmp("flags",varname)==0) {
      if (!user_count) break;
      num = strlen(value);
      if (num <= 0 || num >= MAX_FLAGS_NUM) { /* suspicious length ! */
        continue;
      }
      strncpy(user_pool[user_count-1].flags,value,MAX_FLAGS_NUM);
    } /* flags */
    else if (strcmp("uid",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid uid %s\n",value);
	continue;
      }
      user_pool[user_count-1].uid = num;
    }
    else if (strcmp("rights",varname)==0) {
      if (!user_count) break;
      num = strtoul(value, &ptr, 0);
      /* FIXME by default all users have CWD right FIXME */
      user_pool[user_count-1].userperms = num | RIGHT_CWD;
    }
    else if (strcmp("groups",varname)==0) {
      /* first group */
      ptr = strtok(value,",");
      if (!ptr) continue;
      i = 0;
      while (i < group_count) {
	if (strcmp(value,group_pool[i].groupname)==0) {
	  user_pool[user_count-1].groups[user_pool[user_count-1].group_num++] = i; /* ouch */
	  break;
	}
	i++;
      }
    } /* "groups" */
    else if (strcmp("tagline",varname)==0) {
      strncpy(user_pool[user_count-1].tagline,value,256);
    } /* tagline */
    else if (strcmp("max_ul_speed",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_ul_speed %s\n",value);
        continue;
      }
      user_pool[user_count-1].max_ul_speed = num;
    } /* max_ul_speed */
    else if (strcmp("last_login",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid last_login %s\n",value);
        continue;
      }
      user_pool[user_count-1].last_login = num;
    } /* last_login */
    else if (strcmp("max_dl_speed",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_dl_speed %s\n",value);
        continue;
      }
      user_pool[user_count-1].max_dl_speed = num;
    } /* max_dl_speed */
    else if (strcmp("bytes_ul_total",varname)==0) {
      if (!user_count) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid bytes_ul_total %s\n",value);
        continue;
      }
      user_pool[user_count-1].stats.bytes_ul_total = ul_num;
    } /* bytes_ul_total */
    else if (strcmp("bytes_dl_total",varname)==0) {
      if (!user_count) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid bytes_dl_total %s\n",value);
        continue;
      }
      user_pool[user_count-1].stats.bytes_dl_total = ul_num;
    } /* bytes_dl_total */
    else if (strcmp("files_dl_total",varname)==0) {
      if (!user_count) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid files_dl_total %s\n",value);
        continue;
      }
      user_pool[user_count-1].stats.files_dl_total = u_num;
    } /* files_dl_total */
    else if (strcmp("files_ul_total",varname)==0) {
      if (!user_count) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid files_ul_total %s\n",value);
        continue;
      }
      user_pool[user_count-1].stats.files_ul_total = u_num;
    } /* files_ul_total */
   else if (strcmp("credits",varname)==0) {
      if (!user_count) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid credits %s\n",value);
        continue;
      }
      user_pool[user_count-1].credits = ul_num;
    } /* credits */

    else if (strcmp("num_logins",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid num_logins %s\n",value);
        continue;
      }
      user_pool[user_count-1].num_logins = (unsigned short)num;
    } /* else if (strcmp("num_logins",... */
    else if (strcmp("ratio",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid ratio %s\n",value);
        continue;
      }
      user_pool[user_count-1].ratio = num;
    } /* else if (strcmp("ratio",... */
    else if (strcmp("user_slots",varname)==0) {
      if (!user_count) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid user_slots %s\n",value);
	continue;
      }
      user_pool[user_count-1].user_slots = (unsigned short)u_num;
    } /* else if (strcmp("user_slots",... */
    else if (strcmp("leech_slots",varname)==0) {
      if (!user_count) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
fprintf(stderr,"Invalid leech_slots %s\n",value);
	continue;
      }
      user_pool[user_count-1].leech_slots = (unsigned short)u_num;
    } /* else if (strcmp("user_slots",... */
    else if (strcmp("max_idle_time",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_idle_time %s\n",value);
        continue;
      }
      user_pool[user_count-1].max_idle_time = num;
    } /* max_idle_time */
    else if (strcmp("ip_allowed",varname)==0) {
      user_ip_add(&user_pool[user_count-1],value);
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
  int i;
  unsigned int gid=1; /* default gid counter */

#if 0
fprintf(stderr,"Entering section GROUPS\n");
#endif
  while ( (c = getc(file_user)) != EOF ) {
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
      token = strtok(NULL,"\n");
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
      strncpy(group_pool[group_count-1].groupname,token,128);
      group_pool[group_count-1].gid = gid++;
      group_pool[group_count-1].groupperms = 0;
      group_pool[group_count-1].max_ul_speed = 0;
      group_pool[group_count-1].max_dl_speed = 0;
      group_pool[group_count-1].ratio = 0;
      group_pool[group_count-1].max_idle_time = 0;
      group_pool[group_count-1].num_logins = 0;
      group_pool[group_count-1].defaultpath[0] = 0;
      group_pool[group_count-1].tagline[0] = '\0';
      for (i=0; i<HARD_IP_PER_GROUP; i++)
        group_pool[group_count-1].ip_allowed[i][0] = '\0';
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

      if (strcmp("gid",varname)==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid gid %s\n",value);
          continue;
        }
        group_pool[group_count-1].gid = num;
      }
      else if (strcasecmp(varname,"max_idle_time")==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_idle_time %s\n",value);
          continue;
        }
        group_pool[group_count-1].max_idle_time = num;
      } /* max_idle_time */
      else if (strcmp("num_logins",varname)==0) {
	if (!group_count) break;
	num = strtol(value, &ptr, 0);
	if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid num_logins %s\n",value);
	  continue;
	}
	group_pool[group_count-1].num_logins = (unsigned short)num;
      } /* else if (strcmp("num_logins",... */

      else if (strcmp("ip_allowed",varname)==0) {
        group_ip_add(&group_pool[group_count-1],value);
      } /* ip_allowed */
      else if (strcmp("default_home",varname)==0) {
	strncpy(group_pool[group_count-1].defaultpath,value,WZD_MAX_PATH);
      } /* default_home */
      else if (strcmp("ratio",varname)==0) {
	if (!group_count) break;
	num = strtol(value, &ptr, 0);
	if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
	  fprintf(stderr,"Invalid ratio %s\n",value);
	  continue;
	}
	group_pool[group_count-1].ratio = num;
      } /* else if (strcmp("ratio",... */
      else if (strcmp("tagline",varname)==0) {
        strncpy(group_pool[group_count-1].tagline,value,256);
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
  while ( (c = getc(file_user)) != EOF ) {
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
  int i;

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
  user_init_struct(&user_pool[0]);
  strcpy(user_pool[0].username,"nobody");
  strcpy(user_pool[0].userpass,"------");
  strcpy(user_pool[0].rootpath,"/no/home");
  strcpy(user_pool[0].tagline,"nobody");
  user_pool[0].uid = 65535;
  user_pool[0].userperms = RIGHT_CWD; /* should be enough ! */
  user_pool[0].group_num = 1;
  user_pool[0].groups[0] = 0; /* 0 == nogroup ! */
  user_pool[0].max_ul_speed = 1; /* at this rate, even if you can download it will be ... slow ! */
  user_pool[0].max_dl_speed = 1;
  user_count++;

  strcpy(group_pool[0].groupname,"nogroup");
  group_pool[0].groupperms = 0; /* should be enough ! */
  group_pool[0].max_ul_speed = 0;
  group_pool[0].max_dl_speed = 0;
  group_pool[0].max_idle_time = 0;
  for (i=0; i<HARD_IP_PER_USER; i++)
    group_pool[0].ip_allowed[i][0] = '\0';
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


int FCN_INIT(int *backend_storage, wzd_user_t * user_list, unsigned int user_max, wzd_group_t * group_list, unsigned int group_max, void *arg)
{
  int ret;

  /* storage is done in the main prog's memory */
  *backend_storage = 0;

  user_count_max = user_max;
  group_count_max = group_max;

  user_pool = user_list;
  group_pool = group_list;

  memset(user_pool,0,user_count_max*sizeof(wzd_user_t));
  memset(group_pool,0,group_count_max*sizeof(wzd_group_t));

  ret = read_files( (const char *)arg);

  /* TODO check user definitions (no missing fields, etc) */

  return ret;
}

int FCN_FINI(void)
{
/*  fprintf(stderr,"Backend plaintext unloading\n");*/
  return 0;
}

int wzd_set_user_pool(wzd_user_t * user_list)
{
  user_pool = user_list;
  return 0;
}

int wzd_set_group_pool(wzd_group_t * group_list)
{
  group_pool = group_list;
  return 0;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  unsigned int count;
  int found;
/*  int i;*/

  count=0;
  found = 0;
/*
  while (count<user_count) {
    if (strcmp(login,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }
*/
  while (count<user_count_max) {
    if (strcmp(login,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }

  if (!found) return -1;
  return count;

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
  unsigned int count;
  int found;
  char * cipher;

  count=0;
  found = 0;
  while (count<user_count_max) {
    if (strcmp(login,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }

  if (!found) {
fprintf(stderr,"User %s not found\n",login);
    return -1;
  }
/*fprintf(stderr,"found user at index: %d\n",count);*/

  /* special case: if user_pool[count].userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(user_pool[count].userpass,"%")==0) {
  }
  /* TODO choose encryption func ? */
  else {
    /* FIXME - crypt is NOT reentrant */
    /* XXX - md5 hash in crypt function does NOT work with cygwin */
    cipher = crypt(pass,user_pool[count].userpass);
    found = strcasecmp(cipher,user_pool[count].userpass);
/*fprintf(stderr,"%s %s == %s : %d\n",login,cipher,user_pool[count].userpass,found);*/
    if (found) {
/*fprintf(stderr,"Passwords do no match for user %s (received: %s)\n",user_pool[count].username,pass);*/
      return -1; /* passwords do not match */
    }
  }

  return count;

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
  unsigned int count;
  int found;
/*  int i;*/

  count=0;
  found = 0;
  while (count<user_count_max) {
    if (strcmp(name,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }

  if (!found) return -1;
  else return count;

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

int FCN_FIND_GROUP(int num, wzd_group_t * group)
{
  if (num < 0 || (unsigned int)num >= group_count) return -1;

  return num;
/*
  strncpy(group->groupname,group_pool[num].groupname,256);
  group->groupperms = group_pool[num].groupperms;
  group->max_ul_speed = group_pool[num].max_ul_speed;
  group->max_dl_speed = group_pool[num].max_dl_speed;
  group->max_idle_time = group_pool[num].max_idle_time;
*/
  memcpy(group,&group_pool[num],sizeof(wzd_group_t));

  return 0;
} 

int FCN_CHPASS(const char *username, const char *new_pass)
{
  unsigned int count;
  int found;
  char * cipher;

  count=0;
  found = 0;
  while (count<user_count_max) {
    if (strcmp(username,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }
  
  if (!found) {
fprintf(stderr,"User %s not found\n",username);
    return 1;
  }

  /* special case: if user_pool[count].userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(new_pass,"%")==0) {
    strcpy(user_pool[count].userpass,new_pass);
  }
  /* TODO choose encryption func ? */
  else {
    /* FIXME - crypt is NOT reentrant */
    /* XXX - md5 hash in crypt function does NOT work with cygwin */
    cipher = crypt(new_pass,username);
    strcpy(user_pool[count].userpass,cipher);
  }
  return 0;
}

/* if user does not exist, add it */
int FCN_MOD_USER(const char *name, wzd_user_t * user, unsigned long mod_type)
{
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
	strcpy(user_pool[count].userpass,user->userpass);
      } else {
	salt[0] = 'a' + (char)(rand()%26);
	salt[1] = 'a' + (char)((rand()*72+3)%26);
	cipher = crypt(user->userpass, salt);
	strncpy(user_pool[count].userpass,cipher,MAX_PASS_LENGTH-1);
      }
    }
    if (mod_type & _USER_ROOTPATH) strcpy(user_pool[count].rootpath,user->rootpath);
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
/*    fprintf(stderr,"Add user %s\n",name);*/
    memcpy(&user_pool[user_count],user,sizeof(wzd_user_t));
    if (strcasecmp(user->userpass,"%")!=0) {
      salt[0] = 'a' + (char)(rand()%26);
      salt[1] = 'a' + (char)((rand()*72+3)%26);
      cipher = crypt(user->userpass, salt);
      strncpy(user_pool[user_count].userpass,cipher,MAX_PASS_LENGTH-1);
    }
    /* find a free uid */
    {
      unsigned int uid = 0;
      unsigned int uid_is_free = 0;
      unsigned int i;

      while (!uid_is_free) {
        for (i=0; i<user_count; i++)
        {
          if (user_pool[user_count].uid == uid) { uid_is_free=1; break; }
        }
        uid ++;
        if (uid == (unsigned int)-1) return 1; /* we have too many users ! */
      }
      user_pool[user_count].uid = uid;
    }
    
    user_count++;
  } /* if (found) */

  return 0;
}

int FCN_MOD_GROUP(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  unsigned int count;
  int found;
  
  count=0;
  found = 0;
  while (count<group_count_max) {
    if (strcmp(name,group_pool[count].groupname)==0)
      { found = 1; break; }
    count++;
  }

  if (found) { /* user exist */
/*    fprintf(stderr,"User %s exist\n",name);*/
    if (!group) { /* delete group permanently */
      /* FIXME
       * 1- it is not very stable
       * 2- we do not decrement group_count ...
       * 3- we can't shift all groups, because contexts have id, and
       *   in middle of functions it will cause unstability
       */
      memset(&group_pool[count],0,sizeof(wzd_group_t));
      return 0;
    }
    /* basic verification: trying to commit on self ? then ok */
    if (&group_pool[count] == group) {
      return 0;
    }
    if (mod_type & _GROUP_GROUPNAME) strcpy(group_pool[count].groupname,group->groupname);
    if (mod_type & _GROUP_GROUPPERMS) group_pool[count].groupperms = group->groupperms;
    if (mod_type & _GROUP_IDLE) group_pool[count].max_idle_time = group->max_idle_time;
    if (mod_type & _GROUP_MAX_ULS) group_pool[count].max_ul_speed = group->max_ul_speed;
    if (mod_type & _GROUP_MAX_DLS) group_pool[count].max_dl_speed = group->max_dl_speed;
    if (mod_type & _GROUP_RATIO) group_pool[count].ratio = group->ratio;
    if (mod_type & _GROUP_TAGLINE) strcpy(group_pool[count].tagline,group->tagline);
    if (mod_type & _GROUP_DEFAULTPATH) strcpy(group_pool[count].defaultpath,group->defaultpath);
    if (mod_type & _GROUP_NUMLOGINS) group_pool[count].num_logins = group->num_logins;
    if (mod_type & _GROUP_IP) {
      int i;
      for ( i=0; i<HARD_IP_PER_GROUP; i++ )
	strcpy(group_pool[count].ip_allowed[i],group->ip_allowed[i]);
    }
  } else { /* group not found, add it */
    fprintf(stderr,"Add group %s\n",name);
    memcpy(&group_pool[group_count],group,sizeof(wzd_group_t));
    group_count++;
  } /* if (found) */

  return 0;
}

int  FCN_COMMIT_CHANGES(void)
{
  return write_user_file();
}
