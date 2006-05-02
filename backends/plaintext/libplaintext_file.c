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
#include "../../visual/gnu_regex_dist/regex.h"
#endif

#include <libwzd-auth/wzd_auth.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_debug.h>

#include "libplaintext_main.h"
#include "libplaintext_file.h"


#define MAX_LINE 1024

static const char *tab_directives[] = {
  "privgroup"
};

static regex_t reg_line;
static regmatch_t regmatch[3];

static char varname[2048];
static char value[2048];



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
static int __user_ip_add(wzd_user_t * user, const char *newip)
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

static int __group_ip_add(wzd_group_t * group, const char *newip)
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

int write_single_user(FILE * file, const wzd_user_t * user)
{
  unsigned int j;
  wzd_group_t * loop_group;
  char buffer[4096], errbuf[1024];

  fprintf(file,"name=%s\n",user->username);
  fprintf(file,"pass=%s\n",user->userpass);
  fprintf(file,"home=%s\n",user->rootpath);
  fprintf(file,"uid=%d\n",user->uid);
  /* write ALL groups */

  if (user->group_num>0) {
    loop_group = plaintext_get_group_from_gid(user->groups[0]);
    if (!loop_group) {
      /* FIXME warn user */
      snprintf(errbuf,sizeof(errbuf),"Invalid MAIN group %u for user %s\n",user->groups[0],user->username);
      ERRLOG(errbuf);
    } else {
      strcpy(buffer,loop_group->groupname);
      for (j=1; j<user->group_num; j++) {
        strcat(buffer,",");
        loop_group = plaintext_get_group_from_gid(user->groups[j]);
        if (!loop_group) {
          /* FIXME warn user */
          snprintf(errbuf,sizeof(errbuf),"Invalid MAIN group %u for user %s\n",user->groups[j],user->username);
          ERRLOG(errbuf);
        } else {
          strcat(buffer,loop_group->groupname);
        }
      }
      fprintf(file,"groups=%s\n",buffer);
    }
  }
  fprintf(file,"rights=0x%lx\n",user->userperms);
  if (strlen(user->tagline)>0)
    fprintf(file,"tagline=%s\n",user->tagline);
  for (j=0; j<HARD_IP_PER_USER; j++)
  {
    if (user->ip_allowed[j][0] != '\0')
      fprintf(file,"ip_allowed=%s\n",user->ip_allowed[j]);
  }
  if (user->max_ul_speed)
    fprintf(file,"max_ul_speed=%u\n",user->max_ul_speed);
  if (user->max_dl_speed)
    fprintf(file,"max_dl_speed=%u\n",user->max_dl_speed);

  fprintf(file,"credits=%" PRIu64 "\n",user->credits);
  fprintf(file,"bytes_ul_total=%" PRIu64 "\n",user->stats.bytes_ul_total);
  fprintf(file,"bytes_dl_total=%" PRIu64 "\n",user->stats.bytes_dl_total);

  if (user->stats.files_ul_total)
    fprintf(file,"files_ul_total=%lu\n",user->stats.files_ul_total);
  if (user->stats.files_dl_total)
    fprintf(file,"files_dl_total=%lu\n",user->stats.files_dl_total);
  if (user->ratio)
    fprintf(file,"ratio=%d\n",user->ratio);
  if (user->num_logins)
    fprintf(file,"num_logins=%d\n",user->num_logins);
  if (user->max_idle_time)
    fprintf(file,"max_idle_time=%u\n",user->max_idle_time);
  if (user->flags && strlen(user->flags)>0)
    fprintf(file,"flags=%s\n",user->flags);
  if (user->user_slots)
    fprintf(file,"user_slots=%hd\n",(unsigned short)user->user_slots);
  if (user->leech_slots)
    fprintf(file,"leech_slots=%hd\n",(unsigned short)user->leech_slots);
  if (user->last_login)
    fprintf(file,"last_login=%ld\n",(unsigned long)user->last_login);
  fprintf(file,"\n");

    return 0;
}

int write_single_group(FILE * file, const wzd_group_t * group)
{
  unsigned int j;

  fprintf(file,"privgroup\t%s\n",group->groupname);
  if (group->max_idle_time)
    fprintf(file,"max_idle_time=%u\n",group->max_idle_time);
  if (group->num_logins)
    fprintf(file,"num_logins=%d\n",group->num_logins);
  if (group->max_ul_speed)
    fprintf(file,"max_ul_speed=%u\n",group->max_ul_speed);
  if (group->max_dl_speed)
    fprintf(file,"max_dl_speed=%u\n",group->max_dl_speed);
  if (strlen(group->tagline)>0)
    fprintf(file,"tagline=%s\n",group->tagline);
  fprintf(file,"gid=%d\n",group->gid);
  for (j=0; j<HARD_IP_PER_GROUP; j++)
  {
    if (group->ip_allowed[j][0] != '\0')
      fprintf(file,"ip_allowed=%s\n",group->ip_allowed[j]);
  }
  if (strlen(group->defaultpath)>0)
    fprintf(file,"default_home=%s\n",group->defaultpath);
  if (group->ratio)
    fprintf(file,"ratio=%d\n",group->ratio);
  fprintf(file,"\n");

  return 0;
}


int write_user_file(void)
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
  char errbuf[1024];
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
      ERRLOG("plaintext: EMPTY node in user list !!!\n");
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
    snprintf(errbuf,sizeof(errbuf),"Could not open file %s !\n",filename);
    ERRLOG(errbuf);
    return -1;
  }
  fileold = fopen(filenameold,"w+");
  if (!fileold) {
    snprintf(errbuf,sizeof(errbuf),"Could not open file %s !\n",filenameold);
    ERRLOG(errbuf);
    return -1;
  }

  /* first copy file to .old */
  {
    while ( (i=fread(buffer,1,4096,file)) > 0 )
    {
      j = fwrite(buffer,1,i,fileold);
      if (!j) {
        snprintf(errbuf,sizeof(errbuf),"ERROR writing to %s\n",filenameold);
        ERRLOG(errbuf);
        return -1;
      }
    }
  }
  fclose(fileold);

  /* from this point we block signals, to avoid being interrupted when
   * file is not fully written.
   */
#ifndef WIN32
  sigemptyset(&mask);
  sigaddset(&mask,SIGINT);
  if (sigprocmask(SIG_BLOCK,&mask,NULL)<0) {
    ERRLOG("Unable to block SIGINT with sigprocmask\n");
  }
#endif

  file = freopen(filename,"w+",file);
  if (!file) {
    ERRLOG("unable to reopen users file (%s:%d)\n");
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
      ERRLOG("EMPTY NODE IN GROUP LIST !\n");
      continue;
    }
    if (loop_group->groupname[0]=='\0') continue;
    if (strcmp(loop_group->groupname,"nogroup")==0) continue;

    if (write_single_group(file,loop_group)) {
      /** \todo XXX print error message */
      continue;
    }
  }

  fprintf(file,"# users definitions\n");
  fprintf(file,"# users MUST begin by line name=<>\n");
  fprintf(file,"[USERS]\n");
  for (elmnt=list_head(&user_list); elmnt; elmnt=list_next(elmnt))
  {
    if (!(loop_user = list_data(elmnt))) {
      ERRLOG("EMPTY NODE IN USER LIST !\n");
      continue;
    }
    if (loop_user->username[0]=='\0') continue;
    if (strcmp(loop_user->username,"nobody")==0) continue;

    if (write_single_user(file,loop_user)) {
      /** \todo XXX print error message */
      continue;
    }
  }

  fprintf(file,"# per hosts rights\n");
  fprintf(file,"[HOSTS]\n");
  fprintf(file,"all = *\n");
  fprintf(file,"\n");

  fclose(file);

  /* unblock signals - if a SIGINT is pending, it should be harmless now */
#ifndef WIN32
  if (sigprocmask(SIG_UNBLOCK,&mask,NULL)<0) {
    ERRLOG("Unable to unblock SIGINT with sigprocmask\n");
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

int read_section_hosts(FILE * file_user, char * line)
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

int read_section_groups(FILE * file_user, char * line)
{
  char c;
  char *token, *ptr;
  char errbuf[1024];
  unsigned int directive;
  int err;
  long num;
  gid_t gid=1; /* default gid counter */
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
        ERRLOG("privgroup should be followed by the group name !\n");
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
        snprintf(errbuf,sizeof(errbuf),"Too many groups: %d\n",group_count);
        ERRLOG(errbuf);
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
        snprintf(errbuf,sizeof(errbuf),"Line '%s' does not respect config line format - ignoring\n",line);
        ERRLOG(errbuf);
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
          snprintf(errbuf,sizeof(errbuf),"Invalid gid %s\n",value);
          ERRLOG(errbuf);
          continue;
        }
        group_new->gid = num;
      }
      else if (strcasecmp(varname,"max_idle_time")==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
          snprintf(errbuf,sizeof(errbuf),"Invalid max_idle_time %s\n",value);
          ERRLOG(errbuf);
          continue;
        }
        group_new->max_idle_time = num;
      } /* max_idle_time */
      else if (strcmp("num_logins",varname)==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
          snprintf(errbuf,sizeof(errbuf),"Invalid num_logins %s\n",value);
          ERRLOG(errbuf);
          continue;
        }
        group_new->num_logins = (unsigned short)num;
      } /* else if (strcmp("num_logins",... */

      else if (strcmp("ip_allowed",varname)==0) {
        __group_ip_add(group_new,value);
      } /* ip_allowed */
      else if (strcmp("default_home",varname)==0) {
        strncpy(group_new->defaultpath,value,WZD_MAX_PATH);
      } /* default_home */
      else if (strcmp("ratio",varname)==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
          snprintf(errbuf,sizeof(errbuf),"Invalid ratio %s\n",value);
          ERRLOG(errbuf);
          continue;
        }
        group_new->ratio = num;
      } /* else if (strcmp("ratio",... */
      else if (strcmp("max_dl_speed",varname)==0) {
        if (!group_count || !group_new) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
          snprintf(errbuf,sizeof(errbuf),"Invalid max_dl_speed %s\n",value);
          ERRLOG(errbuf);
          continue;
        }
        group_new->max_dl_speed = num;
      } /* max_dl_speed */
      else if (strcmp("max_ul_speed",varname)==0) {
        if (!group_count || !group_new) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
          snprintf(errbuf,sizeof(errbuf),"Invalid max_ul_speed %s\n",value);
          ERRLOG(errbuf);
          continue;
        }
        group_new->max_ul_speed = num;
      } /* max_ul_speed */
      else if (strcmp("tagline",varname)==0) {
        strncpy(group_new->tagline,value,MAX_TAGLINE_LENGTH);
      } /* tagline */
      break;
    default:
      ERRLOG("Houston, we have a problem (invalid varname)\n");
      break;
    }
  }
  return 0;
}

int read_section_users(FILE * file_user, char * line)
{
  char c;
  int err;
  long num;
  unsigned long u_num;
  u64_t ul_num;
  char *ptr;
  char errbuf[1024];
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
      snprintf(errbuf,sizeof(errbuf),"Line '%s' does not respect config line format - ignoring\n",line);
      ERRLOG(errbuf);
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
        snprintf(errbuf,sizeof(errbuf),"Too many users defined %d\n",user_count);
        ERRLOG(errbuf);
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
        snprintf(errbuf,sizeof(errbuf),"Invalid uid %s\n",value);
        ERRLOG(errbuf);
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
      gid_t _gid;
      char * group_ptr;

      if (!user_new) continue;
      /* first group */
      ptr = strtok_r(value,",",&group_ptr);
      if (!ptr) continue;
      /* we use exported function: FCN_FIND_GROUP */
      _gid = FCN_FIND_GROUP(ptr,NULL);
      if (_gid != (gid_t)-1) {
        user_new->groups[user_new->group_num++] = _gid; /* ouch */
      }

      while ( (ptr = strtok_r(NULL,",",&group_ptr)) )
      {
        _gid = FCN_FIND_GROUP(ptr,NULL);
        if (_gid != (gid_t)-1) {
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
        snprintf(errbuf,sizeof(errbuf),"Invalid max_ul_speed %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->max_ul_speed = num;
    } /* max_ul_speed */
    else if (strcmp("last_login",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid last_login %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->last_login = num;
    } /* last_login */
    else if (strcmp("max_dl_speed",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid max_dl_speed %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->max_dl_speed = num;
    } /* max_dl_speed */
    else if (strcmp("bytes_ul_total",varname)==0) {
      if (!user_count || !user_new) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid bytes_ul_total %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->stats.bytes_ul_total = ul_num;
    } /* bytes_ul_total */
    else if (strcmp("bytes_dl_total",varname)==0) {
      if (!user_count || !user_new) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid bytes_dl_total %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->stats.bytes_dl_total = ul_num;
    } /* bytes_dl_total */
    else if (strcmp("files_dl_total",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid files_dl_total %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->stats.files_dl_total = u_num;
    } /* files_dl_total */
    else if (strcmp("files_ul_total",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid files_ul_total %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->stats.files_ul_total = u_num;
    } /* files_ul_total */
   else if (strcmp("credits",varname)==0) {
      if (!user_count || !user_new) break;
      ul_num = strtoull(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid credits %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->credits = ul_num;
    } /* credits */

    else if (strcmp("num_logins",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid number %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->num_logins = (unsigned short)num;
    } /* else if (strcmp("num_logins",... */
    else if (strcmp("ratio",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid ratio %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->ratio = num;
    } /* else if (strcmp("ratio",... */
    else if (strcmp("user_slots",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid user_slots %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->user_slots = (unsigned short)u_num;
    } /* else if (strcmp("user_slots",... */
    else if (strcmp("leech_slots",varname)==0) {
      if (!user_count || !user_new) break;
      u_num = strtoul(value, &ptr, 0);
      if (ptr == value || *ptr != '\0') { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid leech_slots %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->leech_slots = (unsigned short)u_num;
    } /* else if (strcmp("user_slots",... */
    else if (strcmp("max_idle_time",varname)==0) {
      if (!user_count || !user_new) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
        snprintf(errbuf,sizeof(errbuf),"Invalid max_idle_time %s\n",value);
        ERRLOG(errbuf);
        continue;
      }
      user_new->max_idle_time = num;
    } /* max_idle_time */
    else if (strcmp("ip_allowed",varname)==0) {
      if (!user_new) continue;
      __user_ip_add(user_new,value);
    } /* ip_allowed */
  }
  return 0;
}

int read_files(const char *filename)
{
  FILE *file_user;
  char * line, * token, *ptr;
  int ret;
  wzd_user_t * user;
  wzd_group_t * group;
  char errbuf[1024];

  if (!filename || strlen(filename)>=256) {
    ERRLOG("You MUST provide a parameter for the users file\n");
    ERRLOG("Add  param = /path/to/users  in [plaintext] section in your config file\n");
    ERRLOG("See Documentation for help\n");
    return -1;
  }
  strncpy(USERS_FILE,filename,256);
  file_user = fopen(USERS_FILE,"r");

  if (file_user == NULL) {
    ERRLOG("********************************************\n");
    ERRLOG("\n");
    ERRLOG("This is backend plaintext speaking:\n");
    ERRLOG("Could not open file"); ERRLOG(USERS_FILE);
    ERRLOG("\ndie die die !\n");
    ERRLOG("\n");
    ERRLOG("********************************************\n");
    return -1;
  }

  line = malloc(MAX_LINE);
  if (!line) {
    ERRLOG("Could not malloc !\n");
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
  user->uid = (uid_t)-1;
  user->userperms = RIGHT_CWD; /* should be enough ! */
  user->group_num = 1;
  user->groups[0] = (gid_t)-1;
  user->max_ul_speed = 1; /* at this rate, even if you can download it will be ... slow ! */
  user->max_dl_speed = 1;
  user_count++;

  group = group_allocate_new();
  list_ins_next(&group_list,NULL,group);
  strcpy(group->groupname,"nogroup");
  group->gid = (gid_t)-1;
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
        snprintf(errbuf,sizeof(errbuf),"Unkown section %s\n",token);
        ERRLOG(errbuf);
        regfree(&reg_line);
        return 1;
      }
      continue;
    } /* line begins by [ */
    else { /* directive without section */
      snprintf(errbuf,sizeof(errbuf),"directive without section in line '%s'\n",line);
      ERRLOG(errbuf);
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

