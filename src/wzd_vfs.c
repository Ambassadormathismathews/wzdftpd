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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/types.h>

#ifdef _MSC_VER
#include <winsock2.h>
#include <direct.h> /* _getcwd */
#else
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"

#include "wzd_vfs.h"
#include "wzd_log.h"
#include "wzd_misc.h"

#include "wzd_debug.h"

/** remove a vfs from list */
int vfs_remove( wzd_vfs_t **vfs_list, const char *vpath )
{
  wzd_vfs_t * current_vfs, * next_vfs;
  wzd_vfs_t * previous_vfs = NULL;
  
  current_vfs = *vfs_list;
  while(current_vfs)
  {
    next_vfs = current_vfs->next_vfs;
    
    if ( (strcmp( current_vfs->virtual_dir, vpath) == 0) )
    {
      if (current_vfs == *vfs_list)
      {
        *vfs_list = next_vfs;
        wzd_free (current_vfs);
      } else {
        wzd_free (current_vfs);
        previous_vfs->next_vfs = next_vfs;
      }
      return 0;
    }
    
    previous_vfs = current_vfs;
    current_vfs = next_vfs;
  }

  return 2;
}

/** free vfs list */
int vfs_free(wzd_vfs_t **vfs_list)
{
  wzd_vfs_t * current_vfs, * next_vfs;

  current_vfs = *vfs_list;

  while (current_vfs) {
    next_vfs = current_vfs->next_vfs;

    wzd_free(current_vfs->virtual_dir);
    wzd_free(current_vfs->physical_dir);
    if (current_vfs->target) wzd_free(current_vfs->target);

#ifdef DEBUG
    current_vfs->virtual_dir = NULL;
    current_vfs->physical_dir = NULL;
    current_vfs->target = NULL;
    current_vfs->next_vfs = NULL;
#endif /* DEBUG */
    wzd_free(current_vfs);

    current_vfs = next_vfs;
  }

  *vfs_list = NULL;
  return 0;
}

/** register a new vfs entry, with a condition */
int vfs_add_restricted(wzd_vfs_t ** vfs_list, const char *vpath, const char *path, const char *target)
{
  wzd_vfs_t * current_vfs, * new_vfs;
  struct stat s;

  current_vfs = *vfs_list;
  while (current_vfs)
  {
    if( (strcmp(vpath, current_vfs->virtual_dir)==0) )
    {
      /* virtual path already set */
      return 2;
  }
    current_vfs = current_vfs->next_vfs;
  }

  if (stat(path,&s)) {
    /* destination does not exist */
    return 1;
  }

  new_vfs = wzd_malloc(sizeof(wzd_vfs_t));
  if (!new_vfs) return 1;

  DIRNORM(vpath,strlen(vpath));
  DIRNORM(path,strlen(path));
  new_vfs->virtual_dir = strdup(vpath);
  new_vfs->physical_dir = strdup(path);
  if (target)
  new_vfs->target = strdup(target);
  else
    new_vfs->target = NULL;
  new_vfs->next_vfs = NULL;
  new_vfs->prev_vfs = NULL;

  current_vfs = *vfs_list;

  if (!current_vfs) {
    *vfs_list = new_vfs;
    return 0;
  }

  while (current_vfs->next_vfs) {
    current_vfs = current_vfs->next_vfs;
  }

  current_vfs->next_vfs = new_vfs;
  new_vfs->prev_vfs = current_vfs;

  return 0;
}

/** register a new vfs entry */
int vfs_add(wzd_vfs_t ** vfs_list, const char *vpath, const char *path)
{
  return vfs_add_restricted (vfs_list,vpath,path,NULL);
}

/** \return 1 if user match corresponding line */
int vfs_match_perm(const char *perms,wzd_user_t *user)
{
  char * buffer, *token, *ptr;
  char c;
  unsigned int i;
  short negate;
  wzd_group_t * group;

  if (!perms) return 1;
  buffer=strdup(perms);
  ptr=buffer;
  token = strtok_r(buffer," \t\r\n",&ptr);
 
  while (token) {
    negate=0;
    /* FIXME split token to find entry type : user, group, flag */
    c = *token++;
    if (c == '!') {
      negate = 1;
      c = *token++;
    }
    switch (c) {
    case '=':
      if (strcasecmp(token,user->username)==0) return (negate) ? 0 : 1;
      break;
    case '-':
      for (i=0; i<user->group_num; i++) {
	group = GetGroupByID(user->groups[i]);
	if (strcasecmp(token,group->groupname)==0) return (negate) ? 0 : 1;
      }
      break;
    case '+':
      if (user->flags && strchr(user->flags,*token)) return (negate) ? 0 : 1;
      break;
    case '*':
      return !negate;
      break;
    default:
      continue;
    }
    if (negate)
      *(--token)='!';

    token = strtok_r(NULL," \t\r\n",&ptr);
  }


  wzd_free(buffer);
  return 0;
}

/** if needed, replace the vfs in the path */
int vfs_replace(wzd_vfs_t *vfs_list, char *buffer, unsigned int maxlen, wzd_context_t * context)
{
  char buffer_vfs[2*WZD_MAX_PATH];
  char * ptr_out;
  wzd_user_t *user;

  user=GetUserByID(context->userid);
  if (!user) return -1;

  /* FIXME test length of strings */
  while (vfs_list)
  {
/*    strcpy(buffer_vfs,vfs_list->virtual_dir);*/
    ptr_out = vfs_replace_cookies(vfs_list->virtual_dir,context);
    if (!ptr_out) {
      out_log(LEVEL_CRITICAL,"vfs_replace_cookies returned NULL for %s\n",vfs_list->virtual_dir);
      vfs_list = vfs_list->next_vfs;
      continue;
    }
    strncpy(buffer_vfs,ptr_out,2*WZD_MAX_PATH); /* FIXME this is slow ! replace by memcpy */
    wzd_free(ptr_out);

    if (DIRNCMP(buffer_vfs,buffer,strlen(buffer_vfs))==0
	&&
	(buffer[strlen(buffer_vfs)] == '/' || /* without this test, vfs will always match before vfs1 */
	strcmp(buffer_vfs,buffer)==0) ) /* without this test, 'cd vfs' will not match */
    {
      char buf[2*WZD_MAX_PATH];
      /* test perm */
      if (vfs_list->target) {
	if (!vfs_match_perm(vfs_list->target,user)) { vfs_list = vfs_list->next_vfs; continue; }
      }
#ifdef WZD_DBG_VFS
out_err(LEVEL_HIGH,"VPATH match : %s / %s\n",buffer,vfs_list->virtual_dir);
#endif
      strcpy(buf,vfs_list->physical_dir);
      strcpy(buf+strlen(vfs_list->physical_dir),buffer+strlen(buffer_vfs));
#ifdef WZD_DBG_VFS
out_err(LEVEL_HIGH,"converted to %s\n",buf);
#endif
      strcpy(buffer,buf);
    }
    vfs_list = vfs_list->next_vfs;
  }
  return 0;
}

/** parse vfs entry and replace cookies by their value
 * \return a newly allocated string with the interpreted path
 * \todo TODO it would REALLY be nice to use the function defined in
 *  wzd_cookie_lex.l ... problem: it automatically prints the result !
 */
char * vfs_replace_cookies(const char * path, wzd_context_t * context)
{
  char buffer[2*WZD_MAX_PATH];
  unsigned int length, needed;
  char * out=NULL;
  const char * ptr_in;
  char * ptr_out;
  wzd_user_t * user;
  wzd_group_t * group;

  user=GetUserByID(context->userid);
  if (!user) return NULL;

  if (user->group_num > 0) {
    group = GetGroupByID(user->groups[0]);
  } else
    group = NULL;

  length = 0;
  ptr_in = path; ptr_out = buffer;
  while ( (*ptr_in) ){
    if (length >= 2*WZD_MAX_PATH) {
      out_log(LEVEL_CRITICAL,"buffer size exceeded in vfs_replace_cookies for virtual_dir %s\n",path);
      return NULL;
    }
    if (*ptr_in == '%') {
      if (strncmp(ptr_in,"%username",9)==0) { /* 9 == strlen(%username) */
        needed = strlen(user->username);
        length += needed;
        if (length >= 2*WZD_MAX_PATH) {
          out_log(LEVEL_CRITICAL,"buffer size exceeded in vfs_replace_cookies for virtual_dir %s\n",path);
          return NULL;
        }
        memcpy(ptr_out,user->username,needed);
        ptr_in += 9; /* 9 == strlen(%username) */
        ptr_out += needed;
      } else if (strncmp(ptr_in,"%usergroup",10)==0) { /* 10 == strlen(%usergroup) */
        if (group) {
          needed = strlen(group->groupname);
          length += needed;
          if (length >= 2*WZD_MAX_PATH) {
            out_log(LEVEL_CRITICAL,"buffer size exceeded in vfs_replace_cookies for virtual_dir %s\n",path);
            return NULL;
          }
          memcpy(ptr_out,group->groupname,needed);
          ptr_in += 10; /* 10 == strlen(%usergroup) */
          ptr_out += needed;
        } else { /* ! group */
          return NULL; /* we want user's main group and he has no one ... */
        }
      } else if (strncmp(ptr_in,"%userhome",9)==0) { /* 9 == strlen(%userhome) */
/* TODO XXX FIXME only print iff homedir exists !! */
#if 0
        if (home) { 
#endif /* 0 */
          needed = strlen(user->rootpath);
          length += needed;
          if (length >= 2*WZD_MAX_PATH) {
            out_log(LEVEL_CRITICAL,"buffer size exceeded in vfs_replace_cookies for virtual_dir %s\n",path);
            return NULL;
          }
          memcpy(ptr_out,user->rootpath,needed);
          ptr_in += 9; /* 9 == strlen(%userhome) */
          ptr_out += needed;
        } else { /* ! home */
          return NULL; /* we want user's main home and he has no one ... */
        }
#if 0
      } else {
        *ptr_out++ = *ptr_in++;
        length++;
      }
#endif /* 0 */
    } else {
      *ptr_out++ = *ptr_in++;
      length++;
    }
  }
  *ptr_out = '\0';

  out = wzd_malloc(length+1);
  strncpy(out,buffer,length+1);

  return out;
}

/*************** checkpath ***************************/

char *stripdir(char * dir, char *buf, int maxlen)
{
  char * in, * out;
  char * last; 
  int ldots;
        
  in   = dir;
  out  = buf;
  last = buf + maxlen;
  ldots = 0; 
  *out  = 0;

#ifndef _MSC_VER
  if (*in != '/')
#else
  if (*in != '/' && *(in+1) != ':')
#endif
  {
    if (getcwd(buf, maxlen - 2) ) {
      out = buf + strlen(buf) - 1;
      if (*out != '/') *(++out) = '/';
      out++;
    }       
    else
      return NULL;
  }               

  while (out < last) {
    *out = *in;

    if (*in == '/')
    {
      while (*(++in) == '/') ;
        in--;
    }

    if (*in == '/' || !*in)
    {
      if (ldots == 1 || ldots == 2) {
        while (ldots > 0 && --out > buf)
        {
          if (*out == '/')
            ldots--;
        }
        *(out+1) = 0;
      }
      ldots = 0;

    } else if (*in == '.') {
      ldots++;
    } else {
      ldots = 0;
    }

    out++;

    if (!*in)
      break;
                        
    in++;
  }       
        
  if (*in) {
    errno = ENOMEM;
    return NULL;
  }       
        
  while (--out != buf && (*out == '/' || !*out)) *out=0;
    return buf;
}       


int checkpath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char allowed[WZD_MAX_PATH];
  char cmd[WZD_MAX_PATH];
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0) {
    sprintf(allowed,"%s/",context->userinfo.rootpath);
    sprintf(cmd,"%s%s",context->userinfo.rootpath,context->currentpath);
  } else
#endif
  {
    sprintf(allowed,"%s/",GetUserByID(context->userid)->rootpath);
    if (strcmp(allowed,"//")==0) allowed[1]='\0';
    sprintf(cmd,"%s%s",GetUserByID(context->userid)->rootpath,context->currentpath);
  }
  if (cmd[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      strcat(cmd,wanted_path);
    } else {
      strcpy(cmd,allowed);
      strcat(cmd,wanted_path+1);
    } 
  } 
/*#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif*/
/*  if (!realpath(cmd,path)) return 1;*/
  if (!stripdir(cmd,path,WZD_MAX_PATH)) return 1;
/*#ifdef DEBUG
printf("Converted to: '%s'\n",path);
#endif*/
  if (path[strlen(path)-1] != '/')
    strcat(path,"/");
  strcpy(cmd,path);
  cmd[strlen(allowed)]='\0';
  if (path[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  /* check if user is allowed to even see the path */
  if (DIRNCMP(cmd,allowed,strlen(allowed))) return 1;
  /* in the case of VFS, we need to convert here to a realpath */
  vfs_replace(mainConfig->vfs,path,WZD_MAX_PATH,context);
  if (strlen(path)>1 && path[strlen(path)-1] == '/') path[strlen(path)-1]='\0';
  return 0;
}

int checkabspath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char allowed[WZD_MAX_PATH];
  char cmd[WZD_MAX_PATH];
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0) {
    sprintf(allowed,"%s/",context->userinfo.rootpath);
    sprintf(cmd,"%s%s",context->userinfo.rootpath,context->currentpath);
  } else
#endif
  {
    sprintf(allowed,"%s/",GetUserByID(context->userid)->rootpath);
    if (strcmp(allowed,"//")==0) allowed[1]='\0';
    sprintf(cmd,"%s%s",GetUserByID(context->userid)->rootpath,context->currentpath);
  }
  if (cmd[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      return -1; /* we need absolute path, but it doesn't begin with / */
    } else {
      strcpy(cmd,wanted_path);
    } 
  } 
/*#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif*/
/*  if (!realpath(cmd,path)) return 1;*/
  if (!stripdir(cmd,path,WZD_MAX_PATH)) return 1;
/*#ifdef DEBUG
printf("Converted to: '%s'\n",path);
#endif*/
  if (path[strlen(path)-1] != '/')
    strcat(path,"/");
  strcpy(cmd,path);
  cmd[strlen(allowed)]='\0';
  if (path[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  /* check if user is allowed to even see the path */
  if (strncmp(cmd,allowed,strlen(allowed))) return 1;
  /* in the case of VFS, we need to convert here to a realpath */
  vfs_replace(mainConfig->vfs,path,WZD_MAX_PATH,context);
  if (strlen(path)>1 && path[strlen(path)-1] == '/') path[strlen(path)-1]='\0';
  return 0;
}

/* FIXME: does not yet support vfs */
int path_abs2rel(const char *abs, char *rel, int rel_len, wzd_context_t *context)
{
  const char *ptr;
  wzd_user_t * user;
  wzd_vfs_t * vfs;
  char buffer[2*WZD_MAX_PATH];

  user = GetUserByID(context->userid);
  if (!user) return E_USER_IDONTEXIST;

  strncpy(buffer,abs,2*WZD_MAX_PATH);

  vfs = mainConfig->vfs;
  if (vfs) {
    while (vfs->next_vfs) vfs = vfs->next_vfs;

    if (buffer,vfs->physical_dir,strlen(vfs->physical_dir) == 0) {
      
    }
  }

  if (strncmp(buffer,user->rootpath,strlen(user->rootpath))) /* VFS */
      return 1;

  ptr = buffer + strlen(user->rootpath);
  strncpy(rel,ptr,rel_len);

  return 0;
}
