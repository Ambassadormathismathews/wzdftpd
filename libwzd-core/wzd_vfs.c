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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#include <direct.h> /* _getcwd */
#else
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifndef HAVE_STRTOK_R
# include "libwzd-base/wzd_strtok_r.h"
#endif

#include "wzd_structs.h"

#include "wzd_vfs.h"
#include "wzd_dir.h"
#include "wzd_file.h"
#include "wzd_fs.h"
#include "wzd_group.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

/** remove a vfs from list */
int vfs_remove( wzd_vfs_t **vfs_list, const char *vpath )
{
  wzd_vfs_t * current_vfs, * next_vfs;
  wzd_vfs_t * previous_vfs = NULL;

  current_vfs = *vfs_list;
  while(current_vfs)
  {
    next_vfs = current_vfs->next_vfs;

    if ( (DIRCMP( current_vfs->virtual_dir, vpath) == 0) )
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
  fs_filestat_t s;

  current_vfs = *vfs_list;
  while (current_vfs)
  {
    if( (DIRCMP(vpath, current_vfs->virtual_dir)==0) )
    {
      /* virtual path already set */
      return 2;
  }
    current_vfs = current_vfs->next_vfs;
  }

  if (fs_file_stat(path,&s)) {
    /* destination does not exist */
    return 1;
  }

  new_vfs = wzd_malloc(sizeof(wzd_vfs_t));
  if (!new_vfs) return 1;

  DIRNORM((char*)vpath,strlen(vpath),0);
  DIRNORM((char*)path,strlen(path),0);
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
      if (strcasecmp(token,user->username)==0) { free(buffer); return (negate) ? 0 : 1; }
      break;
    case '-':
      for (i=0; i<user->group_num; i++) {
        group = GetGroupByID(user->groups[i]);
        if (strcasecmp(token,group->groupname)==0) { free(buffer); return (negate) ? 0 : 1; }
      }
      break;
    case '+':
      if (user->flags && strchr(user->flags,*token)) { free(buffer); return (negate) ? 0 : 1; }
      break;
    case '*':
      free(buffer);
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
         DIRCMP(buffer_vfs,buffer)==0) ) /* without this test, 'cd vfs' will not match */
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
  size_t length, needed;
  char * out=NULL;
  const char * ptr_in;
  char * ptr_out;
  wzd_user_t * user;
  wzd_group_t * group;

  user = GetUserByID(context->userid);

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

char *stripdir(const char * dir, char *buf, int maxlen)
{
  const char * in;
  char * out;
  char * last;
  int ldots;

  in   = dir;
  out  = buf;
  last = buf + maxlen;
  ldots = 0;
  *out  = 0;

#ifndef WIN32
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
        if (!*in) {
          if (out-ldots<=dir || *(out-ldots-1) != '/') /** \bug XXX FIXME pointers out and dir are NOT in the same buffers */
            ldots = 0;
        }
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

/** \brief convert ftp-style path to system path
 * \deprecated use \ref checkpath_new
 */
int checkpath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char *allowed;
  char *cmd;

  allowed = malloc(WZD_MAX_PATH);
  cmd = malloc(WZD_MAX_PATH);

  {
    snprintf(allowed,WZD_MAX_PATH,"%s/",GetUserByID(context->userid)->rootpath);
    if (strcmp(allowed,"//")==0) allowed[1]='\0';
    snprintf(cmd,WZD_MAX_PATH,"%s%s",GetUserByID(context->userid)->rootpath,context->currentpath);
  }
  if (cmd[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      strlcat(cmd,wanted_path,WZD_MAX_PATH);
    } else {
      strcpy(cmd,allowed);
      strlcat(cmd,wanted_path+1,WZD_MAX_PATH);
    }
  }
  DIRNORM(cmd,strlen(cmd),0);
/*#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif*/
/*  if (!realpath(cmd,path)) return 1;*/
  if (!stripdir(cmd,path,WZD_MAX_PATH)) { free(allowed); free(cmd); return 1; }
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
  if (DIRNCMP(cmd,allowed,strlen(allowed))) { free(allowed); free(cmd); return 1; }
  /* in the case of VFS, we need to convert here to a realpath */
  vfs_replace(mainConfig->vfs,path,WZD_MAX_PATH,context);
  if (strlen(path)>1 && path[strlen(path)-1] == '/') path[strlen(path)-1]='\0';
  free(allowed);
  free(cmd);
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

    /** \todo XXX FIXME this code is NOT finished ... */
    if (strncmp(buffer,vfs->physical_dir,strlen(vfs->physical_dir)) == 0) {

    }
  }

  if (strncmp(buffer,user->rootpath,strlen(user->rootpath))) /* VFS */
      return 1;

  ptr = buffer + strlen(user->rootpath);
  strncpy(rel,ptr,rel_len);

  return 0;
}

/** converts wanted_path (in ftp-style) to path (system path), checking
 * for errors and permissions
 *
 * \param wanted_path The path in FTP-form
 * \param path MUST have a minimum size of WZD_MAX_PATH
 * \param context The current context
 *
 * If the return is 0, then we are SURE the result exists.
 * If the real path points to a directory, then the result is / terminated
 */
int checkpath_new(const char *wanted_path, char *path, wzd_context_t *context)
{
  int ret;
  char * ftppath, *syspath, *ptr, *lpart, *rpart;
  char * ptr_ftppath;
  wzd_user_t * user;
  unsigned int sys_offset;
  fs_filestat_t s;
  struct wzd_file_t * perm_list, * entry;

  WZD_ASSERT(context != NULL);
  if (context == NULL) return E_USER_IDONTEXIST;

  if (!wanted_path) return E_PARAM_NULL;

  if (strlen(context->currentpath) == 0) return E_PARAM_INVALID;

  user = GetUserByID(context->userid);

  if (!user) return E_USER_IDONTEXIST;
  if (strlen(user->rootpath) + strlen(wanted_path) >= WZD_MAX_PATH) return E_PARAM_BIG;

  ftppath = malloc(WZD_MAX_PATH+1);
  syspath = malloc(WZD_MAX_PATH+1);

#ifdef WIN32
  if (strchr(user->flags,FLAG_FULLPATH) )  memset(syspath,0,sizeof(syspath));
  else
#endif
  {
    wzd_strncpy(syspath, user->rootpath, WZD_MAX_PATH);
    sys_offset = strlen(syspath);
  }

  /* if wanted_path is relative */
  if (wanted_path[0] != '/') {

    wzd_strncpy(ftppath, context->currentpath, WZD_MAX_PATH);
    ptr_ftppath = ftppath + strlen(ftppath) - 1;
    if (*ptr_ftppath != '/') {
      *++ptr_ftppath = '/';
      *++ptr_ftppath = '\0';
    }
    if (ptr_ftppath == ftppath) ptr_ftppath++; /* ftppath is / */
    strcpy(ptr_ftppath, wanted_path);
    if (strncmp(ftppath,"/../",4)==0) {
      free(syspath); free(ftppath);
      return E_WRONGPATH;
    }

    path_simplify(ftppath);

    ret = checkpath_new(ftppath, syspath, context);
    if (!ret || ret == E_FILE_NOEXIST)
      wzd_strncpy(path, syspath, WZD_MAX_PATH);
    free(syspath); free(ftppath);
    return ret;

    /** \bug the following will never be executed */
    sys_offset = strlen(syspath);
    /* remove trailing / */
    if (syspath[sys_offset-1] == '/' && sys_offset > 2)
      syspath[--sys_offset] = '\0';
  } else { /* wanted_path is absolute */
    wzd_strncpy(ftppath, wanted_path, WZD_MAX_PATH);

    path_simplify(ftppath); /** \todo check that \ref path_simplify works as expected */
  }

  /* here we assume syspath contains the user's homedir
   * syspath is not / terminated (for now)
   */
  ptr_ftppath = ftppath;
  if (*ptr_ftppath == '/')
    ptr_ftppath++;

#ifdef WIN32
  if (strchr(user->flags,FLAG_FULLPATH) ) sys_offset=0;
  else
#endif
  {
    if (syspath[sys_offset-1] != '/')
      memcpy(&syspath[sys_offset++],"/\0",2); /*use either strcat or memcpy with terminating 0 or corruption can occur*/
  }

  while (ptr_ftppath[0] != '\0')
  {
    /* start from the top-level dir */
    lpart = ptr_ftppath;
    ptr = strchr(lpart,'/');
    if (!ptr) {
      ptr = lpart + strlen(lpart); /* position of \0 */
    }

    if (!ptr || ptr <= lpart)
    {
      /* we have finished ? */

      wzd_strncpy(path, syspath, WZD_MAX_PATH);
      free(ftppath);
      free(syspath);
      return 0;
    }
    if (*ptr == '\0')
      rpart = ptr; /* if empty, point to the last 0 */
    else
      rpart = ptr+1;
    *ptr = '\0';

/*    out_err(LEVEL_INFO,"   %s | %s\n",lpart,rpart);*/

    strcpy(syspath+sys_offset, lpart);

    /** \todo check permissions here */
    if (fs_file_lstat(syspath,&s)) {
      /* file/dir does not exist
       * 3 cases: error, vfs, symlink */

      /* read permission file for parent */
      strcpy(syspath+sys_offset, HARD_PERMFILE);
      perm_list = NULL;
      ret = readPermFile(syspath, &perm_list);
      syspath[sys_offset] = '\0';

      ret = 1;
      /* check for symlink */
      for (entry=perm_list; entry; entry = entry->next_file)
      {
        if (entry->kind == FILE_LNK && strcmp(lpart,entry->filename) == 0)
        {
          /* bingo, symlink */
          /* we overwrite syspath ! */
          if ( ((char*)entry->data)[0] == '/'
#ifdef WIN32
            || ((char*)entry->data)[1] == ':'
#endif
            )
          { /* symlink target is absolute */
            strncpy(syspath, (char*)entry->data, WZD_MAX_PATH);
            sys_offset = strlen(syspath);
            ret = 0;
            break;
          }
        }
      }

      free_file_recursive(perm_list);

      if (ret) { /* not a symlink, check for VFS */
        /* XXX add vfs entries */
        char * buffer_vfs = wzd_malloc(WZD_MAX_PATH+1);
        char * ptr;
        wzd_vfs_t * vfs = mainConfig->vfs;

        while (vfs)
        {
          ret = 1;
          ptr = vfs_replace_cookies(vfs->virtual_dir,context);
          if (!ptr) {
            out_log(LEVEL_CRITICAL,"vfs_replace_cookies returned NULL for %s\n",vfs->virtual_dir);
            vfs = vfs->next_vfs;
            continue;
          }
          strncpy(buffer_vfs,ptr,WZD_MAX_PATH);
          wzd_free(ptr);
          /** \bug this comparison is false */
          if (DIRNCMP(buffer_vfs,syspath,strlen(syspath))==0)
          { /* ok, we have a candidate. Now check if user is allowed to see it */
            if (!vfs_match_perm(vfs->target,user)) { vfs = vfs->next_vfs; continue; }
            ptr = buffer_vfs + strlen(syspath);
            /* bingo, vfs */
            /* we overwrite syspath ! */
            if ( strchr(ptr,'/')==NULL && !DIRCMP(lpart,ptr) ) { /* not a subdir and same name */
              strncpy(syspath, vfs->physical_dir, WZD_MAX_PATH);
              sys_offset = strlen(syspath);
              ret = 0;
              break;
            }
          }

          vfs = vfs->next_vfs;
        } /* while (vfs) */

        wzd_free(buffer_vfs);
      } /* check for vfs entries */

      /* even if found, check the new destination exists */
      if (ret || fs_file_lstat(syspath,&s)) { /* this time, it is really not found */
        if (!rpart || *rpart=='\0') {
          /* we return the 'what it would have been' path anyway, so it can be used */
          strcpy(syspath+sys_offset, lpart);
          wzd_strncpy(path, syspath, WZD_MAX_PATH);
          ret = E_FILE_NOEXIST;
        } else {
          ret = E_WRONGPATH;
        }
        free(ftppath);
        free(syspath);
        return ret;
      }

    } else {
      /* existing file/dir */
      sys_offset += strlen(lpart);
    } /* stat */

    /* 3 possibilities:
     *   - regular directory
     *   - symlink (on filesystem)
     *   - file
     */
    if (S_ISDIR(s.mode) || S_ISLNK(s.mode)) {
      if (syspath[sys_offset-1] != '/')
        memcpy(&syspath[sys_offset++],"/\0",2); /*use either strcat or memcpy with terminating 0 or corruption can occur*/
      if (_checkFileForPerm(syspath,".",RIGHT_CWD,user)) {
        /* no permissions ! */
        free(ftppath);
        free(syspath);
        return E_NOPERM;
      }
    } else
    {
    }


    /* loop */
    ptr_ftppath = rpart;
  }

  wzd_strncpy(path, syspath, WZD_MAX_PATH);
  free(ftppath);
  free(syspath);
  return 0;
}

/** Tests a path system path, checking
 * for errors and permissions
 *
 * \param trial_path The path in system-form
 * \param context The user context
 * 
 * If the return is 0, then we are SURE the result exists.
 * If the real path points to a directory, then the it must be / terminated
 *
 * Can be used after checkpath_new generates a system path if you wish to
 * recheck whether the file/dir still or now exists
 */

int test_path(const char *trial_path, wzd_context_t *context)
{
  wzd_user_t * user;
  unsigned int trial_offset;
  fs_filestat_t s;

  /* check that we have a valid user, otherwise we can't check permissions */
  user = GetUserByID(context->userid);

  if (!user) return E_USER_IDONTEXIST;

  if (fs_file_lstat(trial_path,&s)) {
    /* test failed, file does not exist */
    return E_FILE_NOEXIST;
  }
  else {
    /* 3 possibilities:
     *   - regular directory
     *   - symlink (on filesystem)
     *   - file
     */
    if (S_ISDIR(s.mode) || S_ISLNK(s.mode)) {
      trial_offset = strlen(trial_path);
      /* check th */
      if (trial_path[trial_offset-1] != '/') {
        return E_WRONGPATH;
      }

      if (_checkFileForPerm(trial_path,".",RIGHT_CWD,user)) {
        /* no permissions ! */

        return E_NOPERM;
      }
    }

  }

  /* its all good */
  return 0;
}


int killpath(const char *path, wzd_context_t * context)
{
  char * test_realpath;
  int found = 0;
  wzd_user_t * me, * user;
  size_t length;

  if (!path) return E_FILE_NOEXIST;

  length = strlen(path);
  test_realpath = malloc(WZD_MAX_PATH+1);

  me = GetUserByID(context->userid);
  WZD_ASSERT( me != NULL );
  if (checkpath_new(context->currentpath,test_realpath,context)) {
    free(test_realpath);
    return E_USER_IDONTEXIST;
  }
#if 0
  /* preliminary check: i can't kill myself */
  if (strncmp(path,test_realpath,length)==0) {
    free(test_realpath);
    return E_USER_ICANTSUICIDE;
  }
#endif

  /* kill'em all ! */
  {
    ListElmt * elmnt;
    wzd_context_t * ctxt;
    for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt)) {
      ctxt = list_data(elmnt);
      if (ctxt->magic == CONTEXT_MAGIC) {
        user = GetUserByID(ctxt->userid);
        WZD_ASSERT( user != NULL );
        if (ctxt->userid == context->userid) { continue; } /* no suicide */
        if (checkpath_new(ctxt->currentpath,test_realpath,ctxt) == 0) {
          if (strncmp(path,test_realpath,length)==0) {
            found++;
            kill_child_new(ctxt->pid_child,context);
          }
        }
      }
    } /* for all contexts */
  }

  free(test_realpath);

  if (!found) return E_USER_NOBODY;

  return E_OK;
}


