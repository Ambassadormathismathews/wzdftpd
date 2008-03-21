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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#endif /* WZD_USE_PCH */

/** \file wzd_file.c
 * \brief Files and directories functions
 *
 * Permissions are stored in a file present in each directory on the server.
 * This allows portable function, and features like symbolic links on
 * systems which does not have links (like windows).
 *
 * \addtogroup libwzd_core
 * @{
 */

#ifdef WIN32
#include <winsock2.h>
#include <io.h>
#include <direct.h> /* _mkdir */
#include <sys/locking.h> /* _locking */
#define _WIN32_WINNT  0x500
#include <windows.h>
#include <tchar.h>
#include <winioctl.h>

// Since MS apparently removed this struct (and its documentation) from
// the W2k SDK, but still refer to it in 'winioctl.h' for the specific
// IOCTLs, I decided to rename it and make it available.
// I've made some modifications to this one for easier access.
//
// Structure for FSCTL_SET_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, and
// FSCTL_DELETE_REPARSE_POINT.
// This version of the reparse data buffer is only for Microsoft tags.

typedef struct
{
    DWORD  ReparseTag;
    WORD   ReparseDataLength;
    WORD   Reserved;

    // IO_REPARSE_TAG_MOUNT_POINT specifics follow
    WORD   SubstituteNameOffset;
    WORD   SubstituteNameLength;
    WORD   PrintNameOffset;
    WORD   PrintNameLength;
    WCHAR  PathBuffer[1];

    // Some helper functions
//	bool Init(LPCSTR szJunctionPoint);
//	bool Init(LPCWSTR wszJunctionPoint);
//	int BytesForIoControl() const;
} TMN_REPARSE_DATA_BUFFER;

#define TMN_REPARSE_DATA_BUFFER_HEADER_SIZE \
			FIELD_OFFSET(TMN_REPARSE_DATA_BUFFER, SubstituteNameOffset)


// These have the wrong values in pre-W2k SDKs, why I redefine them here.
#if !defined(FSCTL_SET_REPARSE_POINT) || \
	(FSCTL_SET_REPARSE_POINT != 0x900a4)
#undef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if !defined(FSCTL_DELETE_REPARSE_POINT) || \
	(FSCTL_DELETE_REPARSE_POINT != 0x900ac)
#undef FSCTL_DELETE_REPARSE_POINT
#define FSCTL_DELETE_REPARSE_POINT      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif




#else
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dirent.h>
#endif

#include <fcntl.h> /* O_RDONLY */

#include "wzd_structs.h"

#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_file.h"
#include "wzd_fs.h"
#include "wzd_group.h"
#include "wzd_cache.h"
#include "wzd_perm.h"
#include "wzd_user.h"
#include "wzd_vfs.h"



/*#define _HAS_MMAP*/

#ifdef _HAS_MMAP
#include <sys/mman.h>
#endif


#include "wzd_debug.h"


#define BUFFER_LEN	4096

/************ PRIVATE FUNCTIONS **************/

/** \brief Get default permission for user
 * \param[in] wanted_right action to be evaluated
 * \param[in] user user definition
 *
 * \todo XXX this function is badly named, userperms is no more a default action, but more a permissions mask
 *
 * Default permissions are set by the userperms field of the user.
 * \return 0 if user is allowed to perform action
 */
static int _default_perm(unsigned long wanted_right, wzd_user_t * user)
{
  return (( wanted_right & user->userperms ) == 0);
}

/** Free file list recursively
 * \note locks SET_MUTEX_FILE_T
 */
void free_file_recursive(struct wzd_file_t * file)
{
  struct wzd_file_t * next_file;
  wzd_acl_line_t *acl_current,*acl_next;

  if (!file) return;
  WZD_MUTEX_LOCK(SET_MUTEX_FILE_T);
  do {
    next_file = file->next_file;
    acl_current = file->acl;
    if (acl_current) {
      do {
        acl_next = acl_current->next_acl;
        wzd_free(acl_current);
        acl_current = acl_next;
      } while (acl_current);
    }
    if (file->data) free(file->data);
    wzd_free (file);
    file = next_file;
  } while (file);
  WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
}

/** \brief Find file \a name in file list
 * \param[in] name file name
 * \param[in] first file list head
 * \return
 *  - file if found
 *  - NULL if not found
 */
static struct wzd_file_t * find_file(const char *name, struct wzd_file_t *first)
{
  struct wzd_file_t *current=first;

  WZD_MUTEX_LOCK(SET_MUTEX_FILE_T);
  while (current) {
    if (strcmp(name,current->filename)==0) {
      WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
      return current;
    }
    current = current->next_file;
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
  return NULL;
}

/** \brief Remove file from linked list
 * \param[in] name file name
 * \param[in,out] file list head
 * \return
 *  - the removed item if found (which must be freed using free_file_recursive()
 *  - NULL if not found
 */
static struct wzd_file_t * remove_file(const char *name, struct wzd_file_t **first)
{
  struct wzd_file_t *current=*first,*prev,*removed;

  if (!current) return NULL;

  WZD_MUTEX_LOCK(SET_MUTEX_FILE_T);
  /* first to be removed ? */
  if (strcmp(name,current->filename)==0) {
    removed = current;
    *first = removed->next_file;
    removed->next_file = NULL;
    WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
    return removed;
  }

  prev = current;
  current = current->next_file;

  while (current) {
    if (strcmp(name,current->filename)==0) {
      removed = current;
      prev->next_file = current->next_file;
      current->next_file = NULL;
      WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
      return removed;
    }
    prev = current;
    current = current->next_file;
  } /* while current */
  WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
  return NULL;
}

/** \brief Insert a new file structure in list, sorted by name
 * \param[in] entry file definition
 * \param[in,out] tab pointer to file list
 */
void file_insert_sorted(struct wzd_file_t *entry, struct wzd_file_t **tab)
{
  struct wzd_file_t *it  = *tab;
  struct wzd_file_t *itp = NULL;

  if ( ! *tab ) {
    *tab = entry;
    return;
  }

  WZD_MUTEX_LOCK(SET_MUTEX_FILE_T);
  while (it) {
    if (strcmp(entry->filename,it->filename)>0)
    {
      itp = it;
      it = it->next_file;
      continue;
    }

    /* we insert here */

    /* head insertion */
    if (itp == NULL) {
      entry->next_file = *tab;
      *tab = entry;
      WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
      return;
    }

    /* middle-insertion */
    entry->next_file = it;
    itp->next_file = entry;

    WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
    return;
  }

  /* tail insertion */
  /* itp can't be NULL here, the first case would have trapped it */
  itp->next_file = entry;

  WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
  return;
}

/** \brief Return ACL corresonding to \a username for \a file
 * \param[in] username User name
 * \param[in] file file structure
 * \return The ACL structure, or NULL
 */
static wzd_acl_line_t * find_acl(const char * username, struct wzd_file_t * file)
{
  wzd_acl_line_t *current = file->acl;

  WZD_MUTEX_LOCK(SET_MUTEX_ACL_T);
  while (current) {
    if (strcmp(username,current->user)==0) {
      WZD_MUTEX_UNLOCK(SET_MUTEX_ACL_T);
      return current;
    }
    current = current->next_acl;
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_ACL_T);
  return NULL;
}

/** \brief Create a structure for file \a name, set owner and group, and append it to list \a first
 * \param[in] name file name
 * \param[in] owner file owner
 * \param[in] group file group
 * \param[in,out] first file list
 * \return a pointer to the new file structure
 */
static struct wzd_file_t * add_new_file(const char *name, const char *owner, const char *group, struct wzd_file_t **first)
{
  struct wzd_file_t *current, *new_file;

  WZD_MUTEX_LOCK(SET_MUTEX_FILE_T);
  new_file = wzd_malloc(sizeof(struct wzd_file_t));
  strncpy(new_file->filename,name,256);
  memset(new_file->owner,0,256);
  if (owner) strncpy(new_file->owner,owner,256);
  memset(new_file->group,0,256);
  if (group) strncpy(new_file->group,group,256);
  new_file->acl = NULL;
  new_file->permissions = mainConfig->umask; /* TODO XXX FIXME hardcoded */
  new_file->kind = FILE_NOTSET;
  new_file->data = NULL;
  new_file->next_file = NULL;
  if (*first == NULL) {
    *first = new_file;
  } else {
    current = *first;
    while (current->next_file)
      current = current->next_file;
    current->next_file = new_file;
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
  return new_file;
}

/** Copy file structure and members
 * \param[in] file_cur file structure
 * \return a newly allocated file structure copied from \a file_cur, or NULL
 * \note one field is changed: next_file is set to NULL to avoid side effects.
 */
struct wzd_file_t * file_deep_copy(struct wzd_file_t *file_cur)
{
  struct wzd_file_t * new_file=NULL;
  wzd_acl_line_t * acl_current, * acl_new, *acl_next;

  if (!file_cur) return NULL;

  WZD_MUTEX_LOCK(SET_MUTEX_FILE_T);
  new_file = wzd_malloc(sizeof(struct wzd_file_t));
  memcpy(new_file, file_cur, sizeof(struct wzd_file_t));
  if (file_cur->data)
    new_file->data = strdup( (char*)file_cur->data ); /** \todo we do not know size */

  if (file_cur->acl) {
    acl_new = malloc(sizeof(wzd_acl_line_t));
    memcpy(acl_new, file_cur->acl, sizeof(wzd_acl_line_t));
    acl_new->next_acl = NULL;
    new_file->acl = acl_new;
    acl_current = file_cur->acl->next_acl;
    while (acl_current) {
      acl_next = malloc(sizeof(wzd_acl_line_t));
      memcpy(acl_next, file_cur->acl, sizeof(wzd_acl_line_t));
      acl_next->next_acl = NULL;
      acl_new->next_acl = acl_next;
      acl_new = acl_next;
      acl_current = acl_current->next_acl;
    }
  }

  /* exception: we set next_file to NULL to avoid side effects */
  new_file->next_file = NULL;

  WZD_MUTEX_UNLOCK(SET_MUTEX_FILE_T);
  return new_file;
}

/** \brief Add new ACL for a file,user
 * \param[in] filename file name
 * \param[in] user
 * \param[in] rights permission line
 * \param[in,out] file file structure
 * \todo return value on error
 * \todo rename function to use common name standards
 */
static void addAcl(const char *filename, const char *user, const char *rights, struct wzd_file_t * file)
{
  wzd_acl_line_t * acl_current, * acl_new;

  WZD_MUTEX_LOCK(SET_MUTEX_ACL_T);

  acl_new = wzd_malloc(sizeof(wzd_acl_line_t));
  strncpy(acl_new->user,user,256);
  strncpy(acl_new->perms,rights,3);

  /* head insertion */
  acl_current = file->acl;
  if (!acl_current) { /* simple case, first insertion */
    file->acl = acl_new;
    acl_new->next_acl = NULL;
    WZD_MUTEX_UNLOCK(SET_MUTEX_ACL_T);
    return;
  }

  while (acl_current) {
    if (strcmp(acl_current->user,user)==0) { /* found ! */
      strncpy(acl_current->perms,rights,3); /* replace old perms */
      wzd_free (acl_new);
      WZD_MUTEX_UNLOCK(SET_MUTEX_ACL_T);
      return;
    }
    acl_current = acl_current->next_acl;
  }

  /* new acl for this file */
  acl_new->next_acl = file->acl;
  file->acl = acl_new;
  WZD_MUTEX_UNLOCK(SET_MUTEX_ACL_T);
}

/** Read permission file and decode it
 * \param[in] permfile full path to permission file
 * \param[out] pTabFiles address of linked list (which will be allocated) containing file permissions
 * \return 0 if ok
 * \todo should be "atomic"
 */
int readPermFile(const char *permfile, struct wzd_file_t **pTabFiles)
{
  wzd_cache_t * fp;
  char line_buffer[BUFFER_LEN];
  struct wzd_file_t *current_file, *ptr_file;
  char * token1, *token2, *token3, *token4, *token5, *token6;
  char *ptr;

  if ( !pTabFiles ) return E_PARAM_NULL;

  current_file = *pTabFiles;

  WZD_MUTEX_LOCK(SET_MUTEX_DIRINFO);
  fp = wzd_cache_open(permfile,O_RDONLY,0644);
  if (!fp) {
    wzd_cache_close(fp);
    WZD_MUTEX_UNLOCK(SET_MUTEX_DIRINFO);
    return E_FILE_NOEXIST;
  }

  ptr = (char*)current_file;
  current_file = NULL;
  while ( wzd_cache_gets(fp,line_buffer,BUFFER_LEN-1) )
  {
    token1 = strtok_r(line_buffer," \t\r\n",&ptr);
    if (!token1) continue; /* malformed line */
    token2 = read_token(NULL, &ptr); /* we can have spaces here */
    if (!token2) continue; /* malformed line */
    token3 = read_token(NULL, &ptr); /* we can have spaces here */
    if (!token3) continue; /* malformed line */
    token4 = strtok_r(NULL," \t\r\n",&ptr);
    if (!token4) continue; /* malformed line */
    /* find file in  list */
    ptr_file = find_file(token2,*pTabFiles);
    if (!ptr_file) {
      ptr_file = add_new_file(token2,0,0,pTabFiles);
    }
    if (strcmp(token1,"owner")==0) {
      token5 = strtok_r(NULL," \t\r\n",&ptr);
/*      if (!token5) continue;*/ /* malformed line */
      strncpy(ptr_file->owner,token3,256);
      strncpy(ptr_file->group,token4,256);
      if (token5) {
        unsigned long ul;
        ul = strtoul(token5,&ptr,8);
        if (ptr==token5) continue;
        ptr_file->permissions = ul;
      } else { /* default user/group permission */
        ptr_file->permissions = mainConfig->umask; /** \todo FIXME hardcoded */
      }
    }
    else if (strcmp(token1,"perm")==0) {
      addAcl(token2,token3,token4,ptr_file);
    }
    else if (strcmp(token1,"link")==0) {
      /** \todo FIXME handle links: set type to link, set destination, set owner/perms */
      token5 = strtok_r(NULL," \t\r\n",&ptr);
      if (!token5) continue; /* malformed line */
      token6 = strtok_r(NULL," \t\r\n",&ptr);

      ptr_file->kind = FILE_LNK;
      ptr_file->data = wzd_strdup(token3);
      strncpy(ptr_file->owner,token4,256);
      strncpy(ptr_file->group,token5,256);
      if (token6) {
        unsigned long ul;
        ul = strtoul(token6,&ptr,8);
        if (ptr==token6) continue;
        ptr_file->permissions = ul;
      } else { /* default user/group permission */
        ptr_file->permissions = mainConfig->umask; /** \todo FIXME hardcoded */
      }
    }
  }

  wzd_cache_close(fp);
  WZD_MUTEX_UNLOCK(SET_MUTEX_DIRINFO);

  return E_OK;
}

/** \brief Write permission file
 * \param[in] permfile permission file full path
 * \param[in] pTabFiles address of linked list of permissions
 * \return 0 if ok
 */
int writePermFile(const char *permfile, struct wzd_file_t **pTabFiles)
{
  char buffer[BUFFER_LEN];
  FILE *fp;
  struct wzd_file_t * file_cur;
  wzd_acl_line_t * acl_cur;
  short has_spaces;

  file_cur = *pTabFiles;

  if ( !file_cur ) {
    /* delete permission file */
    return unlink(permfile);
  }

  WZD_MUTEX_LOCK(SET_MUTEX_DIRINFO);

  fp = fopen(permfile,"w"); /* overwrite any existing file */
  if (!fp) {
    WZD_MUTEX_UNLOCK(SET_MUTEX_DIRINFO);
    return -1;
  }

  /* if file_cur->filename contains spaces, we MUST quote it when writing name */
  while (file_cur) {
    if (file_cur->kind == FILE_LNK) {
      if (strchr( (char*)file_cur->data, ' ')) {
        snprintf(buffer,sizeof(buffer),"link\t%s\t'%s'\t%s\t%s\t%lo\n",
            file_cur->filename,(char*)file_cur->data,file_cur->owner,file_cur->group,file_cur->permissions);
      } else {
        snprintf(buffer,sizeof(buffer),"link\t%s\t%s\t%s\t%s\t%lo\n",
            file_cur->filename,(char*)file_cur->data,file_cur->owner,file_cur->group,file_cur->permissions);
      }
      (void)fwrite(buffer,strlen(buffer),1,fp);
    } else { /* not a link */
      has_spaces = (strchr( (char*)file_cur->filename, ' ') != NULL);
      /* first write owner if available */
      if (strlen(file_cur->owner)>0 || strlen(file_cur->group)>0) {
        if (has_spaces)
          snprintf(buffer,sizeof(buffer),"owner\t'%s'\t%s\t%s\t%lo\n",
              file_cur->filename,file_cur->owner,file_cur->group,file_cur->permissions);
        else
          snprintf(buffer,sizeof(buffer),"owner\t%s\t%s\t%s\t%lo\n",
              file_cur->filename,file_cur->owner,file_cur->group,file_cur->permissions);
        (void)fwrite(buffer,strlen(buffer),1,fp);
      }
      acl_cur = file_cur->acl;
      while (acl_cur) {
        if (has_spaces)
          snprintf(buffer,sizeof(buffer),"perm\t'%s'\t%s\t%c%c%c\n",
              file_cur->filename,acl_cur->user,acl_cur->perms[0],acl_cur->perms[1],acl_cur->perms[2]);
        else
          snprintf(buffer,sizeof(buffer),"perm\t%s\t%s\t%c%c%c\n",
              file_cur->filename,acl_cur->user,acl_cur->perms[0],acl_cur->perms[1],acl_cur->perms[2]);
        (void)fwrite(buffer,strlen(buffer),1,fp);
        acl_cur = acl_cur->next_acl;
      }
    } /* not a link */
    file_cur = file_cur->next_file;
  } /* ! while */

  fclose(fp);

  /* force cache update */
  wzd_cache_update(permfile);

  WZD_MUTEX_UNLOCK(SET_MUTEX_DIRINFO);

  return 0;
}

/** Check if user has a specific permission, given a file and the directory containing it
 * \param[in] dir directory where \a file is stored. it MUST be / terminated
 * \param[in] wanted_file file name
 * \param[in] wanted_right permission to evaluate
 * \param[in] user
 * \return
 *  - 0 if user is authorized to perform action
 *  - 1 if user is not authorized
 *  - -1 on error
 */
int _checkFileForPerm(const char *dir, const char * wanted_file, unsigned long wanted_right, wzd_user_t * user)
{
  char perm_filename[WZD_MAX_PATH+1];
  size_t length, neededlength;
  struct wzd_file_t * file_list=NULL, * file_cur;
  wzd_acl_line_t * acl_cur;
  int ret;
  int is_dir;

  /* find the dir containing the perms file */
  strncpy(perm_filename,dir,WZD_MAX_PATH);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength >= WZD_MAX_PATH )
      return -1;

  /* siteop always hav all permissions */
  if (user->flags && strchr(user->flags,FLAG_SITEOP))
    return 0;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);

/*
out_err(LEVEL_HIGH,"%s:%d\n",__FILE__,__LINE__);
out_err(LEVEL_HIGH,"dir %s filename %s wanted file %s\n",dir,perm_filename,wanted_file);
*/

  ret = readPermFile(perm_filename,&file_list);
  if (ret) { /* no permissions file */
    return _default_perm(wanted_right,user);
  }

  file_cur = find_file(wanted_file,file_list);

  if (file_cur) { /* wanted_file is in list */
    /* now find corresponding acl */
    acl_cur = find_acl(user->username,file_cur);

    is_dir = ( strcmp(wanted_file,".")==0 );

    if (!acl_cur) { /* ! in acl list */
      /* TODO check if user is owner or group of file, and use perms */
      {
        unsigned int i;
        wzd_group_t * group;
/*	out_err(LEVEL_HIGH,"owner %s\n",file_cur->owner);*/
/*	out_err(LEVEL_HIGH,"group %s\n",file_cur->group);*/
/*	out_err(LEVEL_HIGH,"group %lo\n",file_cur->permissions);*/
        if (strcmp(user->username,file_cur->owner)==0) {
          /* NOTE all results are inverted (!=) because we return 0 on success ! */
          switch (wanted_right) {
            case RIGHT_LIST:
            case RIGHT_RETR:
              ret = (file_cur->permissions & 0400);
              break;
            case RIGHT_STOR:
            case RIGHT_MKDIR:
            case RIGHT_RMDIR:
            case RIGHT_RNFR:
              ret = (file_cur->permissions & 0200);
              break;
            case RIGHT_CWD:
              ret = (file_cur->permissions & 0100);
              break;
            default:
              ret = 0;
          }
/*	  out_err(LEVEL_HIGH,"user is file owner : %d !\n",ret);*/
          free_file_recursive(file_list);
          file_list = NULL;
          return !ret;
        }
        for (i=0; i<user->group_num; i++) {
          group = GetGroupByID(user->groups[i]);
          if (group && strcmp(group->groupname,file_cur->group)==0) {
            /* NOTE all results are inverted (!=) because we return 0 on success ! */
            switch (wanted_right) {
              case RIGHT_LIST:
              case RIGHT_RETR:
                ret = (file_cur->permissions & 0040);
                break;
              case RIGHT_STOR:
              case RIGHT_MKDIR:
              case RIGHT_RMDIR:
              case RIGHT_RNFR:
                ret = (file_cur->permissions & 0020);
                break;
              case RIGHT_CWD:
                ret = (file_cur->permissions & 0010);
                break;
              default:
                ret = 0;
            }
            /*	    out_err(LEVEL_HIGH,"user is in group : %d !\n",ret);*/
            free_file_recursive(file_list);
            file_list = NULL;
            return !ret;
          }
        }
      }

      /* NOTE all results are inverted (!=) because we return 0 on success ! */
      switch (wanted_right) {
        case RIGHT_LIST:
        case RIGHT_RETR:
          ret = (file_cur->permissions & 0004);
          break;
        case RIGHT_STOR:
        case RIGHT_MKDIR:
        case RIGHT_RMDIR:
        case RIGHT_RNFR:
          ret = (file_cur->permissions & 0002);
          break;
        case RIGHT_CWD:
          ret = (file_cur->permissions & 0001);
          break;
        default:
          ret = 0;
      }
/*      out_err(LEVEL_HIGH,"user is in others : %d !\n",ret);*/
      free_file_recursive(file_list);
      file_list = NULL;
      return !ret;

    }

    /* NOTE all results are inverted (!=) because we return 0 on success ! */
    switch (wanted_right) {
    case RIGHT_RETR:
      ret = (acl_cur->perms[0]!='r');
      break;
    case RIGHT_STOR:
      ret = (acl_cur->perms[1]!='w');
      break;
    case RIGHT_CWD:
      if (is_dir) ret = (acl_cur->perms[2]!='x');
      else ret = -1;
      break;
    case RIGHT_LIST:
      if (is_dir) ret = (acl_cur->perms[0]!='r');
      else ret = -1;
      break;
    case RIGHT_RNFR:
      ret = (acl_cur->perms[1]!='w');
      break;
    default:
      ret = -1; /* stupid right asked */
      break;
    }
    free_file_recursive(file_list);
    file_list = NULL;
    return ret; /* stupid right asked */
  } else { /* ! in file_list */
    /* FIXME XXX search in parent dirs ???????? - group perms XXX FIXME */
    free_file_recursive(file_list);
    file_list = NULL;
    return _default_perm(wanted_right,user);
  } /* ! in acl */

}

/** MUST NOT be / terminated (except /) */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t * user)
{
  char dir[WZD_MAX_PATH+1];
  char stripped_filename[WZD_MAX_PATH+1];
  char *ptr;
  fs_filestat_t s;

  if (!filename || filename[0] == '\0')
    return -1;

#ifdef WZD_DBG_PERMS
  out_err(LEVEL_HIGH,"_checkPerm(%s,%ld,%s)\n",filename,wanted_right,user->username);
#endif

  strncpy(dir,filename,WZD_MAX_PATH);

  if (user->flags && strchr(user->flags,FLAG_ANONYMOUS))
  {
    switch (wanted_right) {
      case RIGHT_STOR:
      case RIGHT_MKDIR:
      case RIGHT_RMDIR:
      case RIGHT_RNFR:
        return -1;
    }
  }

  if (fs_file_stat(filename,&s)==-1) {
    if (wanted_right != RIGHT_STOR && wanted_right != RIGHT_MKDIR)
      return -1; /* inexistant ? */
    ptr = strrchr(dir,'/');
#ifdef WIN32
    if ( (ptr-dir)==2 && dir[1]==':' )
      ptr++;
#endif
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      if (ptr == &dir[0]) *(ptr+1) = '\0';
      else *ptr = 0;
    }
    /* we need to check in parent dir for the same right */
    if (_checkPerm(dir,wanted_right,user)) return -1; /* we do not have the right to modify parent dir */
  } else {
    if (S_ISDIR(s.mode)) { /* isdir */
      strcpy(stripped_filename,".");
    } else { /* ! isdir */
      ptr = strrchr(dir,'/');
      if (ptr) {
        strcpy(stripped_filename,ptr+1);
        if (ptr == &dir[0]) *(ptr+1) = '\0';
        else *ptr = 0;
      }
    } /* ! isdir */
  } /* stat == -1 */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /** \bug we need to find a way to know if file is in 'visible' path of user.
   * We can't do that without a function to convert syspath to ftppath
   */
#if 0 /* checkpath_new already checks that */
  /* check if file is in user's root path */
  if (strncmp(dir,user->rootpath,strlen(user->rootpath))!=0)
  {
    /* if the file is in a global vfs, it does not need to be in user's rootpath */
    /** \bug it can be a symlink ! */
    wzd_vfs_t * vfs = mainConfig->vfs;
    while(vfs) {
      if (strncmp(dir,vfs->physical_dir,strlen(vfs->physical_dir))==0)
        return _checkFileForPerm(dir,stripped_filename,wanted_right,user);
      vfs = vfs->next_vfs;
    }
    /* if dir is not a vfs, we can have a vfile */
    vfs = mainConfig->vfs;
    while(vfs) {
      if (DIRCMP(filename,vfs->physical_dir)==0)
        return _checkFileForPerm(dir,stripped_filename,wanted_right,user);
      vfs = vfs->next_vfs;
    }
    return 1;
  }
#endif

  return _checkFileForPerm(dir,stripped_filename,wanted_right,user);
}

/** MUST NOT be / terminated (except /) */
int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, unsigned long perms, wzd_context_t * context)
{
  char dir[WZD_MAX_PATH+1];
  char stripped_filename[WZD_MAX_PATH+1];
  char perm_filename[WZD_MAX_PATH+1];
  char *ptr;
  fs_filestat_t s;
  size_t length, neededlength;
  struct wzd_file_t * file_list=NULL, * file_cur;
  int ret;

  if (!filename || filename[0] == '\0')
    return -1;

  strncpy(dir,filename,WZD_MAX_PATH);

  if (fs_file_stat(filename,&s)==-1) return -1; /* inexistant ? */
  if (S_ISDIR(s.mode)) { /* isdir */
    strcpy(stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* find the dir containing the perms file */
  strncpy(perm_filename,dir,WZD_MAX_PATH);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength >= WZD_MAX_PATH )
      return -1;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);


#ifdef WZD_DBG_PERMS
  out_err(LEVEL_FLOOD,"_setPerm: dir %s filename %s wanted file %s\n",dir,perm_filename,stripped_filename);
#endif

  WZD_MUTEX_LOCK(SET_MUTEX_PERMISSION);

  ret = readPermFile(perm_filename,&file_list);
  if (ret) { /* no permissions file */
    file_cur = add_new_file(stripped_filename,0,0,&file_list);
  } else { /* permission file */
    file_cur = find_file(stripped_filename,file_list);
    if (!file_cur) { /* perm file exists, but does not contains acl concerning filename */
      file_cur = add_new_file(stripped_filename,0,0,&file_list);
    }
  }

  /* set the owner/group */
  if (owner || group)
  {
    if (owner) strncpy(file_cur->owner,owner,256);
    if (file_cur->owner[0] == '\0')
      strcpy(file_cur->owner,"nobody");
    if (group) strncpy(file_cur->group,group,256);
    if (file_cur->group[0] == '\0')
      strcpy(file_cur->group,"nogroup");
  }

  /* add the new acl */
  /* remember addAcl REPLACE existing acl on user is already existing */
  if (rights)
    addAcl(stripped_filename,granted_user,rights,file_cur);
  if (perms != (unsigned long)-1)
  {
    file_cur->permissions = perms;
  }

  /* finally writes perm file on disk */
  ret = writePermFile(perm_filename,&file_list);

  free_file_recursive(file_list);
  file_list = NULL;

  WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);
  return 0;
}

/** MUST NOT be / terminated (except /) */
int _movePerm(const char *oldfilename, const char *newfilename, const char *owner, const char *group, wzd_context_t * context)
{
  char dir[BUFFER_LEN];
  char src_stripped_filename[BUFFER_LEN];
  char src_perm_filename[BUFFER_LEN];
  char dst_stripped_filename[BUFFER_LEN];
  char dst_perm_filename[BUFFER_LEN];
  char *ptr;
  fs_filestat_t s,s2;
  size_t length, neededlength;
  struct wzd_file_t * src_file_list=NULL, *dst_file_list=NULL,* file_cur, *file_dst;
  wzd_acl_line_t * acl;
  int ret;

  if (!oldfilename || oldfilename[0] == '\0') return -1;
  if (!newfilename || newfilename[0] == '\0') return -1;

  /* find src perm file name */
  strncpy(dir,oldfilename,BUFFER_LEN);

  if (fs_file_stat(dir,&s)==-1) return -1; /* inexistant ? */
  if (S_ISDIR(s.mode)) { /* isdir */
    /* TODO XXX FIXME Check validity of this assertion ! */
    /* permissions of directory are self contained ! */
    return 0;
    strcpy(src_stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(src_stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* find the dir containing the perms file */
  strncpy(src_perm_filename,dir,BUFFER_LEN);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(src_perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(src_perm_filename+length,HARD_PERMFILE,neededlength);

  /* find dst perm file name */
  strncpy(dir,newfilename,BUFFER_LEN);

  /* if dst file is a dir and exists, we can't make the operation */
  if (fs_file_stat(dir,&s2)==0) { /* file exists ? */
    if (S_ISDIR(s2.mode)) { /* isdir */
      return -1;
    }
  }


  if (S_ISDIR(s.mode)) { /* isdir */
    strcpy(dst_stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(dst_stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* find the dir containing the perms file */
  strncpy(dst_perm_filename,dir,BUFFER_LEN);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(dst_perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(dst_perm_filename+length,HARD_PERMFILE,neededlength);

#ifdef WZD_DBG_PERMS
out_err(LEVEL_FLOOD,"%s:%d\n",__FILE__,__LINE__);
out_err(LEVEL_FLOOD,"dir %s filename %s wanted file %s\n",dir,src_perm_filename,src_stripped_filename);
out_err(LEVEL_FLOOD,"dir %s filename %s wanted file %s\n",dir,dst_perm_filename,dst_stripped_filename);
#endif

  WZD_MUTEX_LOCK(SET_MUTEX_PERMISSION);

  ret = readPermFile(src_perm_filename,&src_file_list);
  if (ret) { /* no permissions file */
    file_dst = NULL;
  } else { /* permission file */
    file_dst = remove_file(src_stripped_filename,&src_file_list);
  } /* permission file */

  /* finally writes perm file on disk */
  ret = writePermFile(src_perm_filename,&src_file_list);
  free_file_recursive(src_file_list);
  src_file_list = NULL;

  ret = readPermFile(dst_perm_filename,&dst_file_list);

  if (!file_dst) { /* src_file had no acl, so we have to remove acl on dst_file if present, and set owner/group */
    file_cur = remove_file(dst_stripped_filename,&dst_file_list);
    free_file_recursive(file_cur);
  } else {

    if (ret) { /* no permissions file */
      file_cur = add_new_file(dst_stripped_filename,file_dst->owner,file_dst->group,&dst_file_list);
    } else { /* permission file */
      file_cur = find_file(dst_stripped_filename,dst_file_list);
      if (!file_cur) { /* perm file exists, but does not contains acl concerning filename */
        file_cur = add_new_file(dst_stripped_filename,file_dst->owner,file_dst->group,&dst_file_list);
      } else {
        if (owner) strncpy(file_cur->owner,file_dst->owner,256);
        if (group) strncpy(file_cur->group,file_dst->group,256);
      }
    }

    /* replace the new acl */
    acl = file_cur->acl;
    file_cur->acl = file_dst->acl;
    file_dst->acl = acl;

    free_file_recursive(file_dst);

  } /* if file_dst */

  /* finally writes perm file on disk */
  ret = writePermFile(dst_perm_filename,&dst_file_list);

  free_file_recursive(dst_file_list);
  dst_file_list = NULL;

  WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);
  return 0;
}

#ifdef _MSC_VER

int _rdb_init(TMN_REPARSE_DATA_BUFFER * rdb, LPCWSTR wszJunctionPoint)
{
  size_t nDestMountPointBytes;

  if (!wszJunctionPoint || !*wszJunctionPoint) {
    return -1;
  }

  nDestMountPointBytes = lstrlenW(wszJunctionPoint) * 2;

  rdb->ReparseTag           = IO_REPARSE_TAG_MOUNT_POINT;
  rdb->ReparseDataLength    = nDestMountPointBytes + 12;
  rdb->Reserved             = 0;
  rdb->SubstituteNameOffset = 0;
  rdb->SubstituteNameLength = nDestMountPointBytes;
  rdb->PrintNameOffset      = nDestMountPointBytes + 2;
  rdb->PrintNameLength      = 0;
  lstrcpyW(rdb->PathBuffer, wszJunctionPoint);

  return 0;
}

/* returns 0 if ok */
int RDB_INIT(TMN_REPARSE_DATA_BUFFER * rdb, LPCSTR szJunctionPoint)
{
  wchar_t wszDestMountPoint[512];
  size_t cchDest;

  if (!szJunctionPoint || !*szJunctionPoint) {
    return -1;
  }

  cchDest = lstrlenA(szJunctionPoint) + 1;
  if (cchDest > 512) {
    return -1;
  }

  if (!MultiByteToWideChar(CP_THREAD_ACP,
        MB_PRECOMPOSED,
        szJunctionPoint,
        cchDest,
        wszDestMountPoint,
        cchDest))
  {
    return -1;
  }

  return _rdb_init(rdb,wszDestMountPoint);
}

int BytesForIoControl(const TMN_REPARSE_DATA_BUFFER *rdb)
{
  return rdb->ReparseDataLength + TMN_REPARSE_DATA_BUFFER_HEADER_SIZE;
}

HANDLE Reparse_Dir_HANDLE(LPCTSTR szDir, int bWriteable)
{
  return CreateFile(	szDir,
      GENERIC_READ | (bWriteable ? GENERIC_WRITE : 0),
      0,
      0,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      0);
}

/* returns 0 if failed, non-zero if success */
int SetReparsePoint(HANDLE m_hDir, const TMN_REPARSE_DATA_BUFFER* rdb)
{
  DWORD dwBytes;
  return DeviceIoControl(m_hDir,
      FSCTL_SET_REPARSE_POINT,
      (LPVOID)rdb,
      BytesForIoControl(rdb),
      NULL,
      0,
      &dwBytes,
      0);
}

int DeleteReparsePoint(HANDLE m_hDir)
{
  REPARSE_GUID_DATA_BUFFER rgdb = { 0 };
  DWORD dwBytes;
  rgdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
  return DeviceIoControl(m_hDir,
      FSCTL_DELETE_REPARSE_POINT,
      &rgdb,
      REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
      NULL,
      0,
      &dwBytes,
      0);
}

int CreateJunctionPoint(LPCTSTR szMountDir, LPCTSTR szDestDirArg)
{
  TCHAR szDestDir[1024];
  char szBuff[MAXIMUM_REPARSE_DATA_BUFFER_SIZE] = { 0 };
  TMN_REPARSE_DATA_BUFFER * rdb;
  TCHAR szFullDir[1024];
  LPTSTR pFilePart;

  if (!szMountDir || !szDestDirArg || !szMountDir[0] || !szDestDirArg[0]) {
    return -1;
  }

  if (szDestDirArg[0] == '\\' && szDestDirArg[1] == '?') {
    lstrcpy(szDestDir, szDestDirArg);
  } else {
    lstrcpy(szDestDir, TEXT("\\??\\"));
    if (!GetFullPathName(szDestDirArg, 1024, szFullDir, &pFilePart) ||
        GetFileAttributes(szFullDir) == -1)
    {
      return -1;
    }
    lstrcat(szDestDir, szFullDir);
  }

  if (!GetFullPathName(szMountDir, 1024, szFullDir, &pFilePart) )
  {
    return -1;
  }
  szMountDir = szFullDir;

  // create link if not existing
  CreateDirectory(szMountDir, NULL);

  rdb = (TMN_REPARSE_DATA_BUFFER*)szBuff;

  RDB_INIT(rdb,szDestDir);

  {
    HANDLE handle;
    handle = Reparse_Dir_HANDLE(szMountDir, 1 /* true */);
    if (handle == INVALID_HANDLE_VALUE) { CloseHandle(handle); RemoveDirectory(szMountDir); return -1; }
    if (!SetReparsePoint(handle,rdb)) { CloseHandle(handle); RemoveDirectory(szMountDir); return -1; }
    CloseHandle(handle);
  }


  return 0;
}

int RemoveJunctionPoint(LPCTSTR szDir)
{
  TCHAR szFullDir[1024];
  LPTSTR pFilePart;

  if (!szDir || !szDir[0]) {
    return -1;
  }

  if (!GetFullPathName(szDir, 1024, szFullDir, &pFilePart) )
  {
    return -1;
  }
  szDir = szFullDir;

  {
    HANDLE handle;
    handle = Reparse_Dir_HANDLE(szDir, 1 /* true */);
    if (handle == INVALID_HANDLE_VALUE) { CloseHandle(handle); return -1; }
    if (!DeleteReparsePoint(handle)) { CloseHandle(handle); return -1; }
    CloseHandle(handle);
    RemoveDirectory(szDir);
  }


  return 0;
}




#endif

int softlink_create(const char *target, const char *linkname)
{
  char perm_filename[WZD_MAX_PATH];
  char stripped_filename[WZD_MAX_PATH];
  char *ptr;
  struct wzd_file_t * perm_list=NULL, * file_cur;
  int ret;
  fs_filestat_t s;

  if (fs_file_stat(target,&s)) { /* target does not exist ?! */
    out_err(LEVEL_FLOOD, "symlink: source does not exist (%s)\n", target);
    return -1;
  }
  if (fs_file_stat(linkname,&s) != -1) { /* linkname already exist ?! */
    out_err(LEVEL_FLOOD, "symlink: destination already exists (%s)\n", linkname);
    return -1;
  }

  /* get permission file */
  strncpy(perm_filename,linkname,WZD_MAX_PATH);
  REMOVE_TRAILING_SLASH(perm_filename);

  ptr = strrchr(perm_filename,'/');
  if (!ptr) return -1;
  {
    /* check that dir exist */
    if (ptr != perm_filename
#ifdef WIN32
      && ptr[-1] != ':'
#endif
      )
    {
      *ptr = '\0';
      if (fs_file_stat(perm_filename,&s)) {
        out_err(LEVEL_FLOOD, "symlink: destination directory does not exist (%s)\n", perm_filename);
        return -1;
      }
      *ptr = '/';
    }
  }
  ptr++; /* position is just after last / */
  strncpy(stripped_filename, ptr, WZD_MAX_PATH);
  strncpy(ptr, HARD_PERMFILE, WZD_MAX_PATH - (ptr-perm_filename));

  WZD_MUTEX_LOCK(SET_MUTEX_PERMISSION);
  /* read perm file */
  ret = readPermFile(perm_filename,&perm_list);

  /* create new entry */
  if (ret) { /* no permission file */
    file_cur = add_new_file(stripped_filename, 0, 0, &perm_list);
  } else {
    file_cur = find_file(stripped_filename, perm_list);
    if (file_cur) {
      /* error, an entry already exists with the same name */
      out_err(LEVEL_FLOOD, "symlink: link already exists here (%s)\n", perm_filename);
      free_file_recursive(perm_list);
      WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);
      return EEXIST;
    }
    file_cur = add_new_file(stripped_filename, 0, 0, &perm_list);
  }

  file_cur->kind = FILE_LNK;
  file_cur->data = strdup(target);
  REMOVE_TRAILING_SLASH( (char*) file_cur->data );

  /** \todo set owner/group of symlink ? */
  strncpy(file_cur->owner,"nobody",256);
  strncpy(file_cur->group,"nogroup",256);

  /* write modified permission file on disk */
  ret = writePermFile(perm_filename, &perm_list);

  free_file_recursive(perm_list);
  perm_list = NULL;
  WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);

  return 0;
}

int softlink_remove(const char *linkname)
{
  char perm_filename[WZD_MAX_PATH];
  char stripped_filename[WZD_MAX_PATH];
  char *ptr;
  size_t length;
  struct wzd_file_t * perm_list=NULL, * file_cur;
  int ret;

  /* get permission file */
  if (!linkname) return -1;

  strncpy(perm_filename,linkname,WZD_MAX_PATH);
  length = strlen(perm_filename);
  if (length > 1 && perm_filename[length-1] == '/') perm_filename[--length] = '\0';

  ptr = strrchr(perm_filename,'/');
  if (!ptr) return -1;
  ptr++; /* position is just after last / */
  strncpy(stripped_filename, ptr, WZD_MAX_PATH);
  strncpy(ptr, HARD_PERMFILE, WZD_MAX_PATH - (ptr-perm_filename));

  WZD_MUTEX_LOCK(SET_MUTEX_PERMISSION);
  /* read perm file */
  ret = readPermFile(perm_filename,&perm_list);

  /* remove entry */
  if (!ret) {
    file_cur = find_file(stripped_filename, perm_list);
    if ( !file_cur || file_cur->kind != FILE_LNK )
    {
      free_file_recursive(perm_list);
      out_err(LEVEL_FLOOD, "symlink: trying to remove something that is not a link (%s)\n", linkname);
      WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);
      return -1;
    }

    file_cur = remove_file(stripped_filename, &perm_list);

    /* write modified permission file on disk */
    ret = writePermFile(perm_filename, &perm_list);

    free_file_recursive(file_cur);
    free_file_recursive(perm_list);
  }

  perm_list = NULL;
  WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);

  return 0;
}


/************ PUBLIC FUNCTIONS ***************/

int file_open(const char *filename, int mode, unsigned long wanted_right, wzd_context_t * context)
{
  fd_t file;
  int ret;
  wzd_user_t * user;
  short is_locked;

  user = GetUserByID(context->userid);

  if (mode & O_WRONLY)
    ret = _checkPerm(filename,RIGHT_STOR,user);
  else
    ret = _checkPerm(filename,RIGHT_RETR,user);
  if (ret)
    return -1;

  /* is a directory ? */
  {
    fs_filestat_t s;
    if (fs_file_stat(filename,&s) == 0) {
      if (S_ISDIR(s.mode)) return -1;
    }
  }

#ifdef WIN32
  mode |= _O_BINARY;
#endif

  file = fs_open(filename,mode,0666);
  if (file == -1) {
    out_log(LEVEL_INFO,"Can't open %s, errno %d : %s\n",filename,errno,strerror(errno));
    return -1;
  }

  is_locked = file_islocked(file,F_WRLCK);

  if (is_locked == -1) {
    out_log(LEVEL_NORMAL,"Could not get lock info\n");
  }
  else {
    if ( mode & O_WRONLY ) {
      if (is_locked) {
        close(file);
/*        out_err(LEVEL_HIGH,"Can't open %s in write mode, locked !\n",filename);*/
        return -1;
      }
      file_lock(file,F_WRLCK);
    }
    else {
      if (is_locked) {
/*	out_err(LEVEL_HIGH,"%s is locked, trying to read\n",filename);*/
        if ( CFG_GET_OPTION(mainConfig,CFG_OPT_DENY_ACCESS_FILES_UPLOADED) ) {
          close(file);
          return -1;
        }
      }
    }
  }

  return file;
}

void file_close(fd_t file, wzd_context_t * context)
{
  close(file);
}

fs_off_t file_seek(fd_t file, fs_off_t offset, int whence)
{
  return fs_lseek(file,offset,whence);
}

/** NOTE:
 * one of username/groupname can be NULL
 * context is usefull to check if the user can chown to other users
 */
int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context)
{
  return _setPerm(filename,0,username,groupname,0,(unsigned long)-1,context);
}

int file_mkdir(const char *dirname, unsigned int mode, wzd_context_t * context)
{
  int ret;
  int err;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  ret = _checkPerm(dirname,RIGHT_MKDIR,user);
  if (ret) return E_NOPERM;
  ret = fs_mkdir(dirname,0755,&err);

  return (ret) ? E_COMMAND_FAILED : E_OK;
}

/** @brief remove directory.
 *
 * dirname must be an absolute path
 */
int file_rmdir(const char *dirname, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  fs_filestat_t s;
  fs_dir_t * dir;
  fs_fileinfo_t * finfo;

  user = GetUserByID(context->userid);

  ret = _checkPerm(dirname,RIGHT_RMDIR,user);
  if (ret) return -1;

  /* is a directory ? */
  if (fs_file_stat(dirname,&s)) return -1;
  if (!S_ISDIR(s.mode)) return -1;

  /* is dir empty ? */
  {
    char path_perm[2048];
    const char *filename;

    if ( fs_dir_open(dirname,&dir) ) return 0;

    while ( !fs_dir_read(dir,&finfo) ) {
      filename = fs_fileinfo_getname(finfo);

      if (strcmp(filename,".")==0 ||
          strcmp(filename,"..")==0 ||
          strcmp(filename,HARD_PERMFILE)==0) /* XXX hide perm file ! */
        continue;
      fs_dir_close(dir);
      return 1; /* dir not empty */
    }

    fs_dir_close(dir);

    /* remove permission file */
    strcpy(path_perm,dirname); /* path is already ended by / */
    if (path_perm[strlen(path_perm)-1] != '/')
      strcat(path_perm,"/");
    (void)strlcat(path_perm,HARD_PERMFILE,sizeof(path_perm));
    unlink(path_perm);
  }

#ifdef DEBUG
out_err(LEVEL_HIGH,"Removing directory '%s'\n",dirname);
#endif

#ifndef __CYGWIN__
  {
    fs_filestat_t s;
    fs_file_lstat(dirname,&s);
    if (S_ISLNK(s.mode))
      return unlink(dirname);
  }
#endif
  return rmdir(dirname);

}

/** \brief Change the name or location of a file
 *
 * old_filename and new_filename must be ABSOLUTE paths
 */
int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context)
{
  char path[2048];
  char * ptr;
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  strncpy(path,new_filename,2048);
  ptr = strrchr(path,'/');
  if (!ptr) return 1;
  *ptr = '\0';
  ret = _checkPerm(old_filename,RIGHT_RNFR,user);
  ret = ret || _checkPerm(path,RIGHT_STOR,user);
  if (ret)
    return 1;

  /* change file name in perm file !! */
  ret = _movePerm(old_filename,new_filename,0,0,context);

  ret = safe_rename(old_filename,new_filename);
  if (ret==-1) {
#ifdef DEBUG
out_err(LEVEL_HIGH,"rename error %d (%s)\n", errno, strerror(errno));
#endif
    return 1;
  }

  return 0;
}

int file_remove(const char *filename, wzd_context_t * context)
{
  char perm_filename[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char * ptr;
  int ret;
  wzd_user_t * user;
  struct wzd_file_t * file_list=NULL, * file_cur;
  size_t neededlength, length;

  /* find the dir containing the perms file */
  strncpy(perm_filename,filename,BUFFER_LEN);
  ptr = strrchr(perm_filename,'/');
  if (!ptr || *(ptr+1)=='\0') return -1;
  strcpy(stripped_filename,ptr+1);
  if (ptr != perm_filename) *(ptr+1)='\0';
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);
  perm_filename[length+neededlength]='\0';

  user = GetUserByID(context->userid);

/*  ret = _checkPerm(filename,RIGHT_STOR ,user);*/
  /* to delete, defaults permissions are: owner and siteop can delete file */
  if (user->flags && strchr(user->flags,FLAG_SITEOP))
    ret = 0; /* siteop -> ok */
  else
  {
    ret = 1;
    file_cur = file_stat(filename, context);

    /* if file_cur is NULL it means that we have no entry for that file
     * it happens when deleting a symlink, when destination does not
     * exist
     */
    if (file_cur) {
      if (strcmp(user->username, file_cur->owner)==0) ret = 0; /* owner */

      free_file_recursive(file_cur);
      file_cur = NULL;
    }

    /* The delete permission is special: by default, all users can run the DELE
     * command, but only owner of the file or siteops can delete files.
     * If the "delete" permission is set, it will allow non-owners to delete the file.
     */
    {
      wzd_command_t * command;
      wzd_string_t * str = STR("delete");

      command = commands_find(mainConfig->commands_list, str);
      str_deallocate(str);
      if (commands_check_permission(command, context) == 0) ret = 0;
    }

  }

  if (ret)
    return 1;

  WZD_MUTEX_LOCK(SET_MUTEX_PERMISSION);
  /* remove name in perm file !! */
  ret = readPermFile(perm_filename,&file_list);
  if (!ret) {
    file_cur = remove_file(stripped_filename, &file_list);
    ret = writePermFile(perm_filename,&file_list);
    free_file_recursive(file_cur);
    free_file_recursive(file_list);
  }
  ret = unlink(filename);
  if (ret==-1) {
#ifdef DEBUG
out_err(LEVEL_HIGH,"remove error %d (%s)\n", errno, strerror(errno));
#endif
    WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);
    return 1;
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_PERMISSION);

  return 0;
}

wzd_user_t * file_getowner(const char *filename, wzd_context_t * context)
{
  char perm_filename[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char * ptr;
  int ret;
  struct wzd_file_t * file_list=NULL, * file_cur;
  size_t neededlength, length;
  fs_filestat_t s;

  if (fs_file_stat(filename,&s))
    return NULL;

  /* find the dir containing the perms file */
  strncpy(perm_filename,filename,BUFFER_LEN);
  ptr = strrchr(perm_filename,'/');
  if (!ptr || *(ptr+1)=='\0') return NULL;

  if (S_ISDIR(s.mode)) { /* isdir */
    strcpy(stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(perm_filename,'/');
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */


/*  strcpy(stripped_filename,ptr+1);*/
/*  if (ptr != perm_filename) *(ptr+1)='\0';*/

  neededlength = strlen(HARD_PERMFILE)+1;
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return NULL;

  if (perm_filename[length-1] != '/' ) {
    ++length;
    perm_filename[length-1] = '/';
  }
  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);

  /* remove name in perm file !! */
  ret = readPermFile(perm_filename,&file_list);
  if (!ret) {
    /* we have a permission file */
    file_cur = file_list;
    while (file_cur)
    {
      if (strcmp(stripped_filename,file_cur->filename)==0) {
        if (file_cur->owner[0]!='\0')
        {
          wzd_user_t * user;
          user = GetUserByName(file_cur->owner);
          free_file_recursive(file_list);
          return user;
        }
        else
        {
          free_file_recursive(file_list);
          return GetUserByName("nobody");
        }
      }
      file_cur = file_cur->next_file;
    }
    free_file_recursive(file_list);
  }

  return GetUserByName("nobody");
}

/** Permissions are returned as a hex value composed of permissions ORed like
 * RIGHT_LIST | RIGHT_CWD
 */
unsigned long file_getperms(struct wzd_file_t * file, wzd_context_t * context)
{
  unsigned long perms = 0;
  wzd_user_t * user;
  wzd_acl_line_t * acl_cur;
  wzd_group_t * group;

  WZD_ASSERT(context != NULL);

  user = GetUserByID(context->userid);
  if (!user) return RIGHT_NONE;

  if (!file) return _default_perm(0xffffffff,user);

  /* now find corresponding acl */
  acl_cur = find_acl(user->username,file);

  if (acl_cur) {
    if (acl_cur->perms[0]=='r') perms |= RIGHT_RETR;
    if (acl_cur->perms[1]=='w') perms |= RIGHT_STOR | RIGHT_RNFR;
    if (file->kind == FILE_DIR && acl_cur->perms[2]=='x') perms |= RIGHT_CWD;
  } else { /* no acl, check 'permissions field */
    /* owner ? */
    if (strcmp(user->username,file->owner)==0) {
      if (file->permissions & 0400) perms |= RIGHT_RETR;
      if (file->permissions & 0200) perms |= RIGHT_STOR | RIGHT_RNFR;
      if (file->kind == FILE_DIR && file->permissions & 0100) perms |= RIGHT_CWD;
    } else {
      /* same group ? */
      unsigned int i;
      unsigned short found=0;

      for (i=0; i<user->group_num; i++) {
        group = GetGroupByID(user->groups[i]);
        if (group && strcmp(group->groupname,file->group)==0) {
          found++;
          if (file->permissions & 0040) perms |= RIGHT_RETR;
          if (file->permissions & 0020) perms |= RIGHT_STOR | RIGHT_RNFR;
          if (file->kind == FILE_DIR && file->permissions & 0010) perms |= RIGHT_CWD;
        }
      }

      if (!found) { /* "others" permissions apply */
        if (file->permissions & 0004) perms |= RIGHT_RETR;
        if (file->permissions & 0002) perms |= RIGHT_STOR | RIGHT_RNFR;
        if (file->kind == FILE_DIR && file->permissions & 0001) perms |= RIGHT_CWD;
      }
    }
  }

  /* is a directory ? */
  if (file->kind == FILE_DIR) {
    if (perms & RIGHT_RETR) perms |= RIGHT_LIST;
    if (perms & RIGHT_STOR) perms |= RIGHT_MKDIR;
  }

  /** \todo RIGHT_DELE is never checked */

  return perms;
}


/** This function return information about the specified file. You do not need any
 * special right on the file, but you need search rights on any directory on the
 * path to the file.
 *
 * If filename is a symbolic link, the destination is stat-ed, not the link itself.
 *
 * Caller MUST free memory using \ref free_file_recursive
 *
 * \return struct, or NULL if nothing known, -1 if error or non-existant
 */
struct wzd_file_t * file_stat(const char *filename, wzd_context_t * context)
{
  char perm_filename[WZD_MAX_PATH+1];
  char stripped_filename[WZD_MAX_PATH+1];
  char * ptr;
  struct wzd_file_t * file_list=NULL, * file_cur, *file;
  size_t neededlength, length;
  fs_filestat_t s;
  int nx=0;

  /** \bug no no no, it can be a symlink or a vfs ! */
/*  if (fs_stat(filename,&s))
    return NULL;*/

  /* check for VFS */
  {
    wzd_vfs_t * vfs = mainConfig->vfs;
    char * buffer_vfs;

    while (vfs) {
      buffer_vfs = vfs_replace_cookies(vfs->virtual_dir,context);
      if (!buffer_vfs) {
        out_log(LEVEL_CRITICAL,"vfs_replace_cookies returned NULL for %s\n",vfs->virtual_dir);
        vfs = vfs->next_vfs;
        continue;
      }

      if (DIRCMP(buffer_vfs,filename)==0) {
        /* ok, we have a candidate */
        file = file_stat(vfs->physical_dir,context);
        wzd_free(buffer_vfs);
        return file;
      }

      wzd_free(buffer_vfs);
      vfs = vfs->next_vfs;
    }

  }

  file = NULL;

  /* find the dir containing the perms file */
  wzd_strncpy(perm_filename,filename,WZD_MAX_PATH);
  length = strlen(perm_filename);
  if (length >1 && perm_filename[length-1]=='/')
    perm_filename[--length] = '\0';
  ptr = strrchr(perm_filename,'/');
  if (ptr == NULL) return NULL;

  if (!fs_file_lstat(filename,&s)) {
    if (S_ISDIR(s.mode)) { /* isdir */
      strcpy(stripped_filename,".");
    } else { /* ! isdir */
      ptr = strrchr(perm_filename,'/');
      if (ptr) {
        strcpy(stripped_filename,ptr+1);
        *ptr = 0;
      }
    }
  } else { /* ! exists */
    nx = 1;
    ptr = strrchr(perm_filename,'/');
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      *ptr = 0;
      if (fs_file_lstat(perm_filename,&s)) {
        out_err(LEVEL_FLOOD, "symlink: destination directory does not exist (%s)\n", perm_filename);
        return NULL;
      }
    }
  } /* ! exists */


/*  strcpy(stripped_filename,ptr+1);*/
/*  if (ptr != perm_filename) *(ptr+1)='\0';*/

  neededlength = strlen(HARD_PERMFILE)+1;
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength >= WZD_MAX_PATH )
      return NULL;

  if (perm_filename[length-1] != '/' ) {
    ++length;
    perm_filename[length-1] = '/';
  }
  wzd_strncpy(perm_filename+length,HARD_PERMFILE,neededlength);

  if ( ! readPermFile(perm_filename,&file_list) ) {
    /* we have a permission file */
    file_cur = find_file(stripped_filename, file_list);
    if (file_cur)
      file = file_deep_copy(file_cur);
    free_file_recursive(file_list);
  }

  if (!file && nx) return NULL;

  if (file == NULL) { /* create minimal struct */
    /** \bug XXX FIXME we should not allocate anything here, since this will be a memory leak */
    file = wzd_malloc(sizeof(struct wzd_file_t));

    wzd_strncpy(file->filename,stripped_filename,sizeof(file->filename));
    file->owner[0] = '\0';
    file->group[0] = '\0';
    file->permissions = mainConfig->umask; /** \todo FIXME default permission */
    file->acl = NULL;
    file->kind = FILE_NOTSET;
    file->data = NULL;
    file->next_file = NULL;
  }

  if (file) {
    if (S_ISDIR(s.mode)) file->kind = FILE_DIR;
    if (S_ISLNK(s.mode)) file->kind = FILE_LNK;
    if (S_ISREG(s.mode)) file->kind = FILE_REG;
  }

  return file;
}

/* if program crash, locks acquired by fcntl (POSIX) or _locking (VISUAL)
 * are released, and then do are less annoying.
 */
int file_lock(fd_t file, short lock_mode)
{
#ifdef WZD_DBG_LOCK
out_err(LEVEL_HIGH,"Locking file %d\n",file);
#endif
#ifndef WIN32
  struct flock lck;
  lck.l_type = lock_mode;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;
  if (fcntl(file, F_SETLK, &lck) < 0) {
    return -1;
  }
#else
  if (_locking(file, LK_NBLCK, -1) == -1)
    return -1;
#endif
  return 0;
}

int file_unlock(fd_t file)
{
#ifdef WZD_DBG_LOCK
out_err(LEVEL_HIGH,"Unlocking file %d\n",file);
#endif
#ifndef WIN32
  struct flock lck;
  lck.l_type = F_UNLCK;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;
  if (fcntl(file, F_SETLK, &lck) < 0) {
    return -1;
  }
#else
  if (_locking(file, LK_UNLCK, -1) == -1)
    return -1;
#endif
  return 0;
}

int file_islocked(fd_t file, short lock_mode)
{
#ifdef WZD_DBG_LOCK
out_err(LEVEL_HIGH,"Testing lock for file %d\n",file);
#endif
#ifndef WIN32
  struct flock lck;
  lck.l_type = lock_mode;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;

  if (fcntl(file, F_GETLK, &lck) < 0) {
    return -1;
  }
  if (lck.l_type == F_RDLCK || lck.l_type == F_WRLCK) return 1;
#else
  if (_locking(file, LK_NBLCK, -1) != -1) {
    _locking(file, LK_UNLCK, -1);
    return 0;
  } else {
    if (errno == EACCES) return 1;
    return -1;
  }
#endif
  return 0;
}

int file_force_unlock(const char *file)
{
  fd_t file;
#ifdef WZD_DBG_LOCK
out_err(LEVEL_HIGH,"Forcing unlock file %s\n",file);
#endif

  file = open(file,O_RDWR);
  if (file < 0) {
    out_log(LEVEL_INFO,"Can't open %s, errno %d : %s\n",file,errno,strerror(errno));
    return -1;
  }

#ifndef WIN32
  {
    struct flock lck;
    lck.l_type = F_UNLCK;
    lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
    lck.l_start = 0;
    lck.l_len = 0;
    if (fcntl(file, F_SETLK, &lck) < 0) {
      close(file);
      return -1;
    }
  }
#else
  if (_locking(file, LK_UNLCK, -1) == -1)
  {
    close(file);
    return -1;
  }
#endif
  close(file);
  return 0;
}

/* wrappers just to keep things in same memory zones */
ssize_t file_read(fd_t file,void *data,size_t length)
{
  return read(file,data,length);
}

ssize_t file_write(fd_t file,const void *data,size_t length)
{
  return write(file,data,length);
}

/* symlink operations */

/** \brief create symlink
 * paths must be absolute
 * paths must not be / terminated !
 * \todo if paths are relative, convert them ?
 */
int symlink_create(const char *existing, const char *link)
{
  /** \todo XXX FIXME check that symlink dest is inside user authorized path */
#ifndef WIN32
  return symlink(existing, link);
#else
  return softlink_create(existing, link);
/*  return CreateJunctionPoint(link, existing);*/
#endif
}

int symlink_remove(const char *link)
{
#ifndef WIN32
  fs_filestat_t s;

  if (fs_file_lstat(link,&s)) return E_FILE_NOEXIST;
  if ( !S_ISLNK(s.mode) ) return E_FILE_TYPE;
  return unlink(link);
#else
  return softlink_remove(link);
/*  return RemoveJunctionPoint(link);*/
#endif
}

/** @} */

