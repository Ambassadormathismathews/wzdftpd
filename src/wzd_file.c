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
#include <sys/stat.h>
#include <errno.h>

#ifdef _MSC_VER
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

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_file.h"
#include "wzd_cache.h"
#include "wzd_perm.h"



/*#define _HAS_MMAP*/

#ifdef _HAS_MMAP
#include <sys/mman.h>
#endif


#include "wzd_debug.h"


#define BUFFER_LEN	4096

/************ PRIVATE FUNCTIONS **************/

static int _default_perm(unsigned long wanted_right, wzd_user_t * user)
{
  return (( wanted_right & user->userperms ) == 0);
}

void free_file_recursive(struct wzd_file_t * file)
{
  struct wzd_file_t * next_file;
  wzd_acl_line_t *acl_current,*acl_next;

  if (!file) return;
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
}

static struct wzd_file_t * find_file(const char *name, struct wzd_file_t *first)
{
  struct wzd_file_t *current=first;

  while (current) {
    if (strcmp(name,current->filename)==0)
      return current;
    current = current->next_file;
  }
  return NULL;
}

static struct wzd_file_t * remove_file(const char *name, struct wzd_file_t **first)
{
  struct wzd_file_t *current=*first,*prev,*removed;

  if (!current) return NULL;
  
  /* first to be removed ? */
  if (strcmp(name,current->filename)==0) {
    removed = current;
    *first = removed->next_file;
    removed->next_file = NULL;
    return removed;
  }
  
  prev = current;
  current = current->next_file;

  while (current) {
    if (strcmp(name,current->filename)==0) {
      removed = current;
      prev->next_file = current->next_file;
      current->next_file = NULL;
      return removed;
    }
    prev = current;
    current = current->next_file;
  } /* while current */
  return NULL;
}

void file_insert_sorted(struct wzd_file_t *entry, struct wzd_file_t **tab)
{
  struct wzd_file_t *it  = *tab;
  struct wzd_file_t *itp = NULL;

  if ( ! *tab ) {
    *tab = entry;
    return;
  }

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
      return;
    }

    /* middle-insertion */
    entry->next_file = it;
    itp->next_file = entry;

    return;
  }

  /* tail insertion */
  /* itp can't be NULL here, the first case would have trapped it */
  itp->next_file = entry;
  
  return;
}


wzd_acl_line_t * find_acl(const char * username, struct wzd_file_t * file)
{
  wzd_acl_line_t *current = file->acl;

  while (current) {
    if (strcmp(username,current->user)==0)
      return current;
    current = current->next_acl;
  }
  return NULL;
}

/** creation and tail insertion */
static struct wzd_file_t * add_new_file(const char *name, const char *owner, const char *group, struct wzd_file_t **first)
{
  struct wzd_file_t *current, *new_file;

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
  return new_file;
}

struct wzd_file_t * file_deep_copy(struct wzd_file_t *file_cur)
{
  struct wzd_file_t * new_file=NULL;
  wzd_acl_line_t * acl_current, * acl_new, *acl_next;

  if (!file_cur) return NULL;

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

  return new_file;
}

/** replace or add acl rule */
void addAcl(const char *filename, const char *user, const char *rights, struct wzd_file_t * file)
{
  wzd_acl_line_t * acl_current, * acl_new;

  acl_new = wzd_malloc(sizeof(wzd_acl_line_t));
  strncpy(acl_new->user,user,256);
  strncpy(acl_new->perms,rights,3);

  /* head insertion */
  acl_current = file->acl;
  if (!acl_current) { /* simple case, first insertion */
    file->acl = acl_new;
    acl_new->next_acl = NULL;
    return;
  }

  while (acl_current) {
    if (strcmp(acl_current->user,user)==0) { /* found ! */
      strncpy(acl_current->perms,rights,3); /* replace old perms */
      wzd_free (acl_new);
      return;
    }
    acl_current = acl_current->next_acl;
  }

  /* new acl for this file */
  acl_new->next_acl = file->acl;
  file->acl = acl_new;
}

/** \todo should be "atomic" */
int readPermFile(const char *permfile, struct wzd_file_t **pTabFiles)
{
  wzd_cache_t * fp;
  char line_buffer[BUFFER_LEN];
  struct wzd_file_t *current_file, *ptr_file;
  char * token1, *token2, *token3, *token4, *token5, *token6;
  char *ptr;

  if ( !pTabFiles ) return E_PARAM_NULL;

  current_file = *pTabFiles;

  fp = wzd_cache_open(permfile,O_RDONLY,0644);
  if (!fp) { wzd_cache_close(fp); return E_FILE_NOEXIST; }

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
  return E_OK;
}

/** \todo should be "atomic" */
int writePermFile(const char *permfile, struct wzd_file_t **pTabFiles)
{
  char buffer[BUFFER_LEN];
  FILE *fp;
  struct wzd_file_t * file_cur;
  wzd_acl_line_t * acl_cur;

  file_cur = *pTabFiles;

  if ( !file_cur ) {
    /* delete permission file */
    return unlink(permfile);
  }

  fp = fopen(permfile,"w"); /* overwrite any existing file */
  if (!fp) return -1;

  /** \bug if file_cur->filename contains spaces, we MUST quote it when writing name */
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
      /* first write owner if available */
      if (strlen(file_cur->owner)>0 || strlen(file_cur->group)>0) {
        snprintf(buffer,sizeof(buffer),"owner\t%s\t%s\t%s\t%lo\n",
            file_cur->filename,file_cur->owner,file_cur->group,file_cur->permissions);
        (void)fwrite(buffer,strlen(buffer),1,fp);
      }
      acl_cur = file_cur->acl;
      while (acl_cur) {
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

  return 0;
}

/** dir MUST be / terminated
 * wanted_file MUST be a single file name !
 */
int _checkFileForPerm(char *dir, const char * wanted_file, unsigned long wanted_right, wzd_user_t * user)
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
fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,perm_filename,wanted_file);
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
  struct stat s;

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

  if (stat(filename,&s)==-1) {
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
    if (S_ISDIR(s.st_mode)) { /* isdir */
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
  struct stat s;
  size_t length, neededlength;
  struct wzd_file_t * file_list=NULL, * file_cur;
  int ret;

  if (!filename || filename[0] == '\0')
    return -1;

  strncpy(dir,filename,WZD_MAX_PATH);

  if (stat(filename,&s)==-1) return -1; /* inexistant ? */
  if (S_ISDIR(s.st_mode)) { /* isdir */
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


/*fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);*/
#ifdef DEBUG
  out_err(LEVEL_FLOOD,"_setPerm: dir %s filename %s wanted file %s\n",dir,perm_filename,stripped_filename);
#endif

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
  struct stat s,s2;
  size_t length, neededlength;
  struct wzd_file_t * src_file_list=NULL, *dst_file_list=NULL,* file_cur, *file_dst;
  wzd_acl_line_t * acl;
  int ret;

  if (!oldfilename || oldfilename[0] == '\0') return -1;
  if (!newfilename || newfilename[0] == '\0') return -1;

  /* find src perm file name */
  strncpy(dir,oldfilename,BUFFER_LEN);

  if (stat(dir,&s)==-1) return -1; /* inexistant ? */
  if (S_ISDIR(s.st_mode)) { /* isdir */
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
  if (stat(dir,&s2)==0) { /* file exists ? */
    if (S_ISDIR(s2.st_mode)) { /* isdir */
      return -1;
    }
  }


  if (S_ISDIR(s.st_mode)) { /* isdir */
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

#ifdef DEBUG
fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,src_perm_filename,src_stripped_filename);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,dst_perm_filename,dst_stripped_filename);
#endif

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
  struct stat s;

  if (stat(target,&s)) { /* target does not exist ?! */
    out_err(LEVEL_FLOOD, "symlink: source does not exist (%s)\n", target);
    return -1;
  }
  if (stat(linkname,&s) != -1) { /* linkname already exist ?! */
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
      if (stat(perm_filename,&s)) {
        out_err(LEVEL_FLOOD, "symlink: destination directory does not exist (%s)\n", perm_filename);
        return -1;
      }
      *ptr = '/';
    }
  }
  ptr++; /* position is just after last / */
  strncpy(stripped_filename, ptr, WZD_MAX_PATH);
  strncpy(ptr, HARD_PERMFILE, WZD_MAX_PATH - (ptr-perm_filename));

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

  strncpy(perm_filename,linkname,WZD_MAX_PATH);
  length = strlen(perm_filename);
  if (length > 1 && perm_filename[length-1] == '/') perm_filename[--length] = '\0';

  ptr = strrchr(perm_filename,'/');
  ptr++; /* position is just after last / */
  strncpy(stripped_filename, ptr, WZD_MAX_PATH);
  strncpy(ptr, HARD_PERMFILE, WZD_MAX_PATH - (ptr-perm_filename));

  /* read perm file */
  ret = readPermFile(perm_filename,&perm_list);

  /* remove entry */
  if (!ret) {
    file_cur = find_file(stripped_filename, perm_list);
    if ( !file_cur || file_cur->kind != FILE_LNK )
    {
      free_file_recursive(perm_list);
      out_err(LEVEL_FLOOD, "symlink: trying to remove something that is not a link (%s)\n", linkname);
     return -1;
    }

    file_cur = remove_file(stripped_filename, &perm_list);

    /* write modified permission file on disk */
    ret = writePermFile(perm_filename, &perm_list);

    free_file_recursive(file_cur);
    free_file_recursive(perm_list);
  }

  perm_list = NULL;

  return 0;
}


/************ PUBLIC FUNCTIONS ***************/

int file_open(const char *filename, int mode, unsigned long wanted_right, wzd_context_t * context)
{
  int fd;
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

#ifdef _MSC_VER
  mode |= _O_BINARY;
#endif

  fd = open(filename,mode,0666);
  if (fd == -1) {
    fprintf(stderr,"Can't open %s,errno %d : %s\n",filename,errno,strerror(errno));
    return -1;
  }

  is_locked = file_islocked(fd,F_WRLCK);

  if (is_locked == -1) {
    out_log(LEVEL_NORMAL,"Could not get lock info\n");
  }
  else {
    if ( mode & O_WRONLY ) {
      if (is_locked) {
        close(fd);
/*        fprintf(stderr,"Can't open %s in write mode, locked !\n",filename);*/
        return -1;
      }
      file_lock(fd,F_WRLCK);
    }
    else {
      if (is_locked) {
/*	fprintf(stderr,"%s is locked, trying to read\n",filename);*/
        if ( CFG_GET_OPTION(mainConfig,CFG_OPT_DENY_ACCESS_FILES_UPLOADED) ) {
          close(fd);
          return -1;
        }
      }
    }
  }

  return fd;
}

/*void file_close(FILE *fp, wzd_context_t * context)*/
void file_close(int fd, wzd_context_t * context)
{
/*  fclose(fp);*/
  close(fd);
}

off_t file_seek(int fd, unsigned long offset, int whence)
{
  return lseek(fd,offset,whence);
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
  wzd_user_t * user;
  
  user = GetUserByID(context->userid);

  ret = _checkPerm(dirname,RIGHT_MKDIR,user);
  if (ret) return -1;
  ret = mkdir(dirname,0755);

  return ret;
}

/** @brief remove directory.
 *
 * dirname must be an absolute path
 */
int file_rmdir(const char *dirname, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  struct stat s;
  
  user = GetUserByID(context->userid);

  ret = _checkPerm(dirname,RIGHT_RMDIR,user);
  if (ret) return -1;

  /* is a directory ? */
  if (stat(dirname,&s)) return -1;
  if (!S_ISDIR(s.st_mode)) return -1;

  /* is dir empty ? */
  {
#ifndef _MSC_VER
    DIR * dir;
    struct dirent *entr;
#else
    HANDLE dir;
    WIN32_FIND_DATA fileData;
    int finished;
    char dirfilter[2048];
#endif
    char path_perm[2048];
    const char *filename;

#ifndef _MSC_VER
    if ((dir=opendir(dirname))==NULL) return 0;
#else
    snprintf(dirfilter,2048,"%s/*",dirname);
    if ((dir = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return 0;
#endif
    
#ifndef _MSC_VER
    while ((entr=readdir(dir))!=NULL) {
      filename = entr->d_name;
#else
    finished = 0;
    while (!finished) {
      filename = fileData.cFileName;
#endif
      if (strcmp(filename,".")==0 ||
          strcmp(filename,"..")==0 ||
          strcmp(filename,HARD_PERMFILE)==0) /* XXX hide perm file ! */
        DIR_CONTINUE
      closedir(dir);
      return 1; /* dir not empty */
    }

    closedir(dir);

    /* remove permission file */
    strcpy(path_perm,dirname); /* path is already ended by / */
    if (path_perm[strlen(path_perm)-1] != '/')
      strcat(path_perm,"/");
    (void)strlcat(path_perm,HARD_PERMFILE,sizeof(path_perm));
    unlink(path_perm);
  }

#ifdef DEBUG
fprintf(stderr,"Removing directory '%s'\n",dirname);
#endif

#ifndef __CYGWIN__
  {
    struct stat s;
    lstat(dirname,&s);
    if (S_ISLNK(s.st_mode))
      return unlink(dirname);
  }
#endif
  return rmdir(dirname);

}

/** RENAME
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
fprintf(stderr,"rename error %d (%s)\n", errno, strerror(errno));
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

    /* check in special permissions from config file */
    if (perm_check("delete", context, mainConfig) == 0) ret = 0; /* specified in config file */

  }
  
  if (ret)
    return 1;

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
fprintf(stderr,"remove error %d (%s)\n", errno, strerror(errno));
#endif
    return 1;
  }

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
  struct stat s;

  if (stat(filename,&s))
    return NULL;

  /* find the dir containing the perms file */
  strncpy(perm_filename,filename,BUFFER_LEN);
  ptr = strrchr(perm_filename,'/');
  if (!ptr || *(ptr+1)=='\0') return NULL;

  if (S_ISDIR(s.st_mode)) { /* isdir */
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

struct wzd_file_t * file_stat(const char *filename, wzd_context_t * context)
{
  char perm_filename[WZD_MAX_PATH+1];
  char stripped_filename[WZD_MAX_PATH+1];
  char * ptr;
  struct wzd_file_t * file_list=NULL, * file_cur, *file;
  size_t neededlength, length;
  struct stat s;
  int nx=0;

  /** \bug no no no, it can be a symlink or a vfs ! */
/*  if (stat(filename,&s))
    return NULL;*/

  file = NULL;

  /* find the dir containing the perms file */
  strncpy(perm_filename,filename,WZD_MAX_PATH);
  length = strlen(perm_filename);
  if (length >1 && perm_filename[length-1]=='/')
    perm_filename[--length] = '\0';
  ptr = strrchr(perm_filename,'/');
  if (!ptr || *(ptr+1)=='\0') return NULL;

  if (!lstat(filename,&s)) {
    if (S_ISDIR(s.st_mode)) { /* isdir */
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
      if (lstat(perm_filename,&s)) {
        out_err(LEVEL_FLOOD, "symlink: destination directory does not exist (%s)\n", perm_filename);
        return NULL;
      }
    }
  } /* ! isdir */


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
  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);

  if ( ! readPermFile(perm_filename,&file_list) ) {
    /* we have a permission file */
    file_cur = find_file(stripped_filename, file_list);
    if (file_cur)
      file = file_deep_copy(file_cur);
    free_file_recursive(file_list);
  }

  if (!file && nx) return NULL;

  return file;
}

/* if program crash, locks acquired by fcntl (POSIX) or _locking (VISUAL)
 * are released, and then do are less annoying.
 */
int file_lock(int fd, short lock_mode)
{
#ifdef WZD_DBG_LOCK
fprintf(stderr,"Locking file %d\n",fd);
#endif
#ifndef _MSC_VER
  struct flock lck;
  lck.l_type = lock_mode;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;
  if (fcntl(fd, F_SETLK, &lck) < 0) {
    return -1;
  }
#else
  if (_locking(fd, LK_NBLCK, -1) == -1)
    return -1;
#endif
  return 0;
}

int file_unlock(int fd)
{
#ifdef WZD_DBG_LOCK
fprintf(stderr,"Unlocking file %d\n",fd);
#endif
#ifndef _MSC_VER
  struct flock lck;
  lck.l_type = F_UNLCK;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;
  if (fcntl(fd, F_SETLK, &lck) < 0) {
    return -1;
  }
#else
  if (_locking(fd, LK_UNLCK, -1) == -1)
    return -1;
#endif
  return 0;
}

int file_islocked(int fd, short lock_mode)
{
#ifdef WZD_DBG_LOCK
fprintf(stderr,"Testing lock for file %d\n",fd);
#endif
#ifndef _MSC_VER
  struct flock lck;
  lck.l_type = lock_mode;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;

  if (fcntl(fd, F_GETLK, &lck) < 0) {
    return -1;
  }
  if (lck.l_type == F_RDLCK || lck.l_type == F_WRLCK) return 1;
#else
  if (_locking(fd, LK_NBLCK, -1) != -1) {
    _locking(fd, LK_UNLCK, -1);
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
  int fd;
#ifdef WZD_DBG_LOCK
fprintf(stderr,"Forcing unlock file %s\n",file);
#endif

  fd = open(file,O_RDWR);
  if (fd < 0) return -1;

#ifndef _MSC_VER
  {
    struct flock lck;
    lck.l_type = F_UNLCK;
    lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
    lck.l_start = 0;
    lck.l_len = 0;
    if (fcntl(fd, F_SETLK, &lck) < 0) {
      close(fd);
      return -1;
    }
  }
#else
  if (_locking(fd, LK_UNLCK, -1) == -1)
  {
    close(fd);
    return -1;
  }
#endif
  close(fd);
  return 0;
}

/* wrappers just to keep things in same memory zones */
ssize_t file_read(int fd,void *data,size_t length)
{
  return read(fd,data,length);
}

ssize_t file_write(int fd,const void *data,size_t length)
{
  return write(fd,data,length);
}

/* symlink operations */

/** \brief create symlink
 * paths must be absolute
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
  struct stat s;

  if (lstat(link,&s)) return E_FILE_NOEXIST;
  if ( !S_ISLNK(s.st_mode) ) return E_FILE_TYPE;
  return unlink(link);
#else
  return softlink_remove(link);
/*  return RemoveJunctionPoint(link);*/
#endif
}
