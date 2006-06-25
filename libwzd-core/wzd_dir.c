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

/** \file wzd_dir.c
  * \brief Utilities functions to manipulate file and dir names
  */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef WIN32
#include <winsock2.h>
#include <io.h>
#include <direct.h> /* _mkdir */
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

#include "wzd_file.h"
#include "wzd_fs.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_dir.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

struct wzd_dir_t * dir_open(const char *name, wzd_context_t * context)
{
  struct wzd_dir_t * _dir=NULL;
  struct wzd_file_t * entry, * it, *itp, ** insertion_point;
  struct wzd_file_t * perm_list = NULL;
  wzd_vfs_t * vfs = mainConfig->vfs;
  short vfs_pad=0; /* is 1 if name has a trailing '/' */
  char * perm_file_name;
  size_t length;
  char * ptr;
  const char * dir_filename;
  char buffer_file[WZD_MAX_PATH+1];
  int ret;
  unsigned short sorted = 0;
  unsigned long watchdog = 0;

  fs_dir_t * dir;
  fs_fileinfo_t * finfo;
  fs_filestat_t st;


  if ( fs_dir_open(name,&dir) ) return NULL;

  if (name[strlen(name)-1] != '/') vfs_pad = 1;

  _dir = malloc(sizeof(struct wzd_dir_t));
  _dir->dirname = path_getbasename(name,NULL); /** \bug XXX FIXME if name has a trailing /, this will return "" */
  _dir->first_entry = NULL;

  length = strlen(name);
  perm_file_name = malloc(length+strlen(HARD_PERMFILE)+2);
  memcpy(perm_file_name,name,length);
  ptr = perm_file_name + length - 1;
  if ( *ptr != '/' ) { *++ptr = '/'; }
  ptr++;
  memcpy(ptr,HARD_PERMFILE,strlen(HARD_PERMFILE));
  *(ptr + strlen(HARD_PERMFILE)) = '\0';

  /* try to read permission file */
  if ( (ret=readPermFile(perm_file_name,&perm_list)) && ret != E_FILE_NOEXIST)
    { free(perm_file_name); free(_dir->dirname); free(_dir); return NULL; }
  free(perm_file_name);

  wzd_strncpy(buffer_file, name, WZD_MAX_PATH);
  length = strlen(buffer_file);
  if (length > 1 && buffer_file[length-1] != '/')
  { buffer_file[length] = '/'; buffer_file[++length] = '\0'; }
  ptr = buffer_file + length;

  insertion_point = &_dir->first_entry;

  /* loop on all directory entries and create child structs */
  while ( !fs_dir_read(dir,&finfo) ) {
    dir_filename = fs_fileinfo_getname(finfo);

    if (watchdog++ > 65535) {
      out_log(LEVEL_HIGH, "watchdog: detected infinite loop in dir_open\n");
      fs_dir_close(dir);
      return NULL;
    }

  /* XXX remove hidden files and special entries '.' '..' */

    if (strcmp(dir_filename,".")==0 ||
        strcmp(dir_filename,"..")==0 ||
        is_hidden_file(dir_filename) )
      continue;

    /* search element in list */
    it = perm_list;
    itp = NULL;
    entry = NULL;
    while (it)
    {
      if ( ! DIRCMP(dir_filename,it->filename) )
      {
        /* remove from perm_list and insert at (*insertion_point) */
        if (!itp) { /* first element */
          entry = perm_list;
          perm_list = perm_list->next_file;
          entry->next_file = NULL;
        } else {
          entry = it;
          itp->next_file = it->next_file;
          it->next_file = NULL;
        }
        break;
      }
      itp = it;
      it = it->next_file;
    }


    if (!entry) { /* not listed in permission file */

      /* if entry is a directory, we must query dir for more infos */
      wzd_strncpy(ptr, dir_filename, WZD_MAX_PATH- (ptr-buffer_file));
      if (fs_file_lstat(buffer_file,&st)) {
        /* we have a big problem here ! */
        out_err(LEVEL_HIGH,"lstat(%s) FAILED ! (errno: %d %s)\n",dir_filename,errno,strerror(errno));
        itp = it;
        it = (it)?it->next_file:NULL;
        continue;
      }
      if (S_ISDIR(st.mode)) {
        /* if this is a dir, we look inside the directory for infos
         * NULL here is no problem, if will be handled by the next test
         */
        entry = file_stat(buffer_file, context);
        if (entry) { /* we correct the name (currently .) */
          wzd_strncpy(entry->filename, dir_filename, sizeof(entry->filename));
        }
      }

      if (!entry) {
        entry = wzd_malloc(sizeof(struct wzd_file_t));

        wzd_strncpy(entry->filename,dir_filename,sizeof(entry->filename));
        entry->owner[0] = '\0';
        entry->group[0] = '\0';
        entry->permissions = mainConfig->umask; /** \todo FIXME default permission */
        entry->acl = NULL;
        entry->kind = FILE_NOTSET; /* can be reg file or symlink */
        entry->data = NULL;
        entry->next_file = NULL;
      }
    } /* not listed in permission file */

    if (entry->kind == 3) {
      /* file exist AND is a symlink ?! */
    }

    /* sorted insertion */
    if (sorted) {
      file_insert_sorted(entry,&_dir->first_entry);
    } else {
      (*insertion_point) = entry;
      insertion_point = &entry->next_file;
    }

  } /* for all directory entries */
  fs_dir_close(dir);

  /* add vfs entries */
  {
    char * buffer_vfs = wzd_malloc(WZD_MAX_PATH+1);
    while (vfs)
    {
      if (watchdog++ > 65535) {
        out_log(LEVEL_HIGH, "watchdog: detected infinite loop in dir_open (in vfs)\n");
        return NULL;
      }

      entry = NULL;
      ptr = vfs_replace_cookies(vfs->virtual_dir,context);
      if (!ptr) {
        out_log(LEVEL_CRITICAL,"vfs_replace_cookies returned NULL for %s\n",vfs->virtual_dir);
        vfs = vfs->next_vfs;
        continue;
      }
      wzd_strncpy(buffer_vfs,ptr,WZD_MAX_PATH);
      wzd_free(ptr);
      if (DIRNCMP(buffer_vfs,name,strlen(name))==0)
      { /* ok, we have a candidate. Now check if user is allowed to see it */
        ptr = buffer_vfs + strlen(name) + vfs_pad;
        if (strchr(ptr,'/')==NULL) {
          /* read vfs permissions, set to default if no permissions set */
          entry = file_stat(vfs->physical_dir,context);
          if (!entry) {
            entry = wzd_malloc(sizeof(struct wzd_file_t));
            entry->owner[0] = '\0';
            entry->group[0] = '\0';
            entry->permissions = mainConfig->umask;
            entry->acl = NULL;
          }
          wzd_strncpy(entry->filename,ptr,sizeof(entry->filename));
          entry->kind = FILE_VFS;
          entry->data = wzd_strdup(vfs->physical_dir);
          entry->next_file = NULL;
        }
      }

      if (entry) {
        /* sorted insertion */
        if (sorted) {
          file_insert_sorted(entry,&_dir->first_entry);
        } else {
          (*insertion_point) = entry;
          insertion_point = &entry->next_file;
        }
      }

      vfs = vfs->next_vfs;
    } /* while (vfs) */
    wzd_free(buffer_vfs);
  } /* add vfs entries */

  /* add symlinks */
  {
    it = perm_list;
    itp = NULL;
    while (it)
    {
      if (watchdog++ > 65535) {
        out_log(LEVEL_HIGH, "watchdog: detected infinite loop in dir_open (in symlinks check)\n");
        return NULL;
      }

      if (it->kind == FILE_LNK)
      {
        entry = it;

        if (!itp) { /* first element */
          it = perm_list = perm_list->next_file;
        } else {
          itp->next_file = it->next_file;
          it = itp;
        }
        entry->next_file = NULL;
        /* sorted insertion */
        if (sorted) {
          file_insert_sorted(entry,&_dir->first_entry);
        } else {
          (*insertion_point) = entry;
          insertion_point = &entry->next_file;
        }
        if (it == perm_list) {
          itp = NULL;
          continue;
        }
      }
      else
      {
        /** \todo warn user, useless entries in perm file. clean up ? */
        if (strcmp(it->filename,".") &&
          strcmp(it->filename,"..") &&
          ! is_hidden_file(it->filename) )
            out_log(LEVEL_FLOOD, "permission file for %s: useless entry %s\n", name, it->filename);
      }
      itp = it;
      it = it->next_file;
    }
  } /* add symlinks */

  _dir->current_entry = _dir->first_entry;

  /** \todo these are useless entries */
  free_file_recursive(perm_list);

  return _dir;
}


void dir_close(struct wzd_dir_t * dir)
{
  if (!dir) return;

  if (dir->dirname) free(dir->dirname);
  if (dir->first_entry) free_file_recursive(dir->first_entry);
  free(dir);
}



struct wzd_file_t * dir_read(struct wzd_dir_t * dir, wzd_context_t * context)
{
  struct wzd_file_t * entry;

  if (!dir || !dir->current_entry) return NULL;
  entry = dir->current_entry;
  dir->current_entry = entry->next_file;
  return entry;
}




/* strip non-directory suffix from file name
 * returns file without its trailing /component removed, if name contains
 * no /'s, returns "." (meaning the current directory).
 * caller MUST free memory !
 */
char * path_getdirname(const char *file)
{
  char * dirname;
  const char * ptr;
  unsigned int length;

  if (!file) return NULL;
  ptr = file + strlen(file);
  while ( (ptr > file) && (*ptr != '/')) ptr--;

  if (ptr == file)
  {
    dirname = malloc(2);
    dirname[0] = (*ptr == '/') ? '/' : '.';
    dirname[1] = '\0';
  }
  else
  {
    length = (ptr - file);
    dirname = malloc(length+1);
    strncpy(dirname,file,length);
    dirname[length] = '\0';
  }

  return  dirname;
}

/* \brief strip directory and suffix from filename
 *
 * Return file with any leading directory components removed. If specified,
 * also remove a trailing suffix.
 * Caller MUST free memory !
 */
char * path_getbasename(const char *file, const char *suffix)
{
  char * basename;
  const char * ptr;
  unsigned int length;

  if (!file) return NULL;
  ptr = file + strlen(file);
  while ( (ptr > file) && (*ptr != '/')) ptr--;

  if (ptr == file)
  {
    /* if file starts with '/', skip the '/' and return the name
     * except if it is exactly '/', which we return unmodified
     */
    if (*ptr == '/' && *(ptr+1) != '\0') basename = strdup(file+1);
    else basename = strdup(file);
  }
  else
  {
    length = strlen(file) - (ptr - file);
    basename = malloc(length+1);
    strncpy(basename,ptr+1,length);
    basename[length] = '\0';
  }

  /* remove suffix if specified */
  if (suffix && *suffix != '\0') {
    size_t length_base, length_suffix;
    length_base = strlen(basename);
    length_suffix = strlen(suffix);
    if (length_base >= length_suffix) {
      if (strcmp(basename + length_base - length_suffix, suffix) == 0) {
        *(basename + length_base - length_suffix) = '\0';
      }
    }
  }

  return basename;
}

/* \brief get the trailing n parts of a filename
 *
 * Return file with any leading directory components removed, until
 * it has n components.
 * Caller MUST free memory !
 */
char * path_gettrailingname(const char *file, unsigned int n)
{
  char * name;
  const char * ptr;
  unsigned int length;
  unsigned int count;

  if (!file) return NULL;
  ptr = file + strlen(file);
  count = 0;
  while ( (ptr > file) && (count < n))
  {
    if (*ptr == '/')
      if (++count >= n) break;
    ptr--;
  }

  if (ptr == file)
  {
    /* if file starts with '/', skip the '/' and return the name
     * except if it is exactly '/', which we return unmodified
     */
    if (*ptr == '/' && *(ptr+1) != '\0') name = strdup(file+1);
    else name = strdup(file);
  }
  else
  {
    length = strlen(file) - (ptr - file);
    name = malloc(length+1);
    strncpy(name,ptr+1,length);
    name[length] = '\0';
  }

  return name;
}

/* \brief remove // /./ and /../ from filename
 *
 * Return filename with any useless component removed: double /
 * /./ or /../
 * Modifications does not check that filename is valid.
 * WARNING: this function does NOT check anything on filename, it just
 * operates on the raw string (i.e it is the responsability of the caller
 * eo check that there is no path injection in string
 * (eg: "c:/../d:/pathname" )
 * This function modify filename !
 */
char * path_simplify(char *filename)
{
  int pos, pos2;

  if (!filename) return filename;

  pos = pos2 = 0;

  while(filename[pos] != '\0')
  {
    switch (filename[pos])
    {
      case '/':
        if (filename[pos+1] == '/') ;
        else if ((strncmp(filename + pos, "/./", 3) == 0) ||
            (strcmp(filename + pos, "/.") == 0))
          pos++;
        else if ((strncmp(filename + pos, "/../", 4) == 0) ||
            (strcmp(filename + pos, "/..") == 0))
        {
          if (pos2 > 1)
            pos2--;
          while ((pos2 > 0) && (filename[pos2] != '/'))
            pos2--;
          pos += 2; /* /.. */
          if (filename[pos2] != '/') /* ex: toto/../dir */
            pos++;
        }
        else
        {
          filename[pos2] = '/';
          pos2++;
        }
        break;
      default:
        filename[pos2] = filename[pos];
        pos2++;
    }
    pos++;
  }

  if (pos2 == 0)
  {
    filename[pos2] = '/';
    pos2++;
  }
  filename[pos2] = '\0';

  return filename;
}

