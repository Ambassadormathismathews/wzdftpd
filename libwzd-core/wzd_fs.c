/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <wchar.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_utf8.h"

#include "wzd_fs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

struct fs_fileinfo_t {
  char * name;
#ifdef WIN32
  wchar_t * wname;
#endif
};

struct fs_dir_t {
  void * handle;
  char * dirname;
#ifdef WIN32
  WIN32_FIND_DATAW entry;
#endif
  fs_fileinfo_t finfo;
};


/** \brief Open/create a file
 *
 * pathname should be UTF-8 encoded, or will be converted to Unicode.
 */
fd_t fs_open(const char *filename, int mode, int permission, int *err) {
}

/** \brief Close an open file handle
 */
void fs_close(fd_t fd) {
}

/** \brief Read from a file
 */
ssize_t fs_read(fd_t fd, void *buffer, size_t size) {
}

/** \brief Write to a file
 */
ssize_t fs_write(fd_t fd, const void *buffer, size_t size) {
}

/** \brief Remove a file
 *
 * filename should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_unlink(const char *filename, int *err) {
}

/** \brief chmod a file
 *
 * filename should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_chmod(const char *filename, int permission, int *err) {
}

/** \brief Rename a file/directory
 *
 * src should be UTF-8 encoded, or will be converted to Unicode.
 * dst should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_rename(const char *src, const char *dst, int *err) {
}


/** \brief Create a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to Unicode.
 *
 * \return -1 on error, and set \a err to errno
 */
int fs_mkdir(const char *pathname, unsigned long mode, int *err) {
  int ret;

#ifndef WIN32
  ret = mkdir(pathname,mode);
  if (err && (ret < 0)) *err = errno;
#else
  {
    int sz;
    wchar_t * dstname;

    if (!utf8_valid(pathname,strlen(pathname)))
      return -1;

    sz = MultiByteToWideChar(CP_UTF8, 0, pathname, (int)strlen(pathname)+1, NULL, 0);
    if (sz <= 0) return -1;

    dstname = malloc((size_t)sz * sizeof(wchar_t) + 1);

    ret = MultiByteToWideChar(CP_UTF8, 0, pathname, (int)strlen(pathname)+1, dstname, sz);

    if (ret <= 0) { free(dstname); return -1; }

    ret = _wmkdir(dstname);
    if (err && (ret < 0)) *err = errno;

    free(dstname);
  }
#endif

  return ret;
}

/** \brief Remove a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_rmdir(const char *pathname, int *err) {
}

/** \brief Open a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_dir_open(const char *pathname, fs_dir_t **newdir) {
  size_t len;

  *newdir = wzd_malloc(sizeof(fs_dir_t));

  (*newdir)->dirname = wzd_malloc(strlen(pathname)+3);
  strncpy((*newdir)->dirname,pathname,strlen(pathname)+2);
  (*newdir)->handle = NULL;
  (*newdir)->finfo.name = NULL;

  /* ensure pathname is / terminated */
  len = strlen(pathname);
  if ( len && (*newdir)->dirname[len-1] != '/' ) {
    (*newdir)->dirname[len++] = '/';
    (*newdir)->dirname[len] = '\0';
  }

  return 0;
}

/** \brief Close a directory
 */
int fs_dir_close(fs_dir_t* dir) {
  int ret = 0;

  /* dir->finfo.name may not be allocated yet, so we have to double check */
  if (dir->finfo.name) wzd_free(dir->finfo.name);

#ifdef WIN32
  if (dir->handle != NULL && !FindClose(dir->handle))
    ret = -1;
#else
  if (dir->handle != NULL && !closedir(dir->handle))
    ret = -1;
#endif
  dir->handle = NULL;
  wzd_free(dir->dirname);

  wzd_free(dir);

  return ret;
}

/** \brief Read a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_dir_read(fs_dir_t *dir, fs_fileinfo_t **fileinfo) {
  char * filename = NULL; /* UTF-8 ! */

#ifdef WIN32
  int ret;
  int sz;

  if (dir->handle == NULL) {
    wchar_t * dstname, * eos;

    sz = MultiByteToWideChar(CP_UTF8, 0, dir->dirname, (int)strlen(dir->dirname)+1, NULL, 0);
    if (sz <= 0) return -1;

    dstname = malloc((size_t)sz * sizeof(wchar_t) + 3);

    ret = MultiByteToWideChar(CP_UTF8, 0, dir->dirname, (int)strlen(dir->dirname)+1, dstname, sz);

    if (ret <= 0) { free(dstname); return -1; }

    /* build filter */
    eos = wcschr(dstname,'\0');
    eos[0] = '*';
    eos[1] = '\0';
    
    dir->handle = FindFirstFileW(dstname,&(dir->entry));
    /* make sure that we actually have a valid handle */
    if (dir->handle == INVALID_HANDLE_VALUE) {
      free(dstname);
      return -1;
    }
    eos[0] = '\0';
    free(dstname);
  }
  else if (!FindNextFileW(dir->handle,&(dir->entry))) {
    return -1;
  }

  sz = WideCharToMultiByte(CP_UTF8, 0, dir->entry.cFileName, (int)wcslen(dir->entry.cFileName)+1, NULL, 0, NULL, NULL);
  if (sz <= 0) return -1;

  filename = wzd_malloc((size_t)sz + 2);

  ret = WideCharToMultiByte(CP_UTF8, 0, dir->entry.cFileName, (int)wcslen(dir->entry.cFileName)+1, filename, sz, NULL, NULL);

  dir->finfo.wname = dir->entry.cFileName;
#else
  {
    struct dirent * dt;

    if (!dir->handle) {
      dir->handle = opendir(dir->dirname);
      if (!dir->handle) return -1;
    }

    dt = readdir(dir->handle);
    if (!dt) return -1;

    filename = wzd_strdup(dt->d_name);
  }
#endif


  /* sanity check to make sure dir->finfo.name is actually allocated */
  if (dir->finfo.name) wzd_free(dir->finfo.name);
  dir->finfo.name = filename;


  if (fileinfo)
    *fileinfo = &dir->finfo;

  return 0;
}

/** \brief Get information about the attributes of a file, following symbolic links
 *
 * filename must be an absolute path.
 * filename should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_file_stat(const char *filename, fs_filestat_t *s, int *err) {
#ifndef WIN32
  struct stat st;

  if (!stat(pathname,&st)) {
    if (s) {
      s->size = (u64_t)st.st_size;
      s->mode = st.st_mode;
      s->mtime = st.st_mtime;
      s->ctime = st.st_ctime;
      s->nlink = st.st_nlink;
      return 0;
    }
  }
  return -1;
#else
  struct _stati64 st;
  wchar_t * wbuffer;
  int sz;
  int ret;

  sz = MultiByteToWideChar(CP_UTF8, 0, pathname, (int)strlen(pathname)+1, NULL, 0);
  if (sz <= 0) return -1;

  wbuffer = malloc((size_t)sz * sizeof(wchar_t) + 5);

  ret = MultiByteToWideChar(CP_UTF8, 0, pathname, (int)strlen(pathname)+1, wbuffer, sz);
  if (ret <= 0) { free(wbuffer); return -1; }

  if( strlen(pathname)==2 && pathname[1]==':' ) wcscat(wbuffer,L"/");

  ret = -1;
  if (!_wstati64(wbuffer,&st)) {
    if (s) {
      s->size = st.st_size;
      s->mode = st.st_mode;
      s->mtime = st.st_mtime;
      s->ctime = st.st_ctime;
      s->nlink = st.st_nlink;
      ret = 0;
    }
  }
  free(wbuffer);
  return ret;
#endif
}

/** \brief Get information about the attributes of a file, not following symbolic links
 *
 * filename must be an absolute path.
 * filename should be UTF-8 encoded, or will be converted to Unicode.
 */
int fs_file_lstat(const char *filename, fs_filestat_t *s, int *err) {
#ifndef WIN32
  struct stat st;

  if (!lstat(pathname,&st)) {
    if (s) {
      s->size = (u64_t)st.st_size;
      s->mode = st.st_mode;
      s->mtime = st.st_mtime;
      s->ctime = st.st_ctime;
      s->nlink = st.st_nlink;
      return 0;
    }
  }
  return -1;
#else
  struct _stati64 st;
  wchar_t * wbuffer;
  int sz;
  int ret;

  sz = MultiByteToWideChar(CP_UTF8, 0, pathname, (int)strlen(pathname)+1, NULL, 0);
  if (sz <= 0) return -1;

  wbuffer = malloc((size_t)sz * sizeof(wchar_t) + 5);

  ret = MultiByteToWideChar(CP_UTF8, 0, pathname, (int)strlen(pathname)+1, wbuffer, sz);
  if (ret <= 0) { free(wbuffer); return -1; }

  if( strlen(pathname)==2 && pathname[1]==':' ) wcscat(wbuffer,L"/");

  ret = -1;
  if (!_wstati64(wbuffer,&st)) {
    if (s) {
      s->size = st.st_size;
      s->mode = st.st_mode;
      s->mtime = st.st_mtime;
      s->ctime = st.st_ctime;
      s->nlink = st.st_nlink;
      ret = 0;
    }
  }
  free(wbuffer);
  return ret;
#endif
}

/** \brief Get information about the attributes of a file, following symbolic links
 */
int fs_file_fstat(fd_t file, fs_filestat_t *s, int *err) {
#ifndef WIN32
  struct stat st;

  if (!fstat(file,&st)) {
    if (s) {
      s->size = (u64_t)st.st_size;
      s->mode = st.st_mode;
      s->mtime = st.st_mtime;
      s->ctime = st.st_ctime;
      s->nlink = st.st_nlink;
      return 0;
    }
  }
  return -1;
#else
  struct _stati64 st;

  if (!_fstati64(file,&st)) {
    if (s) {
      s->size = st.st_size;
      s->mode = st.st_mode;
      s->mtime = st.st_mtime;
      s->ctime = st.st_ctime;
      s->nlink = st.st_nlink;
      return 0;
    }
  }
  return -1;
#endif
}


const char * fs_fileinfo_getname(fs_fileinfo_t * finfo)
{
  return finfo->name;
}




