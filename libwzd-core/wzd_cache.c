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

#if defined(WIN32) || (defined  __CYGWIN__ && defined WINSOCK_SUPPORT)
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#include <io.h>
#else
#include <unistd.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

#include "wzd_cache.h"


#include "wzd_structs.h"
#include "wzd_fs.h"
#include "wzd_group.h"
#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

#define MAX_CACHE_FILE_LEN	32768

typedef struct wzd_internal_cache_t wzd_internal_cache_t;

/** @brief File cache: file descriptor, size, etc.
 *
 * \internal
 * do not use directly
 */
struct wzd_internal_cache_t  {
  int fd;

  unsigned long filename_hash;
  off_t datasize;
  time_t mtime;
  unsigned short use;

  char * data;

  wzd_internal_cache_t * next_cache;
};

struct wzd_cache_t {
  off_t current_location;

  wzd_internal_cache_t * cache;
};

static wzd_internal_cache_t *global_cache=NULL;

#ifdef ENABLE_CACHE
static wzd_cache_t* _cache_refresh(wzd_internal_cache_t *c, const char *file, int flags, unsigned int mode);


static wzd_internal_cache_t * _cache_find(unsigned long hash)
{
  wzd_internal_cache_t * current_cache = global_cache;

  while (current_cache)
  {
    if (hash==current_cache->filename_hash) return current_cache;
    current_cache = current_cache->next_cache;
  }

  return NULL;
}
#endif /* ENABLE_CACHE */

off_t wzd_cache_getsize(wzd_cache_t *c)
{
  if (c == NULL) return -1;
  return c->cache->datasize;
}

wzd_cache_t * wzd_cache_open(const char *file, int flags, unsigned int mode)
{
#ifdef ENABLE_CACHE
  wzd_cache_t * cache;
  wzd_internal_cache_t * c;
  fs_filestat_t s;
  unsigned long hash;
  size_t ret;
  size_t length;
  size_t size;
  int fd;

  if (!file) return NULL;

  hash = compute_hashval(file,strlen(file));
/*  out_err(LEVEL_FLOOD,"HASH %s: %lu\n",file,hash);*/

#ifdef _MSC_VER
  flags |= _O_BINARY;
#endif

  fd = fs_open(file,flags,mode);
  if (fd==-1) return NULL;

  if (fs_file_fstat(fd,&s)) { close(fd); return NULL; }
  FD_REGISTER(fd,"Cached file");

  WZD_MUTEX_LOCK(SET_MUTEX_CACHE);

  c = _cache_find(hash);
  if (c) {
    close(fd);
    FD_UNREGISTER(fd,"Cached file");
    /* detect if file has changed */
    if (s.size != c->datasize || s.mtime > c->mtime) {
      /* REFRESH */
      /* need refresh */
/*      out_err(LEVEL_FLOOD,"cache entry need refresh\n");*/
#ifdef WZD_DBG_CACHE
      out_err(LEVEL_HIGH,"Cache REFRESH %s\n",file);
#endif
      /* _cache_refresh will unlock SET_MUTEX_CACHE */
      return _cache_refresh(c,file,flags,mode);
    }
    /* HIT */
    (void)lseek(c->fd,0,SEEK_SET);
    cache = malloc(sizeof(wzd_cache_t));
    cache->current_location = 0;
    cache->cache = c;
    c->use++;
#ifdef WZD_DBG_CACHE
    out_err(LEVEL_FLOOD,"Cache HIT %s\n",file);
#endif
    WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
    return cache;
  }

  /* MISS */
#ifdef WZD_DBG_CACHE
  out_err(LEVEL_FLOOD,"Cache MISS %s (%d)\n",file,fd);
#endif

  cache = (wzd_cache_t*)malloc(sizeof(wzd_cache_t));
  c = malloc(sizeof(wzd_internal_cache_t));
  c->fd = fd;
  c->filename_hash = hash;
  c->use = 2;
  c->mtime = s.mtime;
  cache->cache = c;
  cache->current_location = 0;
  size = s.size;
  if (size > MAX_CACHE_FILE_LEN) {
    out_err(LEVEL_FLOOD,"File too big to be stored in cache (%ld bytes)\n",(long)size);
    c->data = NULL;
    c->datasize = 0;
  } else {
    length = size;
    c->data = malloc(length+1);
    if ( (ret=read(fd,c->data,length)) != length ) {
      out_err(LEVEL_FLOOD,"Read only %ld bytes on %ld required\n",(long)ret,(long)length);
    }
    c->data[length] = '\0';
    c->datasize = length;
    /* we can close the fd here */
    close(c->fd);
    FD_UNREGISTER(c->fd,"Cached file");
    c->fd = -1;
  }
  c->next_cache = global_cache;
  global_cache = c;

  WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
  return cache;
#else /* ENABLE_CACHE */

  fs_filestat_t st;
  wzd_cache_t * cache;
  wzd_internal_cache_t * c;
  int fd;

  if (!file) return NULL;

#ifdef _MSC_VER
  flags |= _O_BINARY;
#endif

  fd = fs_open(file,flags,mode);
  if (fd==-1) return NULL;

  if (fs_file_fstat(fd,&st)) { close(fd); return NULL; }
  FD_REGISTER(fd,"Cached file");

  cache = (wzd_cache_t*)malloc(sizeof(wzd_cache_t));
  c = malloc(sizeof(wzd_internal_cache_t));
  c->fd = fd;
  c->filename_hash = 0;
  c->use = 1;
  c->mtime = st.mtime;
  cache->cache = c;
  cache->current_location = 0;
  c->datasize = st.size;
  c->data = NULL;

  return cache;

#endif /* ENABLE_CACHE */
}


/** \brief refresh file in cache
 *
 * MUST be called with SET_MUTEX_CACHE locked !
 */
wzd_cache_t* _cache_refresh(wzd_internal_cache_t *c, const char *file, int flags, unsigned int mode)
{
#ifdef ENABLE_CACHE
  wzd_cache_t * cache;
  fs_filestat_t s;
  unsigned long hash;
  size_t length, ret;
  int fd;

  hash = compute_hashval(file,strlen(file));

  fd = fs_open(file,flags,mode);
  if (fd==-1) {
    WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
    return NULL;
  }

  if (fs_file_fstat(fd,&s)) {
    close(fd);
    WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
    return NULL;
  }
  FD_REGISTER(fd,"Cached file");

  if (c->fd != -1) { close(c->fd); FD_UNREGISTER(c->fd,"Cached file"); }
  if (c->data) free(c->data);

  cache = malloc(sizeof(wzd_cache_t));
  c->fd = fd;
  c->filename_hash = hash;
  c->mtime = s.mtime;
  cache->cache = c;
  cache->current_location = 0;
  length = s.size;
  c->use++;
  if (length > MAX_CACHE_FILE_LEN) {
    out_err(LEVEL_FLOOD,"File too big to be stored in cache (%ld bytes)\n",(long)length);
    c->data = NULL;
    c->datasize = 0;
  } else {
    c->data = malloc(length);
    if ( (ret=read(fd,c->data,length)) != length ) {
      out_err(LEVEL_FLOOD,"Read only %ld bytes\n",(long)ret);
    }
    c->datasize = length;
    /* we can close the fd here */
    close(c->fd);
    FD_UNREGISTER(c->fd,"Cached file");
    c->fd = -1;
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
  return cache;

#else /* ENABLE_CACHE */

  fs_filestat_t st;
  wzd_cache_t * cache;
  wzd_internal_cache_t c2, c_old;
  int fd;

  if (!file) return NULL;

#ifdef _MSC_VER
  flags |= _O_BINARY;
#endif

  fd = fs_open(file,flags,mode);
  if (fd==-1) return NULL;

  if (fs_file_fstat(fd,&st)) { close(fd); return NULL; }
  FD_REGISTER(fd,"Cached file");

  cache = (wzd_cache_t*)malloc(sizeof(wzd_cache_t));
  c2.fd = fd;
  c2.filename_hash = 0;
  c2.use = 1;
  c2.mtime = st.mtime;
  cache->cache = c;
  cache->current_location = 0;
  c->datasize = st.size;
  c2.data = NULL;

  /* atomic part */
  memcpy(&c_old, c, sizeof(wzd_internal_cache_t));
  memcpy(c, &c2, sizeof(wzd_internal_cache_t));

  if (c_old.fd) {
    FD_UNREGISTER(c_old.fd, "Cached file");
    close(c_old.fd);
  }
  if (c_old.data) free(c_old.data);

  return cache;

#endif /* ENABLE_CACHE */
}

/** force update of specific file, only if present in cache */
void wzd_cache_update(const char *file)
{
#ifdef ENABLE_CACHE
  wzd_internal_cache_t * c;
  unsigned long hash;

  hash = compute_hashval(file,strlen(file));
/*  out_err(LEVEL_FLOOD,"HASH %s: %lu\n",file,hash);*/

  WZD_MUTEX_LOCK(SET_MUTEX_CACHE);

  c = _cache_find(hash);
  if (c) {
    /* REFRESH */
    /* need refresh */
/*    out_err(LEVEL_FLOOD,"cache refresh forced\n");*/
    (void)_cache_refresh(c,file,O_RDONLY,0600);
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);

#else /* ENABLE_CACHE */

  out_err(LEVEL_HIGH,"*** warning *** call to %s\n",__FUNCTION__);

#endif /* ENABLE_CACHE */
}


/** @brief Read data from cached file
 *
 * we do not need to lock SET_MUTEX_CACHE as this function is reentrant
 */
ssize_t wzd_cache_read(wzd_cache_t * c, void *buf, size_t count)
{
  ssize_t ret;
  wzd_internal_cache_t * cache;
  cache = c->cache;
/*  out_err(LEVEL_FLOOD,"cache read\n");*/
  /* if in cache, read data and pay attention to size ! */
  /* is file stored in cache ? */
#ifdef ENABLE_CACHE
  if (cache->data) {
    if ( (c->current_location+count) <= cache->datasize ) {
      memcpy(buf,cache->data + c->current_location,count);
      c->current_location += count;
      return count;
    }
    memcpy(buf,cache->data + c->current_location,cache->datasize-c->current_location);
    c->current_location = cache->datasize;
    return cache->datasize-c->current_location;
  } else { /* not in cache */
#endif
    /* update current_location */
    if (c) {
      ret = read( cache->fd, buf, count );
      if (ret>0) c->current_location += ret;
      return ret;
    }
#ifdef ENABLE_CACHE
  } /* file in cache ? */
#endif
  return -1;
}

ssize_t wzd_cache_write(wzd_cache_t * c, void *buf, size_t count)
{
#ifdef ENABLE_CACHE
  ssize_t ret;
#endif

  wzd_internal_cache_t * cache;
  cache = c->cache;
  out_err(LEVEL_FLOOD,"cache write\n");
  /* update current_location */
#ifdef ENABLE_CACHE
  if (c) {
    /** \todo if in cache, warn user it is rather stupid to cache a file
      * to be modified, and re-open it in non-cache mode
      */
    if (cache->data) {
      out_err(LEVEL_INFO,"Trying to write a cached file - stupid !\n");
      return -1;
    }
    ret = write( cache->fd, buf, count );
    if (ret>0) c->current_location += ret;
    return ret;
  }
#endif
  return -1;
}

/** @brief Read a line from cached file
 *
 * we do not need to lock SET_MUTEX_CACHE as this function is reentrant
 */
char * wzd_cache_gets(wzd_cache_t * c, char *buf, unsigned int size)
{
  off_t position;
  int fd;
  char buffer[4096], *ptr, *dst;
  char _c=0;
  ssize_t ret;
  unsigned long size_to_read;
  wzd_internal_cache_t * cache;

  if (!c) return NULL;

  cache = c->cache;
  fd = cache->fd;
  /* is file stored in cache ? */
#ifdef ENABLE_CACHE
  if (cache->data) {
    /* get start position */
    position = c->current_location;

    /* read buffer */
    ptr = buffer;
    dst = buf;
    size_to_read = (size<4096)?size:4096;
/*    ret = read(fd,buffer,size_to_read);*/
    if (c->current_location + size_to_read > cache->datasize) {
      size_to_read = cache->datasize - c->current_location; /* XXX -1 ? */
    }
    if (c->current_location >= cache->datasize) return NULL;
    memcpy(buffer,cache->data+c->current_location,size_to_read);
/*    c->current_location += size_to_read;*/
    while (--size>0 && (_c=(*ptr++)) != (char)EOF)
    {
      if ( (*dst++ = _c)=='\n' )
        break;
      if ( --size_to_read == 0 ) {
        size_to_read = (size<4096)?size:4096;
/*	      ret = read(fd,buffer,size_to_read);*/
        if (c->current_location + size_to_read > cache->datasize) {
          size_to_read = cache->datasize - c->current_location; /* XXX -1 ? */
        }
      if (c->current_location + size_to_read > cache->datasize) return NULL;
      memcpy(buffer,cache->data+c->current_location,size_to_read);
/*      c->current_location += size_to_read;*/
      ptr = buffer;
      break;
/*      if (ret < 0) return NULL;*/
      }
    }
    c->current_location += size_to_read;
    *dst=0;
    if (_c==(char)EOF && ptr==buf) return NULL;
/*    lseek(fd,position + (dst-buf), SEEK_SET );*/
    c->current_location = position + (dst-buf);

  } else { /* file is not in cache ! */
#endif

    /* get start position */
    position = lseek(fd,0,SEEK_CUR);

    /* read buffer */
    ptr = buffer;
    dst = buf;
    size_to_read = (size<4096)?size:4096;
    ret = read(fd,buffer,size_to_read);
    if (ret <= 0) return NULL;
    while (--size>0 && (_c=(*ptr++)) != (char)EOF)
    {
      if ( (*dst++ = _c)=='\n' )
        break;
      if ( --size_to_read == 0 ) {
        size_to_read = (size<4096)?size:4096;
        ret = read(fd,buffer,size_to_read);
        ptr = buffer;
        if (ret < 0) return NULL;
      }
    }
    *dst=0;
    if (_c==(char)EOF && ptr==buf) return NULL;
    (void)lseek(fd,position + (dst-buf), SEEK_SET );
    /* update current_location */
    c->current_location += strlen(buf);
#ifdef ENABLE_CACHE
  } /* file in cache ? */
#endif

  return buf;
}

void wzd_cache_close(wzd_cache_t * c)
{
  WZD_MUTEX_LOCK(SET_MUTEX_CACHE);
  if (c) {
    c->cache->use--;
    /** \bug XXX FIXME possible leak here if big file, fd is not closed */
    if (c->cache->use == 0) {
      if (c->cache->fd >= 0) {
        out_err(LEVEL_FLOOD,"Closing file %d\n",c->cache->fd);
        FD_UNREGISTER(c->cache->fd,"Cached file");
        close( c->cache->fd );
      }
      free( c-> cache );
      c->cache = NULL;
    }
  }
  free(c);
  WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
}

void wzd_cache_purge(void)
{
  wzd_internal_cache_t * cache_current, * cache_next;

  WZD_MUTEX_LOCK(SET_MUTEX_CACHE);

  cache_current = global_cache;
  while (cache_current)
  {
    cache_next = cache_current->next_cache;
    /* free data */
    if (cache_current->data) {
      free(cache_current->data);
      cache_current->data=NULL;
    }
    if (cache_current->fd != -1) {
      close(cache_current->fd);
      FD_UNREGISTER(cache_current->fd,"Cached file");
      cache_current->fd = -1;
    }
    free(cache_current);
    cache_current = cache_next;
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_CACHE);
}

/** Open file in cache, read it and return contents
 *
 * *buffer must be freed using wzd_free() if not NULL.
 *
 * \param[in] filename Absolute path to file
 * \param[out] buffer Address of a char *, which will store the contents of the file
 * \param[out] size Address of a size_t, which will store the length of the file
 *
 * \return 0 if ok
 */
int wzd_cache_read_file_fast(const char * filename, char ** buffer, size_t * size)
{
  wzd_cache_t * fp;
  u64_t sz64;
  char * file_buffer;
  unsigned long filesize, size_read;

  fp = wzd_cache_open(filename, O_RDONLY, 0644);
  if (fp == NULL) return -1;

  sz64 = wzd_cache_getsize(fp);
  if (sz64 > INT_MAX) {
    out_log(LEVEL_HIGH,"ERROR: wzd_cache_read_file_fast: file %s is too big to be read\n",filename);
    wzd_cache_close(fp);
    return -1;
  }

  filesize = (unsigned int) sz64;
  file_buffer = wzd_malloc(filesize+1);
  if ( file_buffer == NULL) {
    out_log(LEVEL_HIGH,"ERROR: wzd_cache_read_file_fast: couldn't allocate %ld bytes for file %s\n",filesize+1,filename);
    wzd_cache_close(fp);
    return -1;
  }

  size_read = wzd_cache_read(fp,file_buffer,filesize);
  if ( size_read != filesize ) {
    out_log(LEVEL_HIGH,"ERROR: wzd_cache_read_file_fast: read %ld bytes instead of %ld for file %s\n",size_read,filesize,filename);
    wzd_cache_close(fp);
    return -1;
  }

  file_buffer[filesize]='\0';
  wzd_cache_close(fp);

  *buffer = file_buffer;
  *size = size_read;

  return 0;
}

