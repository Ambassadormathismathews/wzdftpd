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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "wzd_cache.h"


/* speed up compilation */
#define SSL     void
#define SSL_CTX void

/* struct in_addr */
#if defined __CYGWIN__ && defined WINSOCK_SUPPORT
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"

#define MAX_CACHE_FILE_LEN	32768

struct wzd_cache_t  {
  int fd;

  unsigned long filename_hash;
  unsigned int current_location;
  unsigned int datasize;
  time_t mtime;

  char * data;

  wzd_cache_t * next_cache;
};

wzd_cache_t *global_cache=NULL;

wzd_cache_t * wzd_cache_find(unsigned long hash)
{
  wzd_cache_t * current_cache = global_cache;

  while (current_cache)
  {
    if (hash==current_cache->filename_hash) return current_cache;
    current_cache = current_cache->next_cache;
  }

  return NULL;
}

unsigned int wzd_cache_getsize(wzd_cache_t *c)
{
  if (!c) return (unsigned int)-1;
  return c->datasize;
}

wzd_cache_t * wzd_cache_open(const char *file, int flags, unsigned int mode)
{
  wzd_cache_t * cache;
  struct stat s;
  unsigned long hash;
  unsigned int length, ret;
  int fd;

  hash = compute_hashval(file,strlen(file));
/*  out_err(LEVEL_FLOOD,"HASH %s: %lu\n",file,hash);*/

  if (stat(file,&s)) return NULL;

  cache = wzd_cache_find(hash);
  if (cache) {
    /* detect if file has changed */
    if (s.st_mtime > cache->mtime) {
      /* REFRESH */
      /* need refresh */
/*      out_err(LEVEL_FLOOD,"cache entry need refresh\n");*/
      return wzd_cache_refresh(cache,file,flags,mode);
    }
    /* HIT */
    lseek(cache->fd,0,SEEK_SET);
    cache->current_location = 0;
/*    out_err(LEVEL_FLOOD,"Cache hit for file %s\n",file);*/
    return cache;
  }

  /* MISS */
  fd = open(file,flags,mode);
  if (fd==-1) return NULL;

  cache = (wzd_cache_t*)malloc(sizeof(wzd_cache_t));
  cache->fd = fd;
  cache->filename_hash = hash;
  cache->current_location = 0;
  cache->mtime = s.st_mtime;
  length = s.st_size;
  if (length > MAX_CACHE_FILE_LEN) {
    out_err(LEVEL_FLOOD,"File too big to be stored in cache (%ld bytes)\n",length);
    cache->data = NULL;
    cache->datasize = 0;
  } else {
    cache->data = malloc(length);
    if ( (ret=read(fd,cache->data,length)) != length ) {
      out_err(LEVEL_FLOOD,"Read only %ld bytes\n",ret);
    }
    cache->datasize = length;
    /* we can close the fd here */
    close(cache->fd);
    cache->fd = -1;
  }
  cache->next_cache = global_cache;
  global_cache = cache;
  
  return cache;
}

wzd_cache_t* wzd_cache_refresh(wzd_cache_t *c, const char *file, int flags, unsigned int mode)
{
  struct stat s;
  unsigned long hash;
  unsigned int length, ret;
  int fd;

  hash = compute_hashval(file,strlen(file));

  if (stat(file,&s)) return NULL;

  fd = open(file,flags,mode);
  if (fd==-1) return NULL;

  if (c->fd != -1) close(c->fd);
  if (c->data) free(c->data);

  c->fd = fd;
  c->filename_hash = hash;
  c->current_location = 0;
  c->mtime = s.st_mtime;
  length = s.st_size;
  if (length > MAX_CACHE_FILE_LEN) {
    out_err(LEVEL_FLOOD,"File too big to be stored in cache (%ld bytes)\n",length);
    c->data = NULL;
    c->datasize = 0;
  } else {
    c->data = malloc(length);
    if ( (ret=read(fd,c->data,length)) != length ) {
      out_err(LEVEL_FLOOD,"Read only %ld bytes\n",ret);
    }
    c->datasize = length;
    /* we can close the fd here */
    close(c->fd);
    c->fd = -1;
  }
  
  return c;

}

int wzd_cache_read(wzd_cache_t * c, void *buf, unsigned int count)
{
  int ret;
/*  out_err(LEVEL_FLOOD,"cache read\n");*/
  /* if in cache, read data and pay attention to size ! */
  /* is file stored in cache ? */
  if (c->data) {
    if ( (c->current_location+count) <= c->datasize ) {
      memcpy(buf,c->data + c->current_location,count);
      c->current_location += count;
      return count;
    }
    memcpy(buf,c->data + c->current_location,c->datasize-c->current_location);
    c->current_location = c->datasize;
    return c->datasize-c->current_location;
  } else { /* not in cache */
    /* update current_location */
    if (c) {
      ret = read( c->fd, buf, count );
      if (ret>0) c->current_location += ret;
      return ret;
    }
  } /* file in cache ? */
  return -1;
}

int wzd_cache_write(wzd_cache_t * c, void *buf, unsigned int count)
{
  int ret;
  out_err(LEVEL_FLOOD,"cache write\n");
  /* update current_location */
  if (c) {
    /* TODO XXX FIXME if in cache, warn user it is rather stupid to cache a file
     * to be modified, and re-open it in non-cache mode
     */
    if (c->data) {
      out_err(LEVEL_INFO,"Trying to write a cached file - stupid !\n");
      return -1;
    }
    ret = write( c->fd, buf, count );
    if (ret>0) c->current_location += ret;
    return ret;
  }
  return -1;
}

char * wzd_cache_gets(wzd_cache_t * c, char *buf, unsigned int size)
{
  off_t position;
  int fd = c->fd;
  char buffer[4096], *ptr, *dst;
  char _c;
  int ret;
  unsigned int size_to_read;

  if (!c) return NULL;

  /* is file stored in cache ? */
  if (c->data) {
    /* get start position */
    position = c->current_location;

    /* read buffer */
    ptr = buffer;
    dst = buf;
    size_to_read = (size<4096)?size:4096;
/*    ret = read(fd,buffer,size_to_read);*/
    if (c->current_location + size_to_read > c->datasize) {
      size_to_read = c->datasize - c->current_location; /* XXX -1 ? */
    }
    if (c->current_location >= c->datasize) return NULL;
    memcpy(buffer,c->data+c->current_location,size_to_read);
    c->current_location += size_to_read;
    while (--size>0 && (_c=(*ptr++)) != EOF)
    {
      if ( (*dst++ = _c)=='\n' )
	break;
      if ( --size_to_read == 0 ) {
	size_to_read = (size<4096)?size:4096;
/*	ret = read(fd,buffer,size_to_read);*/
	if (c->current_location + size_to_read > c->datasize) {
	  size_to_read = c->datasize - c->current_location; /* XXX -1 ? */
	}
	if (c->current_location >= c->datasize) return NULL;
	memcpy(buffer,c->data+c->current_location,size_to_read);
	c->current_location += size_to_read;
	ptr = buffer;
/*	if (ret < 0) return NULL;*/
      }
    }
    *dst=0;
    if (_c==EOF && ptr==buf) return NULL;
/*    lseek(fd,position + (dst-buf), SEEK_SET );*/
    c->current_location = position + (dst-buf);

  } else { /* file is not in cache ! */

    /* get start position */
    position = lseek(fd,0,SEEK_CUR);

    /* read buffer */
    ptr = buffer;
    dst = buf;
    size_to_read = (size<4096)?size:4096;
    ret = read(fd,buffer,size_to_read);
    if (ret <= 0) return NULL;
    while (--size>0 && (_c=(*ptr++)) != EOF)
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
    if (_c==EOF && ptr==buf) return NULL;
    lseek(fd,position + (dst-buf), SEEK_SET );
    /* update current_location */
    c->current_location += strlen(buf);
  } /* file in cache ? */

  return buf;
}

void wzd_cache_close(wzd_cache_t * c)
{
  if (c) {
 /*   close( c->fd );
    free(c);*/
  } 
}

void wzd_cache_purge(void)
{
  wzd_cache_t * cache_current, * cache_next;

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
      cache_current->fd = -1;
    }
    free(cache_current);
    cache_current = cache_next;
  }
}
