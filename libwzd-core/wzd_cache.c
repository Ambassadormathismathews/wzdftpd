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
  u64_t datasize;
  time_t mtime;
  unsigned short use;

  char * data;

  wzd_internal_cache_t * next_cache;
};

struct wzd_cache_t {
  u64_t current_location;

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

u64_t wzd_cache_getsize(wzd_cache_t *c)
{
  if (!c) return (unsigned int)-1;
  return c->cache->datasize;
}

wzd_cache_t * wzd_cache_open(const char *file, int flags, unsigned int mode)
{
#ifdef ENABLE_CACHE
  wzd_cache_t * cache;
  wzd_internal_cache_t * c;
  fs_filestat_t s;
  unsigned long hash;
  unsigned long ret;
  unsigned int length;
  u64_t l64;
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
    if ((unsigned long)s.size != c->datasize || s.mtime > c->mtime) {
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
  l64 = s.size;
  if (l64 > MAX_CACHE_FILE_LEN) {
    out_err(LEVEL_FLOOD,"File too big to be stored in cache (%ld bytes)\n",length);
    c->data = NULL;
    c->datasize = 0;
  } else {
    length = (unsigned int)l64;
    c->data = malloc(length+1);
    if ( (ret=(unsigned long)read(fd,c->data,length)) != length ) {
      out_err(LEVEL_FLOOD,"Read only %ld bytes on %ld required\n",ret,length);
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
  u64_t length, ret;
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
    out_err(LEVEL_FLOOD,"File too big to be stored in cache (%ld bytes)\n",length);
    c->data = NULL;
    c->datasize = 0;
  } else {
    c->data = malloc((unsigned int)length);
    if ( (ret=read(fd,c->data,length)) != length ) {
      out_err(LEVEL_FLOOD,"Read only %ld bytes\n",ret);
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
int wzd_cache_read(wzd_cache_t * c, void *buf, unsigned int count)
{
  int ret;
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
      return (int)count;
    }
    memcpy(buf,cache->data + c->current_location,cache->datasize-c->current_location);
    c->current_location = cache->datasize;
    return (int)(cache->datasize-c->current_location);
  } else { /* not in cache */
#endif
    /* update current_location */
    if (c) {
      ret = (int)read( cache->fd, buf, count );
      if (ret>0) c->current_location += ret;
      return ret;
    }
#ifdef ENABLE_CACHE
  } /* file in cache ? */
#endif
  return -1;
}

int wzd_cache_write(wzd_cache_t * c, void *buf, unsigned int count)
{
#ifdef ENABLE_CACHE
  int ret;
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
    ret = (int)write( cache->fd, buf, count );
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


#ifndef WZD_NO_USER_CACHE

static CHTBL index_user_name;
static CHTBL index_user_uid;
static CHTBL index_group_name;
static CHTBL index_group_gid;

int hash_uid(const void *key)
{
  return ( (unsigned int) key );
}

int uidcmp(const void *key1, const void *key2)
{
  return ( ((unsigned int)key1) != ((unsigned int)key2) );
}

int predicate_uid(wzd_user_t * user, void * arg)
{
  return (user->username[0] != '\0' && user->uid == (unsigned int)arg);
}

int predicate_name(wzd_user_t * user, void * arg)
{
  return (strcmp(user->username,(char*)arg)==0);
}

int predicate_gid(wzd_group_t * group, void * arg)
{
  return (group->groupname[0] != '\0' && group->gid == (unsigned int)arg);
}

int predicate_groupname(wzd_group_t * group, void * arg)
{
  return (strcmp(group->groupname,(char*)arg)==0);
}

int predicate_groupname(wzd_group_t * group, void * arg);

#ifdef WZD_DBG_UGCACHE
static void _user_free(wzd_user_t *user)
{
  out_err(LEVEL_CRITICAL,"Freeing user %s (%p)\n",user->username,user);
}
#else
#define _user_free wzd_free
#endif

void usercache_init(void)
{
  chtbl_init(&index_user_name,128,(hash_function)hash_str,(cmp_function)strcmp,wzd_free);
  chtbl_init(&index_user_uid,37,(hash_function)hash_uid,(cmp_function)uidcmp,wzd_free);
  chtbl_init(&index_group_name,128,(hash_function)hash_str,(cmp_function)strcmp,wzd_free);
  chtbl_init(&index_group_gid,37,(hash_function)hash_uid,(cmp_function)uidcmp,wzd_free);
}

void usercache_fini(void)
{
  chtbl_destroy(&index_user_uid);
  chtbl_destroy(&index_user_name);
  chtbl_destroy(&index_group_gid);
  chtbl_destroy(&index_group_name);
}


wzd_user_t * usercache_add(wzd_user_t * user)
{
  wzd_user_t * loop_user;
  wzd_user_t * data;

  if (!user) return NULL;

  if ((chtbl_lookup(&index_user_name, user->username, (void**)&data))==0)
  {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"user cache refresh %s\n",user->username);
#endif
    memcpy(data, user, sizeof(wzd_user_t));
    return data;
  }

  /* insert entry */
  loop_user = wzd_malloc(sizeof(wzd_user_t));
  memcpy(loop_user,user,sizeof(wzd_user_t));
  if ((chtbl_insert(&index_user_name, loop_user->username, loop_user, NULL, NULL, _user_free))==0 &&
       chtbl_insert(&index_user_uid, (void*)loop_user->uid, loop_user, NULL, NULL, NULL)==0)
  {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"user cache add %s (%p)\n",user->username,loop_user);
#endif
    return loop_user;
  }
  wzd_free(loop_user);

#ifdef WZD_DBG_UGCACHE
  out_log(LEVEL_NORMAL,"No more free space in cache\n");
  out_log(LEVEL_NORMAL,"%s:%d     user: %s\n",__FILE__,__LINE__,user->username);
#endif
  return NULL;
}

wzd_user_t * usercache_getbyname( const char * name )
{
  wzd_user_t * user;

  if ((chtbl_lookup(&index_user_name, name, (void**)&user))==0) {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"user cache hit NAME %s\n",user->username);
#endif
    return user;
  }

  return NULL;
}

wzd_user_t * usercache_getbyuid( unsigned int uid )
{
  wzd_user_t * user;

  if ((chtbl_lookup(&index_user_uid, (void*)uid, (void**)&user))==0) {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"user cache hit UID %s\n",user->username);
#endif
    return user;
  }

  return NULL;
}

wzd_user_t * usercache_search( predicate_user_t p, void * arg )
{
  wzd_user_t * user;

  if ((chtbl_search(&index_user_name, (cmp_function)p, arg, (void**)&user))==0)
  {
    return user;
  }

  return NULL;
}

void usercache_invalidate( predicate_user_t p, void * arg )
{
  wzd_user_t * user;

  user = usercache_search( p, arg );

  if (user) {
    chtbl_remove(&index_user_uid, (void*)user->uid);
    chtbl_remove(&index_user_name, user->username);
  }
}



wzd_group_t * groupcache_add(wzd_group_t * group)
{
  wzd_group_t * loop_group;
  wzd_group_t * data;

  if (!group) return NULL;

  if ((chtbl_lookup(&index_group_name, group->groupname, (void**)&data))==0)
  {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"group cache refresh %s\n",group->groupname);
#endif
    memcpy(data, group, sizeof(wzd_group_t));
    return data;
  }

  /* insert entry */
  loop_group = wzd_malloc(sizeof(wzd_group_t));
  memcpy(loop_group,group,sizeof(wzd_group_t));
  if ((chtbl_insert(&index_group_name, loop_group->groupname, loop_group, NULL, NULL, wzd_free))==0 &&
       chtbl_insert(&index_group_gid, (void*)loop_group->gid, loop_group, NULL, NULL, NULL)==0)
  {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"group cache add %s\n",group->groupname);
#endif
    return loop_group;
  }
  wzd_free(loop_group);

#ifdef WZD_DBG_UGCACHE
  out_log(LEVEL_NORMAL,"No more free space in cache\n");
  out_log(LEVEL_NORMAL,"%s:%d     group: %s\n",__FILE__,__LINE__,group->groupname);
#endif
  return NULL;
}

wzd_group_t * groupcache_getbyname( const char * name )
{
  wzd_group_t * group;

  if ((chtbl_lookup(&index_group_name, name, (void**)&group))==0) {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"group cache hit NAME %s\n",group->groupname);
#endif
    return group;
  }

  return NULL;
}

wzd_group_t * groupcache_getbygid( unsigned int gid )
{
  wzd_group_t * group;

  if ((chtbl_lookup(&index_group_gid, (void*)gid, (void**)&group))==0) {
#ifdef WZD_DBG_UGCACHE
    out_err(LEVEL_INFO,"group cache hit GID %s\n",group->groupname);
#endif
    return group;
  }

  return NULL;
}

wzd_group_t * groupcache_search( predicate_group_t p, void * arg )
{
  wzd_group_t * group;

  if ((chtbl_search(&index_group_name, (cmp_function)p, arg, (void**)&group))==0)
  {
    return group;
  }

  return NULL;
}

void groupcache_invalidate( predicate_group_t p, void * arg )
{
  wzd_group_t * group;

  group = groupcache_search( p, arg );

  if (group) chtbl_remove(&index_group_gid, (void*)group->gid);
  if (group) chtbl_remove(&index_group_name, group->groupname);
}

#endif /* WZD_NO_USER_CACHE */

