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

#if defined(WIN32) || (defined __CYGWIN__ && defined WINSOCK_SUPPORT)
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#define __USE_GNU  /* avoid warning for strndup */
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"

#endif /* WZD_USE_PCH */

#ifdef HAVE_EXECINFO_H
# include <execinfo.h>
#endif

/* uncomment to trace ALL fd registration operations */
/*#define WZD_DBG_FD*/


#define FD_SIG 0xbf07a4fbUL
#define WZD_MAX_FD 1024

#ifdef DEBUG
struct wzd_fd {
  unsigned long sig;
  int fd;
  char file[256];
  unsigned int line;
  char function[256];
  char desc[256];
};

static struct wzd_fd _wzd_fd_table[WZD_MAX_FD];

static void fd_init(void);

#endif

int fd_register(int fd, const char *desc, const char *file, unsigned int line, const char *function);
int fd_unregister(int fd, const char *desc, const char *file, unsigned int line, const char *function);
void fd_dump(void);

size_t wzd_strnlen (const char *s, size_t n);

/** init all debug functions */
void wzd_debug_init(void)
{
#ifdef DEBUG
  fd_init();
#endif
}

/** end all debug functions */
void wzd_debug_fini(void)
{
#ifdef DEBUG
  fd_dump();
#endif
}

/** Check if fd is a valid file descriptor */
int fd_is_valid(int fd)
{
  /* cygwin does NOT accept testing winsock fd's */
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
  return 1;
#else
  static struct statbuf s;

  if (fs_fstat(fd,&s)<0) return 0;
  return 1;
#endif
}

/* Memory allocation */
/*@null@*/ void * wzd_malloc(size_t size)
{
  return (void*)malloc(size);
}

/* Memory reallocation */
void * wzd_realloc(void * ptr, size_t size)
{
  return (void*)realloc(ptr, size);
}

/** \brief Copy memory area. The memory areas may overlap. */
void * wzd_memmove(void * dst, const void * src, size_t size)
{
  return memmove(dst,src,size);
}

/** \brief Free memory allocated by wzd_malloc */
void wzd_free(void *ptr)
{
  free(ptr);
}

/** \brief Copy with allocation */
char * wzd_strdup(const char *s)
{
  return strdup(s);
}

/** \brief Copy with allocation, at most \a n bytes */
char * wzd_strndup(const char *s, size_t n)
{
#ifdef HAVE_STRNDUP
  return strndup(s,n);
#else
  size_t len = wzd_strnlen(s, n);
  char * new = wzd_malloc (len + 1);

  new[len] = '\0';

  return memcpy(new, s, len);
#endif
}

/** same as strncpy, but write only one zero at end of string */
char * wzd_strncpy(char *dst, const char *src, size_t n)
{
  if (n != 0)
  {
    register char *d = dst;
    register const char *s = src;

    do {
      if ( (*d++ = *s++) == 0 ) break;
    } while (--n != 0);
  }
  return dst;
}

/** Find the length of \a s , but scan at most \a n characters. */
size_t wzd_strnlen (const char *s, size_t n)
{
  const char *end = memchr (s, '\0', n);
  return end ? (size_t)(end - s) : n;
}

#ifdef DEBUG
/** Initializes fd debug table */
static void fd_init(void)
{
  unsigned int i;
  for (i=0; i<WZD_MAX_FD; i++) {
    _wzd_fd_table[i].sig = FD_SIG;
    _wzd_fd_table[i].fd = -1;
  }
}
#endif /* DEBUG */

int fd_register(int fd, const char *desc, const char *file, unsigned int line, const char *function)
{
#ifdef DEBUG
  if (fd < 0) return 1;
  if (fd >= WZD_MAX_FD) return 2;

  /* fd already registered ? */
  if (_wzd_fd_table[fd].fd != -1) {
    out_err(LEVEL_HIGH,"A file descriptor is already present at index %d\n",fd);
    out_err(LEVEL_HIGH,"current fd: %d [%s]\n\t%s:%d (%s)\n",
        _wzd_fd_table[fd].fd,
        _wzd_fd_table[fd].desc,
        _wzd_fd_table[fd].file,
        _wzd_fd_table[fd].line,
        _wzd_fd_table[fd].function);
    out_err(LEVEL_HIGH,"offending fd: %d [%s]\n\t%s:%d (%s)\n",
        fd,
        desc,
        file,
        line,
        function);
    return 3;
  }

  _wzd_fd_table[fd].fd = fd;
  strncpy(_wzd_fd_table[fd].desc,desc,sizeof(_wzd_fd_table[fd].desc));
  strncpy(_wzd_fd_table[fd].file,file,sizeof(_wzd_fd_table[fd].file));
  _wzd_fd_table[fd].line = line;
  strncpy(_wzd_fd_table[fd].function,function,sizeof(_wzd_fd_table[fd].function));
#ifdef WZD_DBG_FD
  out_err(LEVEL_HIGH,"added fd: %d [%s]\n\t%s:%d (%s)\n",
      fd,
      desc,
      file,
      line,
      function);
#endif

#endif
  return 0;
}

int fd_unregister(int fd, const char *desc, const char *file, unsigned int line, const char *function)
{
#ifdef DEBUG
  if (fd < 0) return 1;
  if (fd >= WZD_MAX_FD) return 2;

  /* fd already registered ? */
  if (_wzd_fd_table[fd].fd == -1) {
    out_err(LEVEL_HIGH,"No file descriptor at index %d\n",fd);
    out_err(LEVEL_HIGH,"offending fd: %d [%s]\n\t%s:%d (%s)\n",
        fd,
        desc,
        file,
        line,
        function);
    return 3;
  }

  _wzd_fd_table[fd].fd = -1;
  memset(_wzd_fd_table[fd].desc,0,sizeof(_wzd_fd_table[fd].desc));
  memset(_wzd_fd_table[fd].file,0,sizeof(_wzd_fd_table[fd].file));
  _wzd_fd_table[fd].line = 0;
  memset(_wzd_fd_table[fd].function,0,sizeof(_wzd_fd_table[fd].function));
#ifdef WZD_DBG_FD
  out_err(LEVEL_HIGH,"removed fd: %d [%s]\n\t%s:%d (%s)\n",
      fd,
      desc,
      file,
      line,
      function);
#endif

#endif
  return 0;
}

void fd_dump(void)
{
#ifdef DEBUG
  unsigned int i;
  out_err(LEVEL_HIGH,"starting fd list dump:\n");
  for (i=0; i<WZD_MAX_FD; i++) {
    if (_wzd_fd_table[i].fd == -1) continue;

    out_err(LEVEL_HIGH,"fd: %d [%s]\n\t%s:%d (%s)\n",
        _wzd_fd_table[i].fd,
        _wzd_fd_table[i].desc,
        _wzd_fd_table[i].file,
        _wzd_fd_table[i].line,
        _wzd_fd_table[i].function);
  }
  out_err(LEVEL_HIGH,"end of fd list dump:\n");
#endif
}

void dump_backtrace(void)
{
#ifdef HAVE_BACKTRACE
  void *bt[25];
  char **ptr;
  int i, size;

  if ((size=backtrace(bt,25))>0) {
    if ((ptr=backtrace_symbols(bt,25))) {
      for (i=0; i<size; i++) {
        if (ptr[i])
          out_err(LEVEL_HIGH,"frame %d: %s\n",i,ptr[i]);
      }
    }
  }
#endif
}

/** \brief Check current context for corruptions */
int check_context(wzd_context_t * context)
{
  if (GetMyContext() != context)
  {
    out_err(LEVEL_CRITICAL,"CRITICAL GetMyContext does not match context !\n");
    out_err(LEVEL_CRITICAL,"CRITICAL GetMyContext %p\n",GetMyContext());
    out_err(LEVEL_CRITICAL,"CRITICAL context      %p\n",context);
    return 1;
  }
  if (!context->magic == CONTEXT_MAGIC)
  {
    out_err(LEVEL_CRITICAL,"CRITICAL context->magic is invalid, context may be corrupted\n");
    return 1;
  }
  if (context->controlfd == (fd_t)-1 || !fd_is_valid(context->controlfd)) {
    out_err(LEVEL_CRITICAL,"Trying to set invalid sockfd (%d) %s:%d\n",
        context->controlfd,__FILE__,__LINE__);
    return 1;
  }

  return 0;
}

