/* vi:ai:et:ts=8 sw=2
 */
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

#if defined(_MSC_VER) || (defined __CYGWIN__ && defined WINSOCK_SUPPORT)
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "wzd_structs.h"
#include "wzd_log.h"


/* uncomment to trace ALL fd registration operations */
/*#define WZD_DBG_FD*/


#define FD_SIG 0xbf07a4fb
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
  static struct stat s;

  if (fstat(fd,&s)<0) return 0;
  return 1;
#endif
}

/* Memory allocation */
/*@null@*/ void * wzd_malloc(size_t size)
{
  return (void*)malloc(size);
}

/* Free memory allocated by wzd_malloc */
void wzd_free(void *ptr)
{
  free(ptr);
}

/** Copy with allocation */
char * wzd_strdup(const char *s)
{
  return strdup(s);
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
