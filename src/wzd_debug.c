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
