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

/** \file wzd_dir.c
  * \brief Utilities functions to manipulate file and dir names
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
#include "wzd_dir.h"

#include "wzd_debug.h"

/* strip non-directory suffix from file name
 * returns file without its trailing /component removed, if name contains
 * no /'s, returns "." (meaning the current directory).
 * caller MUST free memory !
 */
char * dir_getdirname(const char *file)
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
char * dir_getbasename(const char *file, const char *suffix)
{
  char * basename;
  const char * ptr;
  unsigned int length;

  if (!file) return NULL;
  ptr = file + strlen(file);
  while ( (ptr > file) && (*ptr != '/')) ptr--;

  if (ptr == file)
  {
    basename = strdup(file);
  }
  else
  {
    length = strlen(file) - (ptr - file);
    basename = malloc(length+1);
    strncpy(basename,ptr+1,length);
    basename[length] = '\0';
  }

  /** \todo TODO if specified, remove suffix */

  return basename;
}

/* \brief get the trailing n parts of a filename
 *
 * Return file with any leading directory components removed, until
 * it has n components.
 * Caller MUST free memory !
 */
char * dir_gettrailingname(const char *file, unsigned int n)
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
    name = strdup(file);
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
