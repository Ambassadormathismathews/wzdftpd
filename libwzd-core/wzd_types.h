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
/** \file
  * \brief Standard wzdftpd types, defined for ease-of-use and portability.
  * \warning This file contains many platform-dependant code.
  */

#ifndef __WZD_TYPES__
#define __WZD_TYPES__

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#include "arch/bsd.h"
#include "arch/win32.h"




#ifndef _MSC_VER

#define WZDIMPORT

/* unsigned int, 64 bits: u64_t */
#define i8_t  int8_t
#define u8_t  uint8_t
#define i16_t int16_t
#define u16_t uint16_t
#define i32_t int32_t
#define u32_t uint32_t
#define i64_t int64_t
#define u64_t uint64_t

typedef signed fd_t;


#include <sys/time.h> /* struct timeval */

#endif /* _MSC_VER */

#ifndef WIN32

#define DIR_CONTINUE continue;

#define DIRCMP	strcmp
#define DIRNCMP	strncmp

#define DIRNORM(x,l,low)

/** remove trailing / */
#define REMOVE_TRAILING_SLASH(str) \
  do { \
    size_t _length = strlen(str); \
    if (_length>1 && (str)[_length-1]=='/') \
      (str)[_length-1] = '\0'; \
  } while(0)

#endif /* WIN32 */


#ifdef IPV6_SUPPORT
#define CURRENT_AF AF_INET6
#else
#define CURRENT_AF AF_INET
#endif


#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
	((((const ULONG *)(a))[0] == 0) \
	&& (((const ULONG *)(a))[1] == 0) \
	&& (((const ULONG *)(a))[2] == htonl (0xffff)))
#endif /* IN6_IS_ADDR_V4MAPPED */

#ifndef INADDR_NONE
# define INADDR_NONE ((unsigned long int) 0xffffffff)
#endif


#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#include <stdio.h>


/* stat64 */
#ifdef HAVE_STAT64
# define statbuf stat64
# define fs_stat(f,s) stat64(f, s)
# define fs_lstat(f,s) lstat64(f, s)
# define fs_fstat(f,s) fstat64(f, s)
# define fs_lseek(f,o,w) lseek64(f, o, w)
# define fs_open(p,f,l) open64(p,f,l)
# define fs_off_t off64_t
#else /* HAVE_STAT64 */
# define statbuf stat
# define fs_stat(f,s) stat(f, s)
# define fs_lstat(f,s) lstat(f, s)
# define fs_fstat(f,s) fstat(f, s)
# define fs_lseek(f,o,w) lseek(f, o, w)
# define fs_open(p,f,l) open(p,f,l)
# define fs_off_t off_t
#endif /* HAVE_STAT64 */





#define WZD_DEFAULT_PIDFILE "/var/run/wzdftpd.pid"


#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#include <libwzd-base/list.h>
#include <libwzd-base/hash.h>
/*#include <libwzd-base/wzd_strtok_r.h>*/

#include "wzd_string.h"

#endif /* __WZD_TYPES__ */
