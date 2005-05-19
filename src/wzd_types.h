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
#include <unistd.h>
#endif

#include <sys/types.h>

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif


#if defined(_MSC_VER)

/* windows have wchar.h */
#define HAVE_WCHAR_H

#ifdef LIBWZD_EXPORTS
# define WZDIMPORT __declspec (dllexport)
#else
# define WZDIMPORT __declspec (dllimport)
#endif

/* unsigned int, 64 bits: u64_t */
#define u64_t unsigned __int64
#define u32_t unsigned __int32
#define u16_t unsigned __int16
#define i64_t __int64
#define i32_t __int32
#define i16_t __int16

#define __PRI64_PREFIX  "I64"

#define PRIu64  __PRI64_PREFIX "u"

typedef unsigned fd_t;

typedef size_t ssize_t;

#include <sys/timeb.h>

#define inline __inline

#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define ECONNREFUSED WSAECONNREFUSED
#define EINPROGRESS  WSAEINPROGRESS
#define ENOTCONN     WSAENOTCONN
#define ETIMEDOUT    WSAECONNABORTED

#define in6_addr in_addr6 /* funny ! */

#define F_RDLCK 0 /* Read lock. */
#define F_WRLCK 1 /* Write lock. */
#define F_UNLCK 2 /* Remove lock. */

#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

#define SIGHUP  1 /* re-read configuration */

#define __S_ISTYPE(mode,mask) (((mode) & _S_IFMT) == (mask))

#ifndef S_ISDIR
#   define S_ISDIR(mode) (__S_ISTYPE((mode), _S_IFDIR))
#endif
#ifndef S_ISDIR
#   define S_ISDIR(mode) 
#endif
#ifndef S_ISLNK
#   define S_ISLNK(mode) (0)
#endif
#ifndef S_ISREG
#   define S_ISREG(mode) __S_ISTYPE((mode), _S_IFREG)
#endif

#define S_IREAD  _S_IREAD
#define S_IWRITE _S_IWRITE
#define S_IEXEC  _S_IEXEC

#ifndef S_IRUSR
#   ifdef S_IREAD
#	define S_IRUSR S_IREAD
#	define S_IWUSR S_IWRITE
#	define S_IXUSR S_IEXEC
#   else
#	define S_IRUSR 0400
#	define S_IWUSR 0200
#	define S_IXUSR 0100
#   endif
#endif

#ifndef S_IRGRP
#   ifdef S_IRUSR
#       define S_IRGRP (S_IRUSR>>3)
#       define S_IWGRP (S_IWUSR>>3)
#       define S_IXGRP (S_IXUSR>>3)
#   else
#       define S_IRGRP 0040
#       define S_IWGRP 0020
#       define S_IXGRP 0010
#   endif
#endif

#ifndef S_IROTH
#   ifdef S_IRUSR
#       define S_IROTH (S_IRUSR>>6)
#       define S_IWOTH (S_IWUSR>>6)
#       define S_IXOTH (S_IXUSR>>6)
#   else
#       define S_IROTH 0040
#       define S_IWOTH 0020
#       define S_IXOTH 0010
#   endif
#endif

#define DIR_CONTINUE \
	  { \
		if (!FindNextFile(dir,&fileData)) \
		{ \
		  if (GetLastError() == ERROR_NO_MORE_FILES) \
		    finished = 1; \
		} \
        continue; \
      }

#define DIRCMP	strcasecmp
#define DIRNCMP	strncasecmp
#define DIRNORM(s,l,low) win_normalize(s,l,low)

/** remove trailing / */
#define REMOVE_TRAILING_SLASH(str) \
  do { \
    size_t _length = strlen((str)); \
    if (_length>1 && (str)[_length-1]=='/') \
      if (_length != 3) /* root of a logical dir */ \
        (str)[_length-1] = '\0'; \
  } while (0)


#ifndef chmod
#  define chmod	_chmod
#endif

#define dlopen(filename,dummy)	LoadLibrary(filename)
#define dlclose(handle)			FreeLibrary(handle)
#define dlsym(handle,symbol)	GetProcAddress(handle,symbol)
#define dlerror()				"Not supported on win32"

#define getcwd	_getcwd

/* FIXME this will surely have some effects ... */
#ifndef stat
#   define fstat _fstati64
#   define lstat _stati64
#   define stat  _stati64
#endif

#ifndef mkdir
#   define mkdir(filename,mode)	_mkdir(filename)
#   define closedir	FindClose
#endif

#ifndef open
#  define open	_open
#endif

#define popen	_popen
#define pclose	_pclose

#define readlink(path,buf,bufsiz)	(-1)
#define symlink(oldpath,newpath)	(-1)

#define strcasecmp	stricmp
#define strncasecmp	strnicmp

#define snprintf	_snprintf
#define vsnprintf	_vsnprintf

#define pid_t		unsigned int
#define socklen_t	unsigned int
#define uid_t		unsigned int
#define gid_t		unsigned int


/*********************** VERSION **************************/

/* Version */
#define  WZD_VERSION_NUM "0.5.3 visual"
#define  WZD_BUILD_NUM __DATE__
#define  WZD_BUILD_OPTS  "visual"

#ifdef WZD_MULTIPROCESS
#define WZD_MP  " mp "
#else /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
#define WZD_MP  " mt "
#else
#define WZD_MP  " up "
#endif /* WZD_MULTITHREAD */
#endif /* WZD_MULTIPROCESS */

#define WZD_VERSION_STR "wzdftpd i386-pc-windows-visual " WZD_MP WZD_VERSION_NUM

#define WZD_DEFAULT_CONF "wzd-win32.cfg"

#include <libwzd-auth/wzd_crypt.h>
#include <libwzd-auth/wzd_md5crypt.h>
#include "wzd_strptime.h"
#include "wzd_strtoull.h"


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <time.h>

#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

#if !defined(_WINSOCK2API_) && !defined(_WINSOCKAPI_)
struct timeval {
    long tv_sec;        /* seconds */
    long tv_usec;  /* microseconds */
};
#endif

struct timezone {
    int tz_minuteswest; /* minutes W of Greenwich */
    int tz_dsttime;     /* type of dst correction */
};

__inline int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME        ft;
    LARGE_INTEGER   li;
    __int64         t;
    static int      tzflag;

    if (tv)
    {
        GetSystemTimeAsFileTime(&ft);
        li.LowPart  = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        t  = li.QuadPart;       /* In 100-nanosecond intervals */
        t -= EPOCHFILETIME;     /* Offset to the Epoch time */
        t /= 10;                /* In microseconds */
        tv->tv_sec  = (long)(t / 1000000);
        tv->tv_usec = (long)(t % 1000000);
    }

    if (tz)
    {
        if (!tzflag)
        {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}

const char * inet_ntop(int af, const void *src, char *dst, size_t size);



#else /* _MSC_VER */

#define WZDIMPORT

/* unsigned int, 64 bits: u64_t */
#define i16_t int16_t
#define u16_t uint16_t
#define i32_t int32_t
#define u32_t uint32_t
#define i64_t int64_t
#define u64_t uint64_t

typedef signed fd_t;


#include <sys/time.h> /* struct timeval */

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

#endif /* _MSC_VER */


#ifdef IPV6_SUPPORT
#define CURRENT_AF AF_INET6
#else
#define CURRENT_AF AF_INET
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#undef IN6_IS_ADDR_V4MAPPED
#define ULONG uint32_t
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
	((((const ULONG *)(a))[0] == 0) \
	&& (((const ULONG *)(a))[1] == 0) \
	&& (((const ULONG *)(a))[2] == htonl (0xffff)))
#endif

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
#include <libwzd-base/wzd_strtok_r.h>

#include "wzd_string.h"

#endif /* __WZD_TYPES__ */
