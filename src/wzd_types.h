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
/** \file
  * \brief System types
  * \warning This file contains many platform-dependant code.
  */

#ifndef __WZD_TYPES__
#define __WZD_TYPES__

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>


#if defined(_MSC_VER)

#define HARD_USERLIMIT	128

/* unsigned int, 64 bits: u64_t */
#define u64_t unsigned __int64
#include <sys/timeb.h>

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
#define	LOG_ERR		3
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

#ifndef S_IRGRP
#   define S_IRUSR S_IREAD
#   define S_IWUSR S_IWRITE
#   define S_IXUSR S_IEXEC
#   define S_IRGRP S_IREAD
#   define S_IWGRP S_IWRITE
#   define S_IXGRP S_IEXEC
#   define S_IROTH S_IREAD
#   define S_IWOTH S_IWRITE
#   define S_IXOTH S_IEXEC
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
#   define lstat	_stati64
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


/*********************** VERSION **************************/

/* Version */
#define  WZD_VERSION_NUM "0.4.0 visual"
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

#include "wzd_crypt.h"
#include "wzd_md5crypt.h"
#include "wzd_strptime.h"
#include "wzd_strtok_r.h"
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



#else /* _MSC_VER */

/* unsigned int, 64 bits: u64_t */
#define u64_t u_int64_t
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


#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif





#define WZD_DEFAULT_PIDFILE "/var/run/wzdftpd.pid"


#include "wzd_strlcat.h"


#endif /* __WZD_TYPES__ */
