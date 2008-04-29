/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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
/** \file win32.h
  * \brief Windows-specific definitions.
  */

#ifndef __ARCH_WIN32__
#define __ARCH_WIN32__

/* win32-common definitions */
#if defined (WIN32)


#if defined(_MSC_VER)

#ifdef LIBWZD_EXPORTS
# define WZDIMPORT __declspec (dllexport)
#else
# define WZDIMPORT __declspec (dllimport)
#endif

#endif /* _MSC_VER */

# include <winsock2.h>

#define pid_t		unsigned int
#define uid_t		unsigned int
#define gid_t		unsigned int

#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define ECONNREFUSED WSAECONNREFUSED
#define EINPROGRESS  WSAEINPROGRESS
#define ENOTCONN     WSAENOTCONN
#define ETIMEDOUT    WSAECONNABORTED

#define SIGHUP  1 /* re-read configuration */

#ifndef RTLD_NOW
# define RTLD_NOW 2
#endif

#define F_RDLCK 0 /* Read lock. */
#define F_WRLCK 1 /* Write lock. */
#define F_UNLCK 2 /* Remove lock. */

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

#ifndef mkdir
# define mkdir(filename,mode) mkdir(filename)
#endif

#define dlopen(filename,dummy)	LoadLibrary(filename)
#define dlclose(handle)			FreeLibrary(handle)
#define dlsym(handle,symbol)	GetProcAddress(handle,symbol)
#define dlerror()				"Not supported on win32"

#define ftruncate(fd,pos)	win32_ftruncate((fd),(__int64)(pos))
int win32_ftruncate(int fd, __int64 length);

#define readlink(path,buf,bufsiz)	(-1)
#define symlink(oldpath,newpath)	(-1)

#include <sys/timeb.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <time.h>

#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

#if !defined(_WINSOCK2API_) && !defined(_WINSOCKAPI_)
#ifndef _TIMEVAL_DEFINED /* also in winsock[2].h */
#define _TIMEVAL_DEFINED
struct timeval {
    long tv_sec;        /* seconds */
    long tv_usec;  /* microseconds */
};
#endif
#endif

struct timezone {
    int tz_minuteswest; /* minutes W of Greenwich */
    int tz_dsttime;     /* type of dst correction */
};


#ifndef gettimeofday
/* defined in wzd_misc.c */
int win32_gettimeofday(struct timeval *tv, struct timezone *tz);
# define gettimeofday  win32_gettimeofday
#endif


/* windows 2000 only */
#if defined(WINVER) && (WINVER < 0x0501)

#define INET_ADDRSTRLEN   16
#define INET6_ADDRSTRLEN  46

#define in6_addr in_addr6 /* funny ! */
#define socklen_t	unsigned int

#endif

/** Some microsoft compilers lack this definition.
 */
#ifndef INVALID_SET_FILE_POINTER
# define INVALID_SET_FILE_POINTER ((DWORD)-1)
#endif


/* visual specific definitions */
#if defined(_MSC_VER)

/* visual c++ and the c99 .. a long story ! */
#ifndef INT_MAX
# define INT_MAX 2147483647
#endif

/* unsigned int, 64 bits: u64_t */
#define u64_t unsigned __int64
#define u32_t unsigned __int32
#define u16_t unsigned __int16
#define u8_t  unsigned __int8
#define i64_t __int64
#define i32_t __int32
#define i16_t __int16
#define i8_t  __int8

#define __PRI64_PREFIX  "I64"

#define PRIu64  __PRI64_PREFIX "u"

/* visual c++ doesn't follow C99 naming standards */
#define strtoll _strtoi64
#define strtoull _strtoui64
#ifndef LLONG_MAX
# define LLONG_MAX _I64_MAX
#endif
#ifndef ULLONG_MAX
# define ULLONG_MAX _UI64_MAX
#endif

#define strtok_r strtok_s

typedef int fd_t;
/* use SOCKET, because it can be 64-bits on windows 64 */
typedef SOCKET socket_t;

/* small hack: ptrdiff_t is the only standard signed type which
 * should be the same size as size_t
 */
typedef ptrdiff_t ssize_t;

#define inline __inline

#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

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

#ifndef chmod
#  define chmod	_chmod
#endif

#define getcwd	_getcwd

/* FIXME this will surely have some effects ... */
#ifndef stat
#   define fstat _fstati64
#   define lstat _stati64
#   define stat  _stati64
#endif

#ifndef mkdir
#   define mkdir(filename)	_mkdir(filename)
#   define closedir	FindClose
#endif

#ifndef open
#  define open	_open
#endif

#define popen	_popen
#define pclose	_pclose

#define snprintf	_snprintf
#define vsnprintf	_vsnprintf


#include <libwzd-auth/wzd_crypt.h>
#include <libwzd-auth/wzd_md5crypt.h>
#include "wzd_strptime.h"



const char * inet_ntop(int af, const void *src, char *dst, size_t size);

#endif /* _MSC_VER */

#define DIR_CONTINUE \
	  { \
		if (!FindNextFile(dir,&fileData)) \
		{ \
		  if (GetLastError() == ERROR_NO_MORE_FILES) \
		    finished = 1; \
		} \
        continue; \
      }

#define strcasecmp	stricmp
#define strncasecmp	strnicmp

#define DIRCMP	strcasecmp
#define DIRNCMP	strncasecmp
#define DIRNORM(s,l,low) win_normalize(s,(unsigned int)l,low)

/** remove trailing / */
#define REMOVE_TRAILING_SLASH(str) \
  do { \
    size_t _length = strlen((str)); \
    if (_length>1 && (str)[_length-1]=='/') \
      if (_length != 3) /* root of a logical dir */ \
        (str)[_length-1] = '\0'; \
  } while (0)


#endif /* WIN32 */

#endif /* __ARCH_WIN32__ */
