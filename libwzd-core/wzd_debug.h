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

#ifndef __WZD_DEBUG__
#define __WZD_DEBUG__

#include "wzd_types.h"

#ifdef DEBUG

#define WZD_ASSERT_VOID(x) if (!(x)) { fprintf(stderr,"Assertion Failed "#x" on %s:%d\n",__FILE__,__LINE__); return ; }
#define WZD_ASSERT(x) if (!(x)) { fprintf(stderr,"Assertion Failed "#x" on %s:%d\n",__FILE__,__LINE__); return -1; }
#define WZD_ASSERT_RETURN(x,r) if (!(x)) { fprintf(stderr,"Assertion Failed "#x" on %s:%d\n",__FILE__,__LINE__); return (r); }

#else

#define WZD_ASSERT_VOID(x)
#define WZD_ASSERT(x)
#define WZD_ASSERT_RETURN(x,y)

#endif

#if defined(_MSC_VER) && (_MSC_VER < 1310)
# define __FUNCTION__ "unknown"
#endif

/** Memory allocation */
void * wzd_malloc(size_t size);

/** Memory reallocation */
void * wzd_realloc(void * ptr, size_t size);

/** Copy memory area. The memory areas may overlap. */
void * wzd_memmove(void * dst, const void * src, size_t size);

/** Free memory allocated by wzd_malloc */
void wzd_free(void *ptr);

/** Copy with allocation */
char * wzd_strdup(const char *s);

/** Copy with allocation, at most \a n bytes */
char * wzd_strndup(const char *s, size_t n);

/** same as strncpy, but write only one zero at end of string */
char * wzd_strncpy(char *dst, const char *src, size_t n);

/** Find the length of \a s , but scan at most \a n characters. */
size_t wzd_strnlen (const char *s, size_t n);

/** init all debug functions */
void wzd_debug_init(void);

/** end all debug functions */
void wzd_debug_fini(void);

int fd_register(fd_t fd, const char *desc, const char *file, unsigned int line, const char *function);
int fd_unregister(fd_t fd, const char *desc, const char *file, unsigned int line, const char *function);
void fd_dump(void);
#ifdef DEBUG
# define FD_REGISTER(fd,desc)   fd_register(fd,desc,__FILE__,__LINE__,__FUNCTION__)
# define FD_UNREGISTER(fd,desc)   fd_unregister(fd,desc,__FILE__,__LINE__,__FUNCTION__)
#else
# define FD_REGISTER(fd,desc)
# define FD_UNREGISTER(fd,desc)
#endif

/** try to print the backtrace */
void dump_backtrace(void);

/** \brief Check current context for corruptions */
int check_context(struct wzd_context_t * context);

#ifdef DEBUG

/* debug file cache */
/*#define ENABLE_CACHE*/
/*#define WZD_DBG_CACHE*/

/* debug users/groups cache */
/*#define WZD_DBG_UGCACHE*/

/* debug cookies parsing code */
/*#define WZD_DBG_COOKIES*/

/* debug crontab */
/*#define WZD_DBG_CRONTAB*/

/* debug events */
/*#define WZD_DBG_EVENT*/

/* debug ident */
/*#define WZD_DBG_IDENT*/

/* locking/unlocking files */
/*#define WZD_DBG_LOCK*/

/* modules loading/unloading */
/*#define WZD_DBG_MODULES*/

/* do not call abort() when trapping SIGSEGV */
/*#define WZD_DBG_NOABORT*/

/* debug permissions */
/*#define WZD_DBG_PERMS*/

/* debug tls */
/*#define WZD_DBG_TLS*/

/* debug vfs */
/*#define WZD_DBG_VFS*/

#ifdef HAVE_MPATROL
#include <mpatrol.h>
#endif

#endif /* DEBUG */

#endif /* __WZD_DEBUG__ */
