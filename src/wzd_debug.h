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

#ifndef __WZD_DEBUG__
#define __WZD_DEBUG__

#define WZD_ASSERT_VOID(x) if (!(x)) { fprintf(stderr,"Assertion Failed "#x" on %s:%d\n",__FILE__,__LINE__); return ; }
#define WZD_ASSERT(x) if (!(x)) { fprintf(stderr,"Assertion Failed "#x" on %s:%d\n",__FILE__,__LINE__); return -1; }

/** Check if fd is a valid file descriptor */
int fd_is_valid(int fd);

/** Memory allocation */
void * wzd_malloc(size_t size);

/** Free memory allocated by wzd_malloc */
void wzd_free(void *ptr);

#ifdef DEBUG

/* debug file cache */
/*#define WZD_DBG_CACHE*/

/* debug cookies parsing code */
/*#define WZD_DBG_COOKIES*/

/* debug crontab */
/*#define WZD_DBG_CRONTAB*/

/* debug ident */
/*#define WZD_DBG_IDENT*/

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
