/* vi:ai:et:ts=8 sw=2
 */
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

#ifndef __LIBSQLITE__
#define __LIBSQLITE__

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
# include <winsock2.h>
# include <windows.h>
# define inline __inline
#else /* !WIN32 */
#include <unistd.h>
#endif

#include <libwzd-auth/wzd_auth.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_user.h>

#include <libwzd-core/wzd_debug.h>

#include <sqlite3.h>

#include "libsqlite_main.h"
#include "libsqlite_user.h"
#include "libsqlite_group.h"

#define SQLITE_BACKEND_VERSION  1
#define SQLITE_LOG_CHANNEL (RESERVED_LOG_CHANNELS + 17) 

#define _TXT_CPY(dest, src, n) if (src != NULL) strncpy(dest, src, n)

#endif /* __LIBMYSQL__ */
