/* vi:ai:et:ts=8 sw=2
 */
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

/** \file wzd_all.h
  * \brief Include all files from wzdftpd main lib. Can be used for precompilation.
  */

#ifdef WZD_USE_PCH

#ifndef __WZD_ALL__
#define __WZD_ALL__

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#ifdef WIN32
#define _WIN32_WINNT    0x500
#define _WINSOCKAPI_
#include <windows.h>

#include <direct.h>
#include <io.h>
#include <winsock2.h>
#include <process.h> /* _getpid() */
#endif /* WIN32 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#ifdef BSD
#define DL_ARG    DL_LAZY
#else
#define DL_ARG    RTLD_NOW
#endif

#ifdef NEED_UNDERSCORE
#define DL_PREFIX "_"
#else
#define DL_PREFIX
#endif



#include "wzd_structs.h"

#include "wzd_backend.h"
#include "wzd_cache.h"
#include "wzd_ClientThread.h"
#include "wzd_configfile.h"
#include "wzd_configloader.h"
#include "wzd_dir.h"
#include "wzd_crontab.h"
#include "wzd_file.h"
#include "wzd_fs.h"
#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_perm.h"
#include "wzd_site.h"
#include "wzd_site_group.h"
#include "wzd_site_user.h"
#include "wzd_socket.h"
#include "wzd_string.h"
#include "wzd_threads.h"
#include "wzd_utf8.h"
#include "wzd_vars.h"
#include "wzd_vfs.h"


#include "wzd_debug.h"

#endif /* __WZD_ALL__ */

#else /* WZD_USE_PCH */

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#endif /* WZD_USE_PCH */

