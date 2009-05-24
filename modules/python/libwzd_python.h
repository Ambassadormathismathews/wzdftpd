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

#ifndef __LIBWZD_PYTHON__
#define __LIBWZD_PYTHON__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <io.h>

#include "../../visual/gnu_regex/regex.h"
#else
#include <dirent.h>
#include <sys/types.h>
#include <regex.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _POSIX_C_SOURCE
#  undef _POSIX_C_SOURCE /* avoid a warning. */
#endif
#include <Python.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_configfile.h> /* server configuration */
#include <libwzd-core/wzd_file.h> /* file_mkdir, file_stat */
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_mod.h> /* essential to define WZD_MODULE_INIT */
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_vfs.h> /* checkpath_new */
#include <libwzd-core/wzd_vars.h> /* needed to access variables */
#include <libwzd-core/wzd_debug.h>

#include "libwzd_python_wzd.h"
#include "libwzd_python_wzd_exc.h"
#include "libwzd_python_wzd_user.h"
#include "libwzd_python_wzd_shm.h"
#include "libwzd_python_wzd_group.h"
#include "libwzd_python_wzd_vfs.h"

#endif /* __LIBWZD_PYTHON__ */

