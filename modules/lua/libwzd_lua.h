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

/**
 * \file libwzd_lua.h
 * \brief Lua module global header
 * \addtogroup module_lua
 * @{
 */

#ifndef __LIBWZD_LUA__
#define __LIBWZD_LUA__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_configfile.h> /* server configuration */
#include <libwzd-core/wzd_file.h> /* file_mkdir, file_stat */
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_mod.h> /* essential to define WZD_MODULE_INIT */
#include <libwzd-core/wzd_file.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_mutex.h>
#include <wzd_ip.h>
#include <libwzd-core/wzd_vfs.h> /* checkpath_new */
#include <libwzd-core/wzd_vars.h> /* needed to access variables */
#include <libwzd-core/wzd_debug.h>

/* local include */
#include "libwzd_lua_api.h"
#include "libwzd_lua_state.h"

#endif /* __LIBWZD_LUA__ */

/** @} */

