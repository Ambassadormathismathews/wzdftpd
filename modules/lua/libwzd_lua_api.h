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
 * \file libwzd_lua_api.h
 * \brief 
 * \addtogroup module_lua
 * @{
 */

#ifndef __LIBWZD_LUA_API__
#define __LIBWZD_LUA_API__

/**
 * \brief Used to declare const in a lua table.
 */
struct libwzd_lua_api_const_s {
  const char *name;        /**< \brief lua const name */
  const lua_Integer value; /**< \brief lua const value */
};

/**
 * \brief Used to declare functions in a lua table.
 */
struct libwzd_lua_api_func_s {
  const char *name;         /**< \brief lua function name */
  const lua_CFunction func; /**< \brief lua C function */
};

/**
 * \brief Used to declare tables.
 */
struct libwzd_lua_api_table_s {
  const char *name;                      /**< \brief lua table name */
  const struct libwzd_lua_api_const_s *consts; /**< \brief lua table's consts */
  const struct libwzd_lua_api_func_s *funcs;   /**< \brief lua table's functions */
  const struct libwzd_lua_api_table_s *tables; /**< \brief lua table's tables */
};

/** global variables **/
extern const struct libwzd_lua_api_const_s libwzd_lua_api_event_consts[];
extern const struct libwzd_lua_api_const_s libwzd_lua_api_file_consts[];
extern const struct libwzd_lua_api_const_s libwzd_lua_api_level_consts[];

extern const struct libwzd_lua_api_func_s  libwzd_lua_api_wzd_funcs[];
extern const struct libwzd_lua_api_table_s libwzd_lua_api_wzd_tables[];

extern const struct libwzd_lua_api_func_s  libwzd_lua_api_group_funcs[];
extern const struct libwzd_lua_api_table_s libwzd_lua_api_group_tables[];

extern const struct libwzd_lua_api_func_s  libwzd_lua_api_shm_funcs[];

extern const struct libwzd_lua_api_func_s  libwzd_lua_api_user_funcs[];
extern const struct libwzd_lua_api_table_s libwzd_lua_api_user_tables[];

extern const struct libwzd_lua_api_func_s  libwzd_lua_api_vfs_funcs[];
extern const struct libwzd_lua_api_table_s libwzd_lua_api_vfs_tables[];

/** functions **/
void libwzd_lua_api_setup(lua_State *state);

#endif /* __LIBWZD_LUA_API__ */

/** @} */

