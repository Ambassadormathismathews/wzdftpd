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
 * \file libwzd_lua_api_shm.c
 * \brief Lua module shm api functions
 * \addtogroup module_lua
 * @{
 */

#include "libwzd_lua.h"

static int _api_shm_get(lua_State *state);
static int _api_shm_set(lua_State *state);

/**
 * \brief wzd.shm.* functions
 */
const struct libwzd_lua_api_func_s libwzd_lua_api_shm_funcs[] = {
  { "get", _api_shm_get },
  { "set", _api_shm_set },
  { NULL, NULL }
};

/**
 * \brief Get a value from shm.
 */
static int _api_shm_get(lua_State *state)
{
  int argc, ret;
  char *buffer;
  const char *var_name;
  
  argc = lua_gettop(state);
  if (argc != 1) {
    lua_pushstring(state, "wzd.shm.get(var_name)");
    lua_error(state);
  }

  var_name = lua_tostring(state, 1);
  buffer = wzd_malloc(1024);

  ret = vars_shm_get(var_name, buffer, 1024, getlib_mainConfig());
  if (ret == 0)
    lua_pushstring(state, buffer);
  else
    lua_pushnil(state);

  wzd_free(buffer);

  return 1;
}

/**
 * \brief Set a value to shm.
 */
static int _api_shm_set(lua_State *state)
{
  int argc, ret;
  const char *var_name;
  const char *var_value;
  
  argc = lua_gettop(state);
  if (argc != 2) {
    lua_pushstring(state, "wzd.shm.set(var_name, var_value)");
    lua_error(state);
  }

  var_name = lua_tostring(state, 1);
  var_value = lua_tostring(state, 2);

  ret = vars_shm_set(var_name, var_value, strlen(var_value)+1,
                     getlib_mainConfig()); 
  if (ret == 0)
    lua_pushboolean(state, 1);
  else
    lua_pushboolean(state, 0);

  return 1;
}

/**
 * @}
 */

