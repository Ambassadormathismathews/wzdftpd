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

#include "libwzd_lua.h"

/**
 * \file libwzd_lua_api.c
 * \brief Lua module api function 
 * \addtogroup module_lua
 * @{
 */

/**
 * \brief declare 'wzd' as root table
 */
static struct libwzd_lua_api_table_s _api_root_tables[] = {
  {"wzd", NULL, libwzd_lua_api_wzd_funcs, libwzd_lua_api_wzd_tables },
  { NULL, NULL, NULL, NULL },
};

/**
 * \brief Setup functions in a table
 * \param state A lua state
 * \param funcs Functions list
 */
static void _api_setup_funcs(lua_State *state, const struct libwzd_lua_api_func_s *funcs)
{
  int i;
  for (i=0; funcs[i].name != NULL; i++) {
    lua_pushstring(state, funcs[i].name);
    lua_pushcfunction(state, funcs[i].func);
    lua_settable(state, -3);
  }
}

/**
 * \brief Setup consts in a table
 * \param state A lua state
 * \param consts Consts list
 */
static void _api_setup_consts(lua_State *state, const struct libwzd_lua_api_const_s *consts)
{
  int i;
  for (i=0; consts[i].name != NULL; i++) {
    lua_pushstring(state, consts[i].name);
    lua_pushinteger(state, consts[i].value);
    lua_settable(state, -3);
  }
}

/**
 * \brief Setup tables in a table.
 *
 * \param state A lua state
 * \param tables Tables list
 * \param child 0=root, incremented when child declare a table.
 */
static void _api_setup_tables(lua_State *state, const struct libwzd_lua_api_table_s *tables, int child)
{
  int i;

  for (i=0; tables[i].name != NULL; i++) {

    if (child > 0) {
      lua_pushstring(state, tables[i].name);
    }

    lua_newtable(state);
    
    if (tables[i].consts != NULL) {
      _api_setup_consts(state, tables[i].consts);
    }

    if (tables[i].funcs != NULL) {
      _api_setup_funcs(state, tables[i].funcs);
    }

    if (tables[i].tables != NULL) {
      _api_setup_tables(state, tables[i].tables, child + 1);
    }

    if (child > 0) {
      lua_settable(state, -3);
    } else {
      /* this is the root table */
      lua_setglobal(state, tables[i].name);
    }

  }
}

/**
 * \brief Setup wzdftpd api in a lua state.
 * \param state A lua state
 */
void libwzd_lua_api_setup(lua_State *state)
{
  _api_setup_tables(state, _api_root_tables, 0);
}

/** @} */

