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
 * \file libwzd_lua_main.c
 * \brief Lua module interface functions
 * \addtogroup module_lua
 * @{
 */

static int _hook_protocol(const char *file, const char *args);

MODULE_NAME(lua);
MODULE_VERSION(1);

/**
 * \brief This function is called when the module is loaded.
 */
int WZD_MODULE_INIT(void)
{
  if (libwzd_lua_state_init() == -1) {
    return -1;
  }

  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_LOGOUT,
                         libwzd_lua_state_logout, NULL);

  hook_add_protocol("lua:", 4, &_hook_protocol);

  out_log(LEVEL_INFO, "Lua module loaded\n");
  return 0;
}

/**
 * \brief This function is called when the module is unloaded.
 */
void WZD_MODULE_CLOSE(void)
{
  
  libwzd_lua_state_finalize();
  out_log(LEVEL_INFO, "Lua module unloaded\n");
}

/**
 * \brief Parse argument string.
 * \param copy the argument string list.
 * \param argc returned count.
 * \param argv returned array.
 */
static void _parse_args(char *copy, int *argc, char ***argv)
{
  char *motif[2] = { " \t", "\"" };
  char *found, *save , *tmp;
  int len, curr = 0;

  *argc = 0;
  *argv = NULL;

  if (copy[0] == '"') curr = 1;
  while ( ( found = strtok_r(copy, motif[curr], &save) ) != NULL) {
    *argv = realloc(*argv, sizeof(char *) * (*argc + 2));
    (*argv)[(*argc)] = found;
    (*argv)[(*argc) + 1] = NULL;
    (*argc)++;

    curr = 0;
    if (save != NULL) {
      len = strlen(save);
      
      if (len >= 1 && save[0] == '"') curr = 1;
      if (len >= 2 && save[1] == '"') {
        tmp = & save[1];
        
        save[0] = '\0';
        free(save);

        save = tmp;
        curr = 1;
      }
    }
    copy = NULL;
  }
}

/**
 * \brief Lua protocol hook function (lua:)
 */
static int _hook_protocol(const char *file, const char *args)
{
  int i;
  int argc=0;
  char *copy = NULL;
  char **argv = NULL;

  lua_State *state = NULL;
  char buffer[256];

  out_log(LEVEL_INFO, "lua: hook %s(%s)\n", file, args);

  libwzd_lua_state_get(GetMyContext(), &state);

  copy = strdup(args);
  _parse_args(copy, &argc, &argv);
  
  lua_newtable(state);
  for(i = argc - 1; i >= 0; i--) {
    lua_pushnumber(state, i + 1);
    lua_pushstring(state, argv[i]);
    lua_settable(state, -3);
  }
  lua_setglobal(state, "args");
  
  free(copy);
  if (argc > 0) free(argv);

  if ( luaL_dofile(state, file) == 1) {
    out_log(LEVEL_INFO, "lua %s error: %s\n", file, lua_tostring(state,-1));
    snprintf(buffer, sizeof(buffer), "501 - lua: cannot execute script %s\n", file);
    send_message_raw(buffer, GetMyContext());
  }

  if ( lua_gettop(state) == 1) {
    return lua_tointeger(state, 1);
  }

  return 0;
}

/** @} */

