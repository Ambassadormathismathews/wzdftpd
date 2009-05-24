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
 * \file libwzd_lua_api_wzd.c
 * \brief Lua module api wzd table 
 * \addtogroup module_lua
 * @{
 */

static int _api_put_log(lua_State *state);
static int _api_send_message(lua_State *state);
static int _api_send_message_raw(lua_State *state);
static int _api_killpath(lua_State *state);

/**
 * \brief wzd.event. consts
 */
static const struct libwzd_lua_api_const_s _api_event_consts[] = {
  { "error", EVENT_ERROR },
  { "ok", EVENT_OK },
  { "break", EVENT_BREAK },
  { "deny", EVENT_DENY },
  { "ignored", EVENT_IGNORED },
  { "next", EVENT_NEXT },
  { "handled", EVENT_HANDLED },
  { "err", EVENT_ERR },
  { NULL, 0 }
};

/**
 * \brief wzd.file. consts
 */
static const struct libwzd_lua_api_const_s _api_file_consts[] = {
  { "notset", FILE_NOTSET },
  { "reg", FILE_REG },
  { "dir", FILE_DIR },
  { "lnk", FILE_LNK },
  { "vfs", FILE_VFS },
  { NULL, 0 },
};

/**
 * \brief wzd.level consts
 */
static const struct libwzd_lua_api_const_s _api_level_consts[] = {
  { "lowest", LEVEL_LOWEST },
  { "flood", LEVEL_FLOOD },
  { "info", LEVEL_INFO },
  { "normal", LEVEL_NORMAL },
  { "high", LEVEL_HIGH },
  { "critical", LEVEL_CRITICAL },
  { NULL, 0 },
};

/**
 * \brief wzd. functions
 */
const struct libwzd_lua_api_func_s libwzd_lua_api_wzd_funcs[] = {
  { "put_log", _api_put_log },
  { "send_message", _api_send_message },
  { "send_message_raw", _api_send_message_raw },
  { "killpath", _api_killpath },
  { NULL, NULL }
};

/**
 * \brief declaration of 'wzd' table
 */
const struct libwzd_lua_api_table_s libwzd_lua_api_wzd_tables[] = {
  { "event", _api_event_consts, NULL, NULL },
  { "file", _api_file_consts, NULL, NULL },
  { "level", _api_level_consts, NULL, NULL },
  { "group", NULL, libwzd_lua_api_group_funcs, libwzd_lua_api_group_tables },
  { "shm", NULL, libwzd_lua_api_shm_funcs, NULL },
  { "user", NULL, libwzd_lua_api_user_funcs, libwzd_lua_api_user_tables },
  { "vfs", NULL, libwzd_lua_api_vfs_funcs, libwzd_lua_api_vfs_tables },
  { NULL, NULL, NULL, NULL }
};

/**
 * \brief Put a log.
 */
static int _api_put_log(lua_State *state)
{
  int level;
  const char *message;

  if (lua_gettop(state) != 2) {
    lua_pushstring(state, "wzd_put_log(level, message)");
    lua_error(state);
  }

  level = lua_tointeger(state, 1);
  message = lua_tostring(state, 2);

  out_log(level, message);
 
  return 0;
}

/**
 * \brief Send a ftp message to the current context. (with cookies)
 */
static int _api_send_message(lua_State *state)
{
  char *message;

  wzd_context_t *context = GetMyContext();
  wzd_user_t *user = context ? GetUserByID(context->userid) : NULL;
  wzd_group_t *group = context ? GetGroupByID(user->groups[0]) : NULL;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd_send_message(message)");
    lua_error(state);
  }
  
  if (context == NULL) {
    lua_pushstring(state, "wzd_send_message(): cannot retrieve current context.");
    lua_error(state);
  }

  message = wzd_malloc(4096);
  *message = '\0';

  cookie_parse_buffer(lua_tostring(state, 1), user, group, context, 
                      message, 4096);

  send_message_raw(message, context);

  wzd_free(message);

  return 0;
}

/**
 * \brief Send a ftp message to the current context. (without cookies)
 */
static int _api_send_message_raw(lua_State *state)
{
  wzd_context_t *context = GetMyContext();
  const char *message;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.send_message_raw(message)");
    lua_error(state);
  }

  if (context == NULL) {
    lua_pushstring(state, "wzd.send_message_raw(): cannot retrieve context");
    lua_error(state);
  }

  message = lua_tostring(state, 1);

  send_message_raw(message, context);

  return 0;
}

/**
 * \brief Kill all users in a path.
*/
static int _api_killpath(lua_State *state)
{
  int argc, real = 0;
  const char* path;
  char real_path[WZD_MAX_PATH + 1];

  argc = lua_gettop(state);
  if (argc < 1) {
    lua_pushstring(state, "wzd.killpath(path [, real] )");
    lua_error(state);
  }

  path = lua_tostring(state, 1);

  if (argc > 2) {
    real = lua_toboolean(state, 2);
  }

  if (real == 1) {
    strncpy(real_path, path, sizeof(real_path));
  } else {
    if (checkpath_new(path, real_path, GetMyContext())) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }

  if (killpath(real_path, GetMyContext()) == E_OK) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * @}
 */

