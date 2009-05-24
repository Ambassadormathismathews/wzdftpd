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
 * \file libwzd_lua_api_user.c
 * \brief Lua module user api functions
 * \addtogroup module_lua
 * @{
 */

#include "libwzd_lua.h"

static int _api_user_new(lua_State *state);
static int _api_user_get(lua_State *state);
static int _api_user_field_get(lua_State *state);
static int _api_user_field_set(lua_State *state);
static int _api_user_group_list(lua_State *state);
static int _api_user_ip_add(lua_State *state);
static int _api_user_ip_del(lua_State *state);
static int _api_user_ip_list(lua_State *state);

static const struct libwzd_lua_api_func_s _api_user_field_funcs[] = {
  { "get", _api_user_field_get },
  { "set", _api_user_field_set },
  { NULL, NULL }
};

static const struct libwzd_lua_api_func_s _api_user_ip_funcs[] = {
  { "add", _api_user_ip_add },
  { "del", _api_user_ip_del },
  { "list", _api_user_ip_list },
  { NULL, NULL }
};

static const struct libwzd_lua_api_func_s _api_user_group_funcs[] = {
  { "add", NULL },
  { "del", NULL },
  { "list", _api_user_group_list },
};

const struct libwzd_lua_api_func_s libwzd_lua_api_user_funcs[] = {
  { "new", _api_user_new },
  { "del", NULL },
  { "get", _api_user_get },
  { "set", NULL },
};

const struct libwzd_lua_api_table_s libwzd_lua_api_user_tables[] = {
  { "field", NULL, _api_user_field_funcs, NULL },
  { "group", NULL, _api_user_group_funcs, NULL },
  { "ip", NULL, _api_user_ip_funcs, NULL },
  { NULL, NULL, NULL, NULL }
};


/**
 * \brief Create a new user
 */
static int _api_user_new(lua_State *state)
{
  const char *username, *password, *group;

  if (lua_gettop(state) != 3) {
    lua_pushstring(state, "wzd.user.new(username, password, group)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);
  password = lua_tostring(state, 2);
  group = lua_tostring(state, 3);

  if (vars_user_new(username, password, group, getlib_mainConfig()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Retrieve all user's fields.
 */
static int _api_user_get(lua_State *state)
{
  wzd_user_t *user;
  const char *username;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.user.get(username)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);

  user = user_get_by_name(username);
  if (user == NULL) {
    lua_pushnil(state);
    return 1;
  }

  lua_newtable(state);

  lua_pushstring(state, "uid");
  lua_pushinteger(state, user->uid);
  lua_settable(state, -3);

  lua_pushstring(state, "username");
  lua_pushstring(state, user->username);
  lua_settable(state, -3);

  lua_pushstring(state, "rootpath");
  lua_pushstring(state, user->rootpath);
  lua_settable(state, -3);

  lua_pushstring(state, "tagline");
  lua_pushstring(state, user->tagline);
  lua_settable(state, -3);

  lua_pushstring(state, "num_logins");
  lua_pushinteger(state, user->num_logins);
  lua_settable(state, -3);

  lua_pushstring(state, "credits");
  lua_pushinteger(state, user->credits);
  lua_settable(state, -3);

  lua_pushstring(state, "ratio");
  lua_pushinteger(state, user->ratio);
  lua_settable(state, -3);

  lua_pushstring(state, "flags");
  lua_pushstring(state, user->flags);
  lua_settable(state, -3);

  return 1;  
}

/**
 * \brief Retrieve a user's field. 
 */
static int _api_user_field_get(lua_State *state)
{
  int ret;
  char *buffer;
  const char *username, *fieldname;

  if (lua_gettop(state) != 2) {
    lua_pushstring(state, "wzd.user.field.get(username, fieldname)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);
  fieldname = lua_tostring(state, 2);

  buffer = wzd_malloc(1024);

  ret = vars_user_get(username, fieldname, buffer, 1024, getlib_mainConfig());
  if (ret == 0) {
    lua_pushstring(state, buffer);
  } else {
    lua_pushnil(state);
  }

  wzd_free(buffer);

  return 1;
}

/**
 * \brief Change a field value. 
 */
static int _api_user_field_set(lua_State *state)
{
  int ret;
  const char *username, *fieldname, *fieldvalue;

  if (lua_gettop(state) != 3) {
    lua_pushstring(state,
      "wzd.user.field.get(username, fieldname, fieldvalue)"
    );
    lua_error(state);
  }

  username = lua_tostring(state, 1);
  fieldname = lua_tostring(state, 2);
  fieldvalue = lua_tostring(state, 3);

  ret = vars_user_set(username, fieldname, fieldvalue, strlen(fieldvalue),
                      getlib_mainConfig());

  if (ret == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Get list of user's group. 
 */
static int _api_user_group_list(lua_State *state)
{
  unsigned int i;
  const char *username;
  wzd_user_t *user;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.user.group.list(username)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);

  user = user_get_by_name(username);
  if (user == NULL) {
    lua_pushnil(state);
    return 1;
  }

  lua_newtable(state);
  for (i=0; i < user->group_num; i++) {
    lua_pushinteger(state, i);
    lua_pushinteger(state, user->groups[i]);
    lua_settable(state, -3);
  }

  return 1;
}

/**
 * \brief Add an ip to an user.
 */
static int _api_user_ip_add(lua_State *state)
{
  const char *username, *ip;

  if (lua_gettop(state) != 2) {
    lua_pushstring(state, "wzd.user.ip.add(username, ip)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);
  ip = lua_tostring(state, 2);

  if (vars_user_addip(username, ip, getlib_mainConfig()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }
  return 1;
}

/**
 * \brief Remove an ip to a user. 
 */
static int _api_user_ip_del(lua_State *state)
{
  const char *username, *ip;

  if (lua_gettop(state) != 2) {
    lua_pushstring(state, "wzd.user.ip.del(username, ip)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);
  ip = lua_tostring(state, 2);

  if (vars_user_delip(username, ip, getlib_mainConfig()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Get user's ip list.
 * \param state the lua state.
 */
static int _api_user_ip_list(lua_State *state)
{
  unsigned int i;
  wzd_user_t *user;
  struct wzd_ip_list_t *ip;
  const char *username;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.user.ip.list(username)");
    lua_error(state);
  }

  username = lua_tostring(state, 1);

  user = user_get_by_name(username);
  if (user == NULL) {
    lua_pushnil(state);
    return 1;
  }

  lua_newtable(state);
  for(i=0, ip=user->ip_list; ip != NULL; i++, ip=ip->next_ip) {
    lua_pushinteger(state, i);
    lua_pushstring(state, ip->regexp);
    lua_settable(state, -3);
  }
  
  return 1;
}

/** @} */

