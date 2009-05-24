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
 * \file libwzd_lua_api_group.c
 * \brief Lua module group api functions
 * \addtogroup module_lua
 * @{
 */

#include "libwzd_lua.h"

static int _api_group_new(lua_State *state);
static int _api_group_get(lua_State *state);
static int _api_group_field_get(lua_State *state);
static int _api_group_field_set(lua_State *state);
static int _api_group_ip_list(lua_State *state);

/**
 * \brief wzd.group.field. functions
 */
static const struct libwzd_lua_api_func_s _api_group_field_funcs[] = {
  { "get", _api_group_field_get },
  { "set", _api_group_field_set },
  { NULL, NULL }
};

/**
 * \brief wzd.group.ip. functions
 */
static const struct libwzd_lua_api_func_s _api_group_ip_funcs[] = {
  { "add", NULL },
  { "del", NULL },
  { "list", _api_group_ip_list },
  { NULL, NULL }
};


/**
 * \brief wzd.group. functions
 */
const struct libwzd_lua_api_func_s libwzd_lua_api_group_funcs[] = {
  { "new", _api_group_new },
  { "del", NULL },
  { "get", _api_group_get },
  { "set", NULL },
  { NULL, NULL }
};

/**
 * \brief wzd.group. tables
 */
const struct libwzd_lua_api_table_s libwzd_lua_api_group_tables[] = {
  { "field", NULL, _api_group_field_funcs, NULL },
  { "ip", NULL, _api_group_ip_funcs, NULL },
  { NULL, NULL, NULL, NULL }
};

/**
 * \brief Create a new group.
 */
static int _api_group_new(lua_State *state)
{
  int ret;
  const char *groupname;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.group.new(groupname)");
    lua_error(state);
  }

  groupname = lua_tostring(state, 1);
  
  ret = vars_group_new(groupname, getlib_mainConfig());
  if (ret == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Retrieve group's fields.
 */
static int _api_group_get(lua_State *state)
{
  wzd_group_t *group;
  const char *groupname;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.group.get(groupname)");
    lua_error(state);
  }

  groupname = lua_tostring(state, 1);
  group = group_get_by_name(groupname);

  if (group == NULL) {
    lua_pushnil(state);
    return 1;
  }

  lua_newtable(state);

  lua_pushstring(state, "gid");
  lua_pushinteger(state, group->gid);
  lua_settable(state, -3);

  lua_pushstring(state, "groupname");
  lua_pushstring(state, group->groupname);
  lua_settable(state, -3);

  lua_pushstring(state, "tagline");
  lua_pushstring(state, group->tagline);
  lua_settable(state, -3);

  lua_pushstring(state, "max_idle_time");
  lua_pushinteger(state, group->max_idle_time);
  lua_settable(state, -3);

  lua_pushstring(state, "max_ul_speed");
  lua_pushinteger(state, group->max_ul_speed);
  lua_settable(state, -3);

  lua_pushstring(state, "max_dl_speed");
  lua_pushinteger(state, group->max_dl_speed);
  lua_settable(state, -3);

  lua_pushstring(state, "ratio");
  lua_pushinteger(state, group->ratio);
  lua_settable(state, -3);

  lua_pushstring(state, "defaultpath");
  lua_pushstring(state, group->defaultpath);
  lua_settable(state, -3);

  return 1;
}

/**
 * \brief Retrieve a field.
 */
static int _api_group_field_get(lua_State *state)
{
  int ret;
  char *buffer;
  const char *groupname, *fieldname;

  if (lua_gettop(state) != 2) {
    lua_pushstring(state, "wzd.group.field.get(groupname, fieldname)");
    lua_error(state);
  }

  groupname = lua_tostring(state, 1);
  fieldname = lua_tostring(state, 2);
  
  buffer = wzd_malloc(1024);

  ret = vars_group_get(groupname, fieldname, buffer, 1024, getlib_mainConfig());
  if (ret == 0) {
    lua_pushstring(state, buffer);
  } else {
    lua_pushnil(state);
  }

  wzd_free(buffer);

  return 1;
}

/**
 * \brief Set a field.
 */
static int _api_group_field_set(lua_State *state)
{
  int ret;
  const char *groupname, *fieldname, *fieldvalue;

  if (lua_gettop(state) != 3) {
    lua_pushstring(state, "wzd.group.field.set(groupname, fieldname, fieldvalue)");
    lua_error(state);
  }

  groupname = lua_tostring(state, 1);
  fieldname = lua_tostring(state, 2);
  fieldvalue = lua_tostring(state, 3);
  
  ret = vars_group_set(groupname, fieldname, fieldvalue, strlen(fieldvalue), getlib_mainConfig());
  if (ret == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Retrieve ip list.
 */
static int _api_group_ip_list(lua_State *state)
{
  unsigned int i;
  struct wzd_ip_list_t *curr;
  wzd_group_t *group;
  const char *groupname;

  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.group.ip.list(groupname)");
    lua_error(state);
  }

  groupname = lua_tostring(state, 1);
  group = group_get_by_name(groupname);

  if (group == NULL) {
    lua_pushnil(state);
    return 1;
  }

  lua_newtable(state);
  for (i=0, curr = group->ip_list; curr != NULL; curr = curr->next_ip, i++) {
    lua_pushinteger(state, i);
    lua_pushstring(state, curr->regexp);
    lua_settable(state, -3);
  }

  return 1;
}

/** @} */

