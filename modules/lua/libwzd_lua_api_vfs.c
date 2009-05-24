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
 * \file libwzd_lua_api_vfs.c
 * \brief Lua module vfs api functions
 * \addtogroup module_lua
 * @{
 */

#include "libwzd_lua.h"

static int _api_vfs_read(lua_State *state);
static int _api_vfs_mkdir(lua_State *state);
static int _api_vfs_rmdir(lua_State *state);
static int _api_vfs_link_create(lua_State *state);
static int _api_vfs_link_remove(lua_State *state);
static int _api_vfs_ftp2sys(lua_State *state);
static int _api_vfs_chgrp(lua_State *state);
static int _api_vfs_chown(lua_State *state);
static int _api_vfs_chmod(lua_State *state);

/**
 * \brief wzd.vfs.link.* functions
 */
static const struct libwzd_lua_api_func_s _api_vfs_link_funcs[] = {
  { "create", _api_vfs_link_create },
  { "remove", _api_vfs_link_remove },
  { NULL, NULL }
};

/**
 * \brief wzd.vfs.* functions
 */
const struct libwzd_lua_api_func_s libwzd_lua_api_vfs_funcs[] = {
  { "read", _api_vfs_read },
  { "mkdir", _api_vfs_mkdir },
  { "rmdir", _api_vfs_rmdir },
  { "ftp2sys", _api_vfs_ftp2sys },
  { "chgrp", _api_vfs_chgrp },
  { "chown", _api_vfs_chown },
  { "chmod", _api_vfs_chmod },
  { NULL, NULL }
};

/**
 * \brief wzd.vfs.* tables
 */
const struct libwzd_lua_api_table_s libwzd_lua_api_vfs_tables[] = {
  { "link", NULL, _api_vfs_link_funcs, NULL },
  { NULL, NULL, NULL, NULL },
};

/**
 * \brief Read information about a file.
 */
static int _api_vfs_read(lua_State *state)
{
  int argc, real = 0;
  const char *path;
  struct wzd_file_t *file;
  char real_path[WZD_MAX_PATH + 1];
  
  argc = lua_gettop(state);
  if (argc < 1) {
    lua_pushstring(state, "wzd.vfs.read(path [, real] )");
    lua_error(state);
  }

  path = lua_tostring(state, 1);

  if (argc > 1) {
    real = lua_toboolean(state, 2);
  }

  if (real == 1) {
    strncpy(real_path, path, sizeof(real_path));
  } else {
    if (checkpath_new(path, real_path, GetMyContext()) ) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }

  file = file_stat(real_path, GetMyContext());
  if (file == NULL) {
    lua_pushnil(state);
    return 1;
  }

  lua_newtable(state);

  lua_pushstring(state, "filename");
  lua_pushstring(state, file->filename);
  lua_settable(state, -3);

  lua_pushstring(state, "owner");
  lua_pushstring(state, file->owner);
  lua_settable(state, -3);

  lua_pushstring(state, "group");
  lua_pushstring(state, file->group);
  lua_settable(state, -3);

  lua_pushstring(state, "permissions");
  lua_pushinteger(state, file->permissions);
  lua_settable(state, -3);

  lua_pushstring(state, "kind");
  lua_pushinteger(state, file->kind);
  lua_settable(state, -3);

  return 1; 
}

/**
 * \brief Create a directory.
 */
static int _api_vfs_mkdir(lua_State *state)
{
  int argc;
  int real = 0;
  int i_mode = 0755;
  const char *path, *s_mode;
  char real_path[WZD_MAX_PATH + 1];
  
  argc = lua_gettop(state);
  if (argc < 1) {
    lua_pushstring(state, "wzd.vfs.mkdir(path [, mode [, real] ] )");
    lua_error(state);
  }

  path = lua_tostring(state, 1);

  if (argc > 1) {
    s_mode = lua_tostring(state, 2);
    i_mode = (int) strtol(s_mode, NULL, 8);
  }

  if (argc > 2) {
    real = lua_toboolean(state, 3);
  }

  if (real == 1) {
    strncpy(real_path, path, sizeof(real_path));
  } else {
    if (checkpath_new(path, real_path, GetMyContext()) != E_FILE_NOEXIST) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }

  if ( file_mkdir(real_path, i_mode, GetMyContext()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Delete a directory.
 */
static int _api_vfs_rmdir(lua_State *state)
{
  int argc, real = 0;
  const char *path;
  char real_path[WZD_MAX_PATH + 1];
  
  argc = lua_gettop(state);
  if (argc < 1) {
    lua_pushstring(state, "wzd.vfs.rmdir(path [, real] )");
    lua_error(state);
  }

  path = lua_tostring(state, 1);

  if (argc > 1) {
    real = lua_toboolean(state, 2);
  }

  if (real == 1) {
    strncpy(real_path, path, sizeof(real_path));
  } else {
    if (checkpath_new(path, real_path, GetMyContext()) ) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }

  if ( file_rmdir(real_path, GetMyContext()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1; 
}

/**
 * \brief create a link
 */
static int _api_vfs_link_create(lua_State *state)
{
  int argc;
  int real = 0;
  const char *path, *link;

  char real_path[WZD_MAX_PATH + 1];
  char real_link[WZD_MAX_PATH + 1];
  
  argc = lua_gettop(state);
  if (argc < 2) {
    lua_pushstring(state, "wzd.vfs.link.create(path, link [, real] ] )");
    lua_error(state);
  }

  path = lua_tostring(state, 1);
  link = lua_tostring(state, 2);

  if (argc > 2) {
    real = lua_toboolean(state, 3);
  }

  /* path */
  if (real == 1) {
    strncpy(real_path, path, sizeof(real_path));
  } else {
    if (checkpath_new(path, real_path, GetMyContext()) != E_FILE_NOEXIST) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }

  /* link */
  if (real == 1) {
    strncpy(real_link, link, sizeof(real_link));
  } else {
    if (checkpath_new(link, real_link, GetMyContext()) != E_FILE_NOEXIST) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }
  
  REMOVE_TRAILING_SLASH(real_path);
  REMOVE_TRAILING_SLASH(real_link);

  if (symlink_create(real_path, real_link) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Remove a link.
 */
static int _api_vfs_link_remove(lua_State *state)
{
  int argc, real = 0;
  const char *link;
  char real_link[WZD_MAX_PATH + 1];
  
  argc = lua_gettop(state);
  if (argc < 1) {
    lua_pushstring(state, "wzd.vfs.link.remove(link [, real] )");
    lua_error(state);
  }

  link = lua_tostring(state, 1);

  if (argc > 1) {
    real = lua_toboolean(state, 2);
  }

  if (real == 1) {
    strncpy(real_link, link, sizeof(real_link));
  } else {
    if (checkpath_new(link, real_link, GetMyContext()) ) {
      lua_pushboolean(state, 0);
      return 1;
    }
  }

  if ( symlink_remove(real_link) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1; 
}

/**
 * \brief convert a ftp path to a system path.
 */
static int _api_vfs_ftp2sys(lua_State *state)
{
  const char *path;
  char real_path[WZD_MAX_PATH + 1];
  
  if (lua_gettop(state) != 1) {
    lua_pushstring(state, "wzd.vfs.ftp2sys(path)");
    lua_error(state);
  }

  path = lua_tostring(state, 1);

  if (checkpath_new(path, real_path, GetMyContext())) {
    lua_pushnil(state);
    return 1;
  }

  lua_pushstring(state, real_path);
  return 1;
}

/**
 * \brief Change group owner.
 */
static int _api_vfs_chgrp(lua_State *state)
{
  char real_path[WZD_MAX_PATH + 1];
  const char *groupname, *path;

  if (lua_gettop(state) == 2) {
    lua_pushstring(state, "wzd.vfs.chgrp(groupname, path)");
    lua_error(state);
  }

  groupname = lua_tostring(state, 1);
  path = lua_tostring(state, 2);

  if (checkpath_new(path, real_path, GetMyContext()) != E_OK) {
    lua_pushboolean(state, 0);
    return 1;
  }

  if (file_chown(real_path, NULL, groupname, GetMyContext()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  return 1;
}

/**
 * \brief Change user owner
 */
static int _api_vfs_chown(lua_State *state)
{
  char *copy;
  char real_path[WZD_MAX_PATH + 1];
  const char *usergroup, *path, *user = NULL, *group = NULL;

  if (lua_gettop(state) == 2) {
    lua_pushstring(state, "wzd.vfs.chown(username, path)");
    lua_error(state);
  }

  usergroup = lua_tostring(state, 1);
  path = lua_tostring(state, 2);

  copy = strdup(usergroup);
  /* group only */
  if (copy[0] == ':') {
    group = & copy[1];
  } 
  /* user only */
  else if (strchr(usergroup, ':') == NULL) {
    user = copy;
  }
  /* both */
  else {
    user = strtok(copy, ":");
    group = strtok(NULL, ":");
  }

  if (checkpath_new(path, real_path, GetMyContext()) != E_OK) {
    lua_pushboolean(state, 0);
    return 1;
  }

  if (file_chown(real_path, user, group, GetMyContext()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }

  free(copy);

  return 1;
}

/**
 * \brief Change permission.
 */
static int _api_vfs_chmod(lua_State *state)
{
  unsigned long perms;
  const char *mode, *path;
  char *end, real_path[WZD_MAX_PATH + 1];

  if (lua_gettop(state) != 2) {
    lua_pushstring(state, "wzd.vfs.chmod(mode, path)");
    lua_error(state);
  }

  mode = lua_tostring(state, 1);
  perms = strtoul(mode, &end, 8);
  if (end == mode) {
    lua_pushboolean(state, 0);
    return 1;
  }

  path = lua_tostring(state, 2);
  if ( checkpath_new(path, real_path, GetMyContext()) != E_OK) {
    lua_pushboolean(state, 0);
    return 1;
  }

  if (_setPerm(path, NULL, NULL, NULL, NULL, perms, GetMyContext()) == 0) {
    lua_pushboolean(state, 1);
  } else {
    lua_pushboolean(state, 0);
  }
  
  return 1;
}

/** @} */

