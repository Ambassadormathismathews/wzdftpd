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

#include "libsqlite.h"

/* IMPORTANT needed to check version */
BACKEND_NAME(sqlite);
BACKEND_VERSION(SQLITE_BACKEND_VERSION);

/** 
 * \file libsqlite_main.c
 * \brief Sqlite backend main functions
 * \addtogroup backend_sqlite
 * @{
 */


#define CACHE
#define BACKEND_ID 1 

/** \brief used to store filepath */
const char *_sqlite_file; 

/** 
 * \brief retrieve a sqlite3 handle with _sqlite_file
 * \return sqlite3 handle or NULL
 */
sqlite3 *libsqlite_open()
{
  sqlite3 *db=NULL;
  if (sqlite3_open(_sqlite_file, &db) != SQLITE_OK) {
    out_log(SQLITE_LOG_CHANNEL, "%s(%s):%d cannot open database file\n", __FILE__, __FUNCTION__, __LINE__);
    out_log(SQLITE_LOG_CHANNEL, "sqlite message: %s\n", sqlite3_errmsg(db));
    libsqlite_close(&db);
    return NULL;
  }
  return db;
}

/**
 * \brief close a sqlite handle and set it to NULL.
 * \param db a pointer to a sqlite3 handle
 */
void libsqlite_close(sqlite3 **db)
{
  if (*db != NULL) sqlite3_close(*db);
  *db = NULL;
}

/**
 * \brief function used to generate update query (printf like).
 * \param query pointer where query is stored. The query must be free with sqlite3_free and can be null for the first use.
 * \param format sqlite3_mprintf format
 * \param ... vars use in format 
 */
void libsqlite_add_to_query(char **query, char *format, ...)
{
  char *new=NULL, *add=NULL;
  va_list va;

  if (!format) return;
  if (! query) return;

  va_start(va, format);
  add = sqlite3_vmprintf(format, va);
  va_end(va);

  if (*query) {
    new = sqlite3_mprintf("%s%s", *query, add);
    sqlite3_free(*query);
    sqlite3_free(add);
    *query = new;
  }
  else {
    *query = add;
  }
}

/**
 * \brief function used to retrieve 3 lists for update, delete,
 *                 and add in database
 * \param curr_in_db list of ips currently in database.
 * \param should_in_db list of ips should be in database.
 * \param delete list of ips should be delete in database.
 * \param add list of ips should be add in database.
 */
void
libsqlite_update_ip(struct wzd_ip_list_t *db,
                    struct wzd_ip_list_t *update,
                    struct wzd_ip_list_t **delete,
                    struct wzd_ip_list_t **add)
{
  unsigned int found;
  struct wzd_ip_list_t *curr_db=NULL;
  struct wzd_ip_list_t *curr_update=NULL;

  /* search for deleted */
  for(curr_db = db; curr_db; curr_db = curr_db->next_ip) {
    found = 0; 
    for(curr_update = update; curr_update; curr_update = curr_update->next_ip) {
      if (strcmp(curr_db->regexp, curr_update->regexp) == 0) {
        found = 1;
      }
    }
    if (found == 0) {
      ip_add_check(delete, curr_db->regexp, 1);
    }
  }
  
  /* search for added */
  for(curr_update = update; curr_update; curr_update = curr_update->next_ip) {
    found = 0;
    for(curr_db = db; curr_db; curr_db = curr_db->next_ip) {
      if (strcmp(curr_db->regexp, curr_update->regexp) == 0) {
        found = 1;
      }
    }
    if (found == 0) {
      ip_add_check(add, curr_update->regexp, 1);
    }
  }
}


static int FCN_INIT(const char *arg)
{
  struct stat st;

  if (log_get(SQLITE_LOG_CHANNEL) == -1)
    log_set(SQLITE_LOG_CHANNEL, log_get(LEVEL_NORMAL));

  if (arg == NULL) {
    out_log(SQLITE_LOG_CHANNEL, "%s(%s):%d no argument given\n", __FILE__, __FUNCTION__, __LINE__);
    out_log(SQLITE_LOG_CHANNEL, "you MUST provide a parameter for the sqlite connection\n");
    out_log(SQLITE_LOG_CHANNEL, "Add 'param=file' in [sqlite]\n");
    return -1;
  }

  if (stat(arg, &st) == -1 || ! st.st_mode & S_IFREG) {
    out_log(SQLITE_LOG_CHANNEL, "Sqlite db file does'nt exist or not a regular file.\n");
    return -1;
  }

  _sqlite_file = arg;

  out_log(SQLITE_LOG_CHANNEL, "Backend sqlite initialized\n");

  return 0;
}

static int FCN_FINI(void)
{
  out_log(SQLITE_LOG_CHANNEL, "Backend sqlite unloading\n");

  return 0;
}

static uid_t FCN_VALIDATE_LOGIN(const char *login, UNUSED wzd_user_t * _ignored)
{
 
  out_log(SQLITE_LOG_CHANNEL, "Backend sqlite search for user '%s'\n", login);

  return libsqlite_user_get_id_by_name(login);
}

static uid_t FCN_VALIDATE_PASS(const char *login, const char *pass, UNUSED wzd_user_t * _ignored)
{
  wzd_user_t * user;

  user = libsqlite_user_get_by_name(login);
  if (user == NULL) return INVALID_USER;

  if (strlen(user->userpass) == 0) {
    out_log(SQLITE_LOG_CHANNEL,"WARNING: empty password field whould not be allowed !\n");
    out_log(SQLITE_LOG_CHANNEL,"WARNING: you should run: UPDATE users SET userpass='%%' WHERE userpass is NULL\n");
    return user->uid; /* passworldless login */
  }

  if (strcmp(user->userpass,"%")==0)
    return user->uid; /* passworldless login */

/*  if (check_auth(login, pass, user->userpass)==1) */
  if (strcmp(user->userpass, pass) == 0)
    return user->uid;

  return INVALID_USER;
}
  
static wzd_user_t * FCN_GET_USER(uid_t uid)
{
  uid_t reg_uid;
  wzd_user_t *user = NULL;

  if (uid == GET_USER_LIST) {
    return (wzd_user_t *) libsqlite_user_get_list();
  }

#ifdef CACHE
  user = user_get_by_id(uid);
  if (user) return user;
#endif

  user = libsqlite_user_get_by_id(uid);

#ifdef CACHE
  if (user) {
    reg_uid = user_register(user, BACKEND_ID);
    if (reg_uid != user->uid) {
      out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could not registre user.\n");
      user_free(user);
      return NULL;
    }
  }
#endif
  return user;
}

static wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  gid_t reg_gid;
  wzd_group_t *group = NULL;

  if (gid == GET_GROUP_LIST) {
    return (wzd_group_t *) libsqlite_group_get_list();
  }

#ifdef CACHE
  group = group_get_by_id(gid);
  if (group) return group;
#endif

  group = libsqlite_group_get_by_id(gid);

#ifdef CACHE
  if (group) {
    reg_gid = group_register(group, BACKEND_ID);
    if (reg_gid != group->gid) {
      out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could not registre group.\n");
      group_free(group);
      return NULL;
    }
  }
#endif
  return group;
}

static uid_t FCN_FIND_USER(const char *name, UNUSED wzd_user_t * _ignored)
{
  uid_t reg_uid;
  wzd_user_t *user=NULL;

#ifdef CACHE
  user = user_get_by_name(name);
  if (user) return user->uid;
#endif /* CACHE */

  user = libsqlite_user_get_by_name(name);
  if (! user) return INVALID_USER;
#ifdef CACHE
  if (user) {
    reg_uid = user_register(user, BACKEND_ID);
    if (reg_uid != user->uid) {
      out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could not registre user.\n");
      user_free(user);
      return INVALID_USER;
    }
  }
#endif /* CACHE */
  return user->uid;
}

static gid_t FCN_FIND_GROUP(const char *name, UNUSED wzd_group_t * _ignored)
{
  gid_t reg_gid;
  wzd_group_t *group = NULL;

#ifdef CACHE
  group = group_get_by_name(name);
  if (group) return group->gid;
#endif /* CACHE */

  group = libsqlite_group_get_by_name(name);
  if (! group) return INVALID_GROUP;
#ifdef CACHE
  if (group) {
    reg_gid = group_register(group, BACKEND_ID);
    if (reg_gid != group->gid) {
      out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could not registre group.\n");
      group_free(group);
      return INVALID_USER;
    }
  }
#endif /* CACHE */
  return group->gid; 
}

static int FCN_MOD_USER(uid_t uid, wzd_user_t * user, unsigned long mod_type)
{
  uid_t reg_uid = INVALID_USER;
  wzd_user_t *registered_user=NULL;

  /* delete */
  if (!user) {
    libsqlite_user_del(uid);
#ifdef CACHE
    registered_user = user_get_by_id(uid);
    if (registered_user != NULL) {
      registered_user = user_unregister(registered_user->uid);
      user_free(registered_user);
    }
#endif /* CACHE */
    return 0;
  }

  /* add */
  if (mod_type & _USER_CREATE) {
    libsqlite_user_add(user);
#ifdef CACHE
    reg_uid = user_register(user, BACKEND_ID);
    if (reg_uid != user->uid) {
      out_log(SQLITE_LOG_CHANNEL, "Sqlite backend can't registre on add\n");
    }
#endif /* CACHE */
  }
  
  /* update */
  else {
    libsqlite_user_update(uid, user, mod_type);
#ifdef CACHE
    registered_user = user_get_by_id(user->uid);
    if (registered_user) {
      user_update(registered_user->uid, user);
    } else {
      reg_uid = user_register(user, BACKEND_ID);
      if (reg_uid != user->uid) {
        out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could'nt registre user.\n");
        user_free(user);
        return -1;
      }
    }
#endif /* CACHE */
  }
  return 0;
}

static int FCN_MOD_GROUP(gid_t gid, wzd_group_t * group, unsigned long mod_type)
{
  gid_t reg_gid;
  wzd_group_t *registred_group;

  if (!group) {
    libsqlite_group_del(gid);
#ifdef CACHE
    registred_group = group_get_by_id(gid);
    if (registred_group) {
      group_unregister(registred_group->gid);
      group_free(registred_group);
    }
#endif /* CACHE */
    return 0;
  }

  /* add */
  if ( mod_type & _GROUP_CREATE) {
    libsqlite_group_add(group);
#ifdef CACHE
    reg_gid = group_register(group, BACKEND_ID);
    if (reg_gid != group->gid) {
      out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could not registre group.\n");
      group_free(group);
      return -1;
    }
#endif /* CACHE */
  }

  /* update */
  else {
    libsqlite_group_update(gid, group, mod_type);
#ifdef CACHE
    registred_group = group_get_by_id(group->gid);
    if (registred_group) {
      group_update(registred_group->gid, group);
    } else {
      reg_gid = group_register(group, BACKEND_ID);
      if (reg_gid != group->gid) {
        out_log(SQLITE_LOG_CHANNEL, "Backend sqlite could not registre group.\n");
        group_free(group);
        return -1;
      }
    }
#endif /* CACHE */
  }

  return 0;
}

static int  FCN_COMMIT_CHANGES(void)
{
  return 0;
}

/**
 * \brief backend initialization function.
 */
int wzd_backend_init(wzd_backend_t * backend)
{
  if (!backend) return -1;

  backend->name = wzd_strdup("sqlite");
  backend->version = SQLITE_BACKEND_VERSION;

  backend->backend_init = FCN_INIT;
  backend->backend_exit = FCN_FINI;

  backend->backend_validate_login = FCN_VALIDATE_LOGIN;
  backend->backend_validate_pass = FCN_VALIDATE_PASS;

  backend->backend_get_user = FCN_GET_USER;
  backend->backend_get_group = FCN_GET_GROUP;

  backend->backend_find_user = FCN_FIND_USER;
  backend->backend_find_group = FCN_FIND_GROUP;

  backend->backend_mod_user = FCN_MOD_USER;
  backend->backend_mod_group = FCN_MOD_GROUP;

  backend->backend_chpass = NULL;
  backend->backend_commit_changes = FCN_COMMIT_CHANGES;

  return 0;
}

/** @} */

