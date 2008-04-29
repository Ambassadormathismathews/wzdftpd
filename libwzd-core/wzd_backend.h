/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

#ifndef __WZD_BACKEND__
#define __WZD_BACKEND__

#include <stdarg.h>

#include "wzd_structs.h"

/*
 * 101 backend_id
 */
#define STRUCT_BACKEND_VERSION  101

/** \brief Initialization for backends */
struct wzd_backend_t {
  unsigned int struct_version; /* used to know which fields are
                                  present in the struct .. */
  char * name;
  unsigned int version;

  int (*backend_init)(const char * param);

  uid_t (*backend_validate_login)(const char *, wzd_user_t *);
  uid_t (*backend_validate_pass) (const char *, const char *, wzd_user_t *);
  wzd_user_t * (*backend_get_user)(uid_t uid);
  wzd_group_t * (*backend_get_group)(gid_t gid);
  uid_t (*backend_find_user) (const char *, wzd_user_t *);
  gid_t (*backend_find_group) (const char *, wzd_group_t *);
  int (*backend_chpass) (const char *, const char *);
  int (*backend_mod_user) (uid_t, wzd_user_t *, unsigned long);
  int (*backend_mod_group) (gid_t, wzd_group_t *, unsigned long);
  int (*backend_commit_changes) (void);

  int (*backend_exit)(void);

  u16_t backend_id;
};


/* used to know what was modified in update functions */
#define _USER_NOTHING       0
#define _USER_USERNAME      1<<0
#define _USER_USERPASS      1<<1
#define _USER_ROOTPATH      1<<2
#define _USER_TAGLINE       1<<3
#define _USER_UID           1<<4
#define _USER_GROUPNUM      1<<5
#define _USER_GROUP         1<<6
#define _USER_IDLE          1<<7
#define _USER_PERMS         1<<8
#define _USER_FLAGS         1<<9
#define _USER_MAX_ULS       1<<10
#define _USER_MAX_DLS       1<<11
#define _USER_IP            1<<12
#define _USER_BYTESUL       1<<13
#define _USER_BYTESDL       1<<14
#define _USER_CREDITS       1<<15
#define _USER_NUMLOGINS     1<<16
#define _USER_USERSLOTS     1<<17
#define _USER_LEECHSLOTS    1<<18
#define _USER_RATIO	        1<<19
#define _USER_CREATOR       1<<20
#define _USER_LOGINSPERIP   1<<21
#define _USER_ALL           0x0000ffff
#define _USER_CREATE        0x01000000

#define _GROUP_NOTHING      0
#define _GROUP_GROUPNAME    1<<0
#define _GROUP_GROUPPERMS   1<<1
#define _GROUP_IDLE         1<<2
#define _GROUP_MAX_ULS      1<<3
#define _GROUP_MAX_DLS      1<<4
#define _GROUP_RATIO        1<<5
#define _GROUP_IP           1<<6
#define _GROUP_DEFAULTPATH  1<<7
#define _GROUP_NUMLOGINS    1<<8
#define _GROUP_TAGLINE      1<<9
#define _GROUP_GID          1<<10
#define _GROUP_FLAGS        1<<11
#define _GROUP_ALL          0x0000ffff
#define _GROUP_CREATE       0x01000000


/** \brief Get backend version
 */
char *backend_get_version(wzd_backend_def_t *backend);

/** \brief Get backend name
 *
 * \note This is generally the short name of the backend (for ex, pgsql), and
 * is different from the name defined in the config (the shared library name).
 */
char *backend_get_name(wzd_backend_def_t *backend);

/** \brief Validate backend by checking needed functions, and if a specific version is required
 *
 * \param backend The shared library file name
 * \param pred A predicate (for ex, >=)
 * \param version The version to be compared, by the predicate, to the backend version
 *
 * \return
 * - a newly allocated structure for the backend, or
 * - NULL if some functions are missing (check logs for details)
 *
 * \note Actually, \a pred and \a version are ignored
 */
wzd_backend_def_t * backend_validate(const char *backend, const char *pred, const char *version);

/** \brief Register backend
 * Use \a filename for dynamic modules (shared libraries)
 * \a fcn for static modules.
 * When loading a static module, \a filename is used as a comment
 */
struct wzd_backend_def_t * backend_register(const char * filename, backend_init_function_t fcn);

/**
 * \brief Initialize backend
 * \param backend The backend name
 */
int backend_init(wzd_backend_def_t * backend);

/** \brief Close backend and associated resources
 *
 * Call backend exit function (if defined), mark backend as closed, and
 * unloads shared library if present.
 *
 * \note The backend structure must still be removed from list
 *
 * \return
 * - 0 if ok
 * - 1 if an error occurred
 */
int backend_close(const char *backend);

/** \brief Reload backend
 *
 * \param backend The backend (short) name
 *
 * \return
 * - 0 if ok
 * - 1 if an error occurred (the backend may be in inconsistant state)
 */
int backend_reload(const char *backend);

#define INVALID_USER  (uid_t)-1
#define GET_USER_LIST (uid_t)-2

/**
 * \brief Get user informations
 * \param userid The user id, or the special value (uid_t)-2
 *
 * Search backend for user with the corresponding uid and return the corresponding struct.
 *
 * If the argument is -2, this function returns an array of uid (ended with -1) containing
 * the list of all known users (you have to cast the return to a (uid_t *) to use it). You must
 * free the returned array using wzd_free().
 */
wzd_user_t * backend_get_user(uid_t userid);

#define INVALID_GROUP  (gid_t)-1
#define GET_GROUP_LIST (gid_t)-2

/**
 * \brief Get group informations
 * \param groupid The group id, or the special value (gid_t)-2
 *
 * Search backend for group with the corresponding gid and return the corresponding struct.
 *
 * If the argument is -2, this function returns an array of gid (ended with -1) containing
 * the list of all known groups (you have to cast the return to a (gid_t *) to use it). You must
 * free the returned array using wzd_free().
 */
wzd_group_t * backend_get_group(gid_t groupid);

/** \brief Search for user with name \a name in backends
 *
 * If an user is found, its uid is stored in \a userid. If \a user is not NULL,
 * the structure is copied (and should be freed using free() )
 */
int backend_find_user(const char *name, wzd_user_t * user, int * userid);

/** \brief Search for group with name \a name in backends
 *
 * If a group is found, its gid is stored in \a groupid. If \a group is not NULL,
 * the structure is copied (and should be freed using free() )
 */
int backend_find_group(const char *name, wzd_group_t * group, int * groupid);

/** \brief Check if \a name is a defined in backend, and retrieve the associated structure
 */
int backend_validate_login(const char *name, wzd_user_t * user, uid_t * userid);

/** \brief Check user and password, and retrieve associated structure
 */
int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user, uid_t * userid);

/** \brief Send user modifications to backend
 *
 * The modified user is identified by the backend and the \a uid.
 * \a mod_type is used to determine which values are changed, and the new values
 * are taken from the structure \a user.
 *
 * If the user does not exist, the backend will add it. If \a user is NULL, the user
 * is deleted.
 */
int backend_mod_user(const char *backend, uid_t uid, wzd_user_t * user, unsigned long mod_type);

/** \brief Send group modifications to backend
 *
 * The modified group is identified by the backend and the \a gid.
 * \a mod_type is used to determine which values are changed, and the new values
 * are taken from the structure \a group.
 *
 * If the group. does not exist, the backend will add it. If \a group. is NULL, the group.
 * is deleted.
 */
int backend_mod_group(const char *backend, gid_t gid, wzd_group_t * group, unsigned long mod_type);

/** \brief Commit changes to backend
 */
int backend_commit_changes(const char *backend);

/** \brief Check if a backend is currently used
 * \return The number of users connected currently using this backend
 */
int backend_inuse(const char *backend);

#ifndef STRINGIFY
# define STRINGIFY(v) STRINGIFY1(v)
# define STRINGIFY1(v) #v
#endif

#define BACKEND_NAME(n)    const char * wzd_backend_name = STRINGIFY(n)
#define BACKEND_VERSION(v) const char * wzd_backend_version = STRINGIFY(v)


/** \brief Get user identified by \a id from backend
 *
 * \param id The uid of the user
 *
 * \return A wzd_user_t structure, or NULL if not found
 */
wzd_user_t * GetUserByID(uid_t id);

/** \brief Get user identified by \a name from backend
 *
 * \param name The name of the user
 *
 * \return A wzd_user_t structure, or NULL if not found
 */
wzd_user_t * GetUserByName(const char *name);

/** \brief Get group identified by \a id from backend
 *
 * \param id The gid of the group
 *
 * \return A wzd_group_t structure, or NULL if not found
 */
wzd_group_t * GetGroupByID(gid_t id);

/** \brief Get group identified by \a name from backend
 *
 * \param name The name of the group
 *
 * \return A wzd_group_t structure, or NULL if not found
 */
wzd_group_t * GetGroupByName(const char *name);

/** \brief Get user ID identified by \a name from backend
 *
 * \param name The name of the user
 *
 * \return The unique identifier of the user, or -1 if not found
 */
uid_t GetUserIDByName(const char *name);

/** \brief Get group ID identified by \a name from backend
 *
 * \param name The name of the group
 *
 * \return The unique identifier of the group, or -1 if not found
 */
gid_t GetGroupIDByName(const char *name);


#endif /* __WZD_BACKEND__ */
