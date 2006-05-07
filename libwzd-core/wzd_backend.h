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
  int (*backend_mod_user) (const char *, wzd_user_t *, unsigned long);
  int (*backend_mod_group) (const char *, wzd_group_t *, unsigned long);
  int (*backend_commit_changes) (void);

  int (*backend_exit)(void);

  u16_t backend_id;
};

/* used to know what was modified in update functions */
#define	_USER_NOTHING		0
#define	_USER_USERNAME		1<<0
#define	_USER_USERPASS		1<<1
#define	_USER_ROOTPATH		1<<2
#define	_USER_TAGLINE		1<<3
#define	_USER_UID		1<<4
#define	_USER_GROUPNUM		1<<5
#define	_USER_GROUP		1<<6
#define	_USER_IDLE		1<<7
#define	_USER_PERMS		1<<8
#define	_USER_FLAGS		1<<9
#define	_USER_MAX_ULS		1<<10
#define	_USER_MAX_DLS		1<<11
#define	_USER_IP		1<<12
#define	_USER_BYTESUL		1<<13
#define	_USER_BYTESDL		1<<14
#define	_USER_CREDITS		1<<15
#define	_USER_NUMLOGINS		1<<16
#define	_USER_USERSLOTS		1<<17
#define	_USER_LEECHSLOTS	1<<18
#define	_USER_RATIO		1<<19
#define _USER_ALL	0xffffffff

#define _GROUP_NOTHING		0
#define	_GROUP_GROUPNAME	1<<0
#define	_GROUP_GROUPPERMS	1<<1
#define	_GROUP_IDLE		1<<2
#define	_GROUP_MAX_ULS		1<<3
#define	_GROUP_MAX_DLS		1<<4
#define	_GROUP_RATIO		1<<5
#define	_GROUP_IP		1<<6
#define	_GROUP_DEFAULTPATH	1<<7
#define	_GROUP_NUMLOGINS	1<<8
#define	_GROUP_TAGLINE		1<<9
#define	_GROUP_GID		1<<10
#define _GROUP_ALL	0xffffffff


char *backend_get_version(wzd_backend_def_t *backend);
char *backend_get_name(wzd_backend_def_t *backend);
int backend_validate(const char *backend, const char *pred, const char *version);

/**
 * \brief loads backend
 * \param backend The backend name
 * \param user_max Max number of users to store in user_list (NOT used! !)
 * \param group_max Max number of group to store in group_list (NOT used! !)
 */
int backend_init(const char *backend, unsigned int user_max, unsigned int group_max);

int backend_close(const char *backend);

int backend_reload(const char *backend);

enum { INVALID_USER = (uid_t)-1, GET_USER_LIST = (uid_t)-2 };

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

enum { INVALID_GROUP = (gid_t)-1, GET_GROUP_LIST = (gid_t)-2 };

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

int backend_find_user(const char *name, wzd_user_t * user, int * userid);

int backend_find_group(const char *name, wzd_group_t * group, int * groupid);

int backend_validate_login(const char *name, wzd_user_t * user, uid_t * userid);

int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user, uid_t * userid);

/* if user does not exist, add it
 * if struct user is NULL, delete user
 */
int backend_mod_user(const char *backend, const char *name, wzd_user_t * user, unsigned long mod_type);

/* if group does not exist, add it
 * if struct group is null, delete group
 */
int backend_mod_group(const char *backend, const char *name, wzd_group_t * group, unsigned long mod_type);

int backend_commit_changes(const char *backend);

int backend_inuse(const char *backend);

#ifndef STRINGIFY
# define STRINGIFY(v) STRINGIFY1(v)
# define STRINGIFY1(v) #v
#endif

#define BACKEND_NAME(n)    const char * wzd_backend_name = STRINGIFY(n)
#define BACKEND_VERSION(v) const char * wzd_backend_version = STRINGIFY(v)


/* wrappers to user list */

wzd_user_t * GetUserByID(uid_t id);
wzd_user_t * GetUserByName(const char *name);
wzd_group_t * GetGroupByID(gid_t id);
wzd_group_t * GetGroupByName(const char *name);
uid_t GetUserIDByName(const char *name);
gid_t GetGroupIDByName(const char *name);


#endif /* __WZD_BACKEND__ */
