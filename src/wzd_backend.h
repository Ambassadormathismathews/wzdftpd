/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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

#include "wzd_hardlimits.h"
#include "wzd_structs.h"

#if 0
/* IMPORTANT:
 *
 * all validation functions have the following return code:
 *   0 = success
 *   !0 = failure
 *
 * the last parameter of all functions is a ptr to current user
 */


typedef struct {
  char name[1024];
  void * handle;
  int backend_storage;
  int (*back_validate_login)(const char *, wzd_user_t *);
  int (*back_validate_pass) (const char *, const char *, wzd_user_t *);
  int (*back_find_user) (const char *, wzd_user_t *);
  int (*back_find_group) (int, wzd_group_t *);
  int (*back_chpass) (const char *, const char *);
  int (*back_mod_user) (const char *, wzd_user_t *, unsigned long);
  int (*back_mod_group) (const char *, wzd_group_t *, unsigned long);
  int (*back_commit_changes) (void);
} wzd_backend_t;
#endif

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
#define _GROUP_ALL	0xffffffff

/* int FCN_INIT(int *backend_storage, wzd_user_t * user_list, unsigned int user_max, wzd_group_t * group_list, unsigned int group_max, void * arg) */
#define	FCN_INIT		wzd_init
#define	STR_INIT		"wzd_init"

/* int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user) */
#define	FCN_VALIDATE_LOGIN	wzd_validate_login
#define	STR_VALIDATE_LOGIN	"wzd_validate_login"

/* int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user) */
#define	FCN_VALIDATE_PASS	wzd_validate_pass
#define	STR_VALIDATE_PASS	"wzd_validate_pass"

/* int FCN_FIND_USER(const char *name, wzd_user_t * user) */
#define	FCN_FIND_USER		wzd_find_user
#define	STR_FIND_USER	 	"wzd_find_user"

/* int FCN_FIND_GROUP(int num, wzd_group_t * group) */
#define	FCN_FIND_GROUP		wzd_find_group
#define	STR_FIND_GROUP	 	"wzd_find_group"

/* int FCN_CHPASS(const char *username, const char *new_pass) */
#define	FCN_CHPASS		wzd_chpass
#define	STR_CHPASS	 	"wzd_chpass"

/* int FCN_MOD_USER(const char *name, wzd_user_t * user) */
#define	FCN_MOD_USER		wzd_mod_user
#define	STR_MOD_USER	 	"wzd_mod_user"

/* int FCN_MOD_GROUP(int num, wzd_group_t * group) */
#define	FCN_MOD_GROUP		wzd_mod_group
#define	STR_MOD_GROUP	 	"wzd_mod_group"

/* int FCN_COMMIT_CHANGES(void) */
#define	FCN_COMMIT_CHANGES	wzd_commit_changes
#define	STR_COMMIT_CHANGES	"wzd_commit_changes"


int backend_validate(const char *backend, const char *pred, const char *version);

/**
 * \brief loads backend
 * \param backend The backend name
 * \param backend_storage (output) Address of integer which indicates if backend stores data itself
 * \param user_list Memory zone to be filled dy user_data. Must be allocated
 * \param user_max Max number of users to store in user_list
 * \param group_list Memory zone to be filled dy group_data. Must be allocated
 * \param group_max Max number of group to store in group_list
 */
int backend_init(const char *backend, int * backend_storage, wzd_user_t * user_list, unsigned int user_max, wzd_group_t * group_list, unsigned int group_max);

int backend_close(const char *backend);

int backend_reload(const char *backend);

int backend_find_user(const char *name, wzd_user_t * user, int * userid);

int backend_find_group(int num, wzd_group_t * group, int * groupid);

int backend_validate_login(const char *name, wzd_user_t * user, unsigned int * userid);

int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user, unsigned int * userid);

int backend_chpass(const char *username, const char *new_pass);

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

#endif /* __WZD_BACKEND__ */
