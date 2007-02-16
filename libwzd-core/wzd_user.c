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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#include <direct.h> /* _getcwd */
#else
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "wzd_structs.h"

#include "wzd_fs.h"
#include "wzd_group.h"
#include "wzd_ip.h"
#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

static uid_t _max_uid = 0;
static wzd_user_t ** _user_array = NULL;


/** \brief Allocate a new empty structure for a user
 */
wzd_user_t * user_allocate(void)
{
  wzd_user_t * user;

  user = wzd_malloc(sizeof(wzd_user_t));

  WZD_ASSERT_RETURN(user != NULL, NULL);
  if (user == NULL) {
    out_log(LEVEL_CRITICAL,"FATAL user_allocate out of memory\n");
    return NULL;
  }

  user_init_struct(user);

  return user;
}

/** \brief Initialize members of struct \a user
 */
void user_init_struct(wzd_user_t * user)
{
  WZD_ASSERT_VOID(user != NULL);
  if (user == NULL) return;

  memset(user,0,sizeof(wzd_user_t));

  user->uid = (uid_t)-1;
}

/** \brief Free memory used by a \a user structure
 */
void user_free(wzd_user_t * user)
{
  if (user == NULL) return;

  ip_list_free(user->ip_list);
  wzd_free(user);
}

/** \brief Create a new user, giving default parameters
 * \return The new user, or NULL. If \a err is provided, set it to
 * the error code.
 */
wzd_user_t * user_create(const char * username, const char * pass, const char * groupname, wzd_context_t * context, wzd_config_t * config, int * err)
{
  wzd_user_t * newuser;
  wzd_group_t * group = NULL;
  const char * homedir;
  unsigned int ratio;

  WZD_ASSERT_RETURN( username != NULL, NULL );
  if (username == NULL) {
    if (err) *err = E_PARAM_NULL;
    return NULL;
  }

  if (strlen(username) == 0 || strlen(username) >= HARD_USERNAME_LENGTH) {
    if (err) *err = E_PARAM_BIG;
    return NULL;
  }

  if (GetUserByName(username) != NULL) {
    if (err) *err = E_PARAM_EXIST;
    return NULL;
  }

  if (groupname)
    group = GetGroupByName(groupname);

  if (groupname == NULL) {
    if (err) *err = E_PARAM_NULL;
    return NULL;
  }

  /* create new user */
  newuser = user_allocate();

  homedir = group->defaultpath;
  ratio = group->ratio;
  newuser->userperms = group->groupperms;

  /* check if homedir exist */
  {
    fs_filestat_t s;
    if (fs_file_stat(homedir,&s) || !S_ISDIR(s.mode)) {
      out_log(LEVEL_HIGH,"WARNING homedir %s does not exist (while creating user %s)\n",homedir,username);
    }
  }

  strncpy(newuser->username, username, HARD_USERNAME_LENGTH-1);
  strncpy(newuser->userpass, pass, MAX_PASS_LENGTH-1);
  strncpy(newuser->rootpath, homedir, WZD_MAX_PATH-1);
  newuser->group_num=0;
  if (group != NULL) {
    newuser->groups[0] = group->gid;
    if (newuser->groups[0] != INVALID_USER) newuser->group_num = 1;
  }

  return newuser;
}

/** \brief Register a user to the main server
 * \return The uid of the registered user, or -1 on error
 */
uid_t user_register(wzd_user_t * user, u16_t backend_id)
{
  uid_t uid;

  WZD_ASSERT(user != NULL);
  if (user == NULL) return (uid_t)-1;

  WZD_ASSERT(user->uid != (uid_t)-1);
  if (user->uid == (uid_t)-1) return (uid_t)-1;

  /* safety check */
  if (user->uid >= INT_MAX) {
    out_log(LEVEL_HIGH, "ERROR user_register(uid=%d): uid too big\n",user->uid);
    return (uid_t)-1;
  }

  WZD_MUTEX_LOCK(SET_MUTEX_USER);

  /** \todo we should check unicity of username */

  uid = user->uid;

  if (uid >= _max_uid) {
    size_t size; /* size of extent */

    if (uid >= _max_uid + 255)
      size = uid - _max_uid;
    else
      size = 256;
    _user_array = wzd_realloc(_user_array, (_max_uid + size + 1)*sizeof(wzd_user_t*));
    memset(_user_array + _max_uid, 0, (size+1) * sizeof(wzd_user_t*));
    _max_uid = _max_uid + size;
  }

  if (_user_array[uid] != NULL) {
    out_log(LEVEL_NORMAL, "INFO user_register(uid=%d): another user is already present (%s)\n",uid,_user_array[uid]->username);
    WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
    return -1;
  }

  _user_array[uid] = user;
  user->backend_id = backend_id;

  out_log(LEVEL_FLOOD,"DEBUG registered uid %d with backend %d\n",uid,backend_id);

  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
  return uid;
}

/** \brief Update a registered user atomically. Datas are copied,
 * and old user is freed.
 * A pointer to the old user is still valid (change is done in-place)
 * If the uid had changed, the user will be moved
 * \return 0 if ok
 */
int user_update(uid_t uid, wzd_user_t * new_user)
{
  wzd_user_t * buffer;

  if (uid == (uid_t)-1) return -1;
  if (uid > _max_uid) return -1;
  if (_user_array[uid] == NULL) return -2;

  if (uid != new_user->uid) {
    if (_user_array[new_user->uid] != NULL) return -3;
  }

  /* same user ? do nothing */
  if (uid == new_user->uid && _user_array[uid] == new_user) return 0;

  WZD_MUTEX_LOCK(SET_MUTEX_USER);
  /* backup old user */
  buffer = wzd_malloc(sizeof(wzd_user_t));
  *buffer = *_user_array[uid];
  /* update user */
  *_user_array[uid] = *new_user;
  user_free(buffer);
  if (uid != new_user->uid) {
    _user_array[new_user->uid] = _user_array[uid];
    _user_array[uid] = NULL;
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);

  return 0;
}

/** \brief Unregister a user to the main server
 * The \a user struct must be freed using user_free()
 * \warning Unregistering a user at runtime can break the server if the user is being used
 * \return The unregistered user structure, or NULL on error
 */
wzd_user_t * user_unregister(uid_t uid)
{
  wzd_user_t * user = NULL;

  WZD_ASSERT_RETURN(uid != (uid_t)-1, NULL);
  if (uid == (uid_t)-1) return NULL;

  if (uid > _max_uid) return NULL;

  WZD_MUTEX_LOCK(SET_MUTEX_USER);

  if (_user_array[uid] != NULL) {
    user = _user_array[uid];
    _user_array[uid] = NULL;
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
  out_log(LEVEL_FLOOD,"DEBUG unregistered uid %d\n",uid);

  return user;
}

/** \brief Free memory used to register users
 * \warning Also free ALL registered users !
 */
void user_free_registry(void)
{
  uid_t uid;
  WZD_MUTEX_LOCK(SET_MUTEX_USER);
  if (_user_array != NULL) {
    for (uid=0; uid<=_max_uid; uid++) {
      user_free(_user_array[uid]);
    }
  }
  wzd_free(_user_array);
  _user_array = NULL;
  _max_uid = 0;
  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
}

/** \brief Get registered user using the \a uid
 * \return The user, or NULL
 */
wzd_user_t * user_get_by_id(uid_t uid)
{
  if (uid == (uid_t)-1) return NULL;
  if (uid > _max_uid) return NULL;
  if (_max_uid == 0) return NULL;

  return _user_array[uid];
}

/** \brief Get registered user using the \a name
 * \return The user, or NULL
 * \todo Re-implement the function using a hash table
 */
wzd_user_t * user_get_by_name(const char * username)
{
  uid_t uid;

  if (username == NULL || strlen(username)<1 || _max_uid==0) return NULL;

  /* We don't need to lock the access since the _user_array can only grow */
  for (uid=0; uid<=_max_uid; uid++) {
    if (_user_array[uid] != NULL
        && _user_array[uid]->username != NULL
        && strcmp(username,_user_array[uid]->username)==0)
      return _user_array[uid];
  }
  return NULL;
}

/** \brief Get list or users register for a specific backend
 * The returned list is terminated by -1, and must be freed with wzd_free()
 */
uid_t * user_get_list(u16_t backend_id)
{
  uid_t * uid_list = NULL;
  uid_t size;
  int index;
  uid_t uid;

  /** \todo XXX we should use locks (and be careful to avoid deadlocks) */

  /** \todo it would be better to get the real number of used uid */
  size = _max_uid;

  uid_list = (uid_t*)wzd_malloc((size+1)*sizeof(uid_t));
  index = 0;
  /* We don't need to lock the access since the _user_array can only grow */
  for (uid=0; uid<size; uid++) {
    if (_user_array[uid] != NULL
        && _user_array[uid]->uid != INVALID_USER)
      uid_list[index++] = _user_array[uid]->uid;
  }
  uid_list[index] = (uid_t)-1;
  uid_list[size] = (uid_t)-1;

  return uid_list;
}

/** \brief Find the first free uid, starting from \a start
 */
uid_t user_find_free_uid(uid_t start)
{
  uid_t uid;

  if (start == (uid_t)-1) start = 0;

  /** \todo locking may be harmful if this function is called from another
   * user_x() function
   */
/*  WZD_MUTEX_LOCK(SET_MUTEX_USER);*/
  for (uid = start; uid < _max_uid && uid != (uid_t)-1; uid++) {
    if (_user_array[uid] == NULL) break;
  }
/*  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);*/

  return uid;
}

/** \brief Add an ip to the list of authorized/forbidden ips
 * \return 0 if ok
 */
int user_ip_add(wzd_user_t * user, const char * ip, int is_authorized)
{
  WZD_ASSERT( user != NULL );
  if (user == NULL) return -1;

  /** \note The number of stored ips per user is no more limited */

  return ip_add_check(&user->ip_list, ip, is_authorized);
}


