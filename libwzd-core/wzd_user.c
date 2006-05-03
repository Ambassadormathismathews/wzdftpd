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

  memset(user,0,sizeof(user));
  user->uid = (uid_t)-1;

  return user;
}

/** \brief Free memory used by a \a user structure
 */
void user_free(wzd_user_t * user)
{
  if (user == NULL) return;

  wzd_free(user);
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
    out_log(LEVEL_HIGH, "ERROR user_register(uid=%d): uid too big\n",uid);
    return (uid_t)-1;
  }

  WZD_MUTEX_LOCK(SET_MUTEX_USER);

  uid = user->uid;

  if (uid > _max_uid) {
    size_t size; /* size of extent */

    if (uid >= _max_uid + 255)
      size = uid + 1 - _max_uid;
    else
      size = 256;
    _user_array = wzd_realloc(_user_array, (_max_uid + size)*sizeof(wzd_user_t*));
    memset(_user_array + _max_uid, 0, size * sizeof(wzd_user_t*));
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

/** \brief Unregister a user to the main server
 * The \a user struct must be freed using user_free()
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
  return user;
}

/** \brief Free memory used to register users
 */
void user_free_registry(void)
{
  WZD_MUTEX_LOCK(SET_MUTEX_USER);
  wzd_free(_user_array);
  _user_array = NULL;
  _max_uid = 0;
  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
}

