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

#include "wzd_group.h"
#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_misc.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

static gid_t _max_gid = 0;
static wzd_group_t ** _group_array = NULL;

/** \brief Allocate a new empty structure for a group
 */
wzd_group_t * group_allocate(void)
{
  wzd_group_t * group;

  group = wzd_malloc(sizeof(wzd_group_t));

  WZD_ASSERT_RETURN(group != NULL, NULL);
  if (group == NULL) {
    out_log(LEVEL_CRITICAL,"FATAL group_allocate out of memory\n");
    return NULL;
  }

  memset(group,0,sizeof(group));
  group->gid = (gid_t)-1;

  return group;
}

/** \brief Free memory used by a \a group structure
 */
void group_free(wzd_group_t * group)
{
  if (group == NULL) return;

  wzd_free(group);
}

/** \brief Register a group to the main server
 * \return The gid of the registered group, or -1 on error
 */
gid_t group_register(wzd_group_t * group, u16_t backend_id)
{
  gid_t gid;

  WZD_ASSERT(group != NULL);
  if (group == NULL) return (gid_t)-1;

  WZD_ASSERT(group->gid != (gid_t)-1);
  if (group->gid == (gid_t)-1) return (gid_t)-1;

  /* safety check */
  if (group->gid >= INT_MAX) {
    out_log(LEVEL_HIGH, "ERROR group_register(gid=%d): gid too big\n",gid);
    return (gid_t)-1;
  }

  WZD_MUTEX_LOCK(SET_MUTEX_USER);

  gid = group->gid;

  if (gid > _max_gid) {
    size_t size; /* size of extent */

    if (gid >= _max_gid + 255)
      size = gid + 1 - _max_gid;
    else
      size = 256;
    _group_array = wzd_realloc(_group_array, (_max_gid + size)*sizeof(wzd_group_t*));
    memset(_group_array + _max_gid, 0, size * sizeof(wzd_group_t*));
    _max_gid = _max_gid + size;
  }

  if (_group_array[gid] != NULL) {
    out_log(LEVEL_NORMAL, "INFO group_register(gid=%d): another group is already present (%s)\n",gid,_group_array[gid]->groupname);
    WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
    return -1;
  }

  _group_array[gid] = group;
  group->backend_id = backend_id;

  out_log(LEVEL_FLOOD,"DEBUG registered gid %d with backend %d\n",gid,backend_id);

  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
  return gid;
}

/** \brief Unregister a group to the main server
 * The \a group struct must be freed using group_free()
 * \return The unregistered group structure, or NULL on error
 */
wzd_group_t * group_unregister(gid_t gid)
{
  wzd_group_t * group = NULL;

  WZD_ASSERT_RETURN(gid != (gid_t)-1, NULL);
  if (gid == (gid_t)-1) return NULL;

  if (gid > _max_gid) return NULL;

  WZD_MUTEX_LOCK(SET_MUTEX_USER);

  if (_group_array[gid] != NULL) {
    group = _group_array[gid];
    _group_array[gid] = NULL;
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
  return group;
}

/** \brief Free memory used to register groups
 */
void group_free_registry(void)
{
  WZD_MUTEX_LOCK(SET_MUTEX_USER);
  wzd_free(_group_array);
  _group_array = NULL;
  _max_gid = 0;
  WZD_MUTEX_UNLOCK(SET_MUTEX_USER);
}

