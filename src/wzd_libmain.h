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

#ifndef __WZD_LIBMAIN__
#define __WZD_LIBMAIN__

#include "wzd_mutex.h"

typedef enum {
  SET_MUTEX_GLOBAL=0,

  SET_MUTEX_SHVARS,

  SET_MUTEX_LIMITER,

  SET_MUTEX_PERMISSION,
  SET_MUTEX_DIRINFO,
  SET_MUTEX_FILE_T,
  SET_MUTEX_ACL_T,

  SET_MUTEX_NUM /* must be last */
} wzd_set_mutext_t;

WZDIMPORT extern wzd_mutex_t * limiter_mutex;
WZDIMPORT extern wzd_mutex_t * server_mutex;
WZDIMPORT extern time_t server_time;
WZDIMPORT extern wzd_mutex_t * mutex_set[SET_MUTEX_NUM];

void server_restart(int signum);

#define WZD_MUTEX_LOCK(x) wzd_mutex_lock(mutex_set[x])
#define WZD_MUTEX_UNLOCK(x) wzd_mutex_unlock(mutex_set[x])


int server_mutex_set_init(void);
int server_mutex_set_fini(void);

wzd_config_t * getlib_mainConfig(void);
void setlib_mainConfig(wzd_config_t *);

List * getlib_contextList(void);
void setlib_contextList(List *);

gid_t getlib_server_gid(void);
void setlib_server_gid(gid_t);

int getlib_server_uid(void);
void setlib_server_uid(int);

void libtest(void);


/** \brief remove a context from the list */
int context_remove(List * context_list, wzd_context_t * context);

#endif /* __WZD_LIBMAIN__ */
