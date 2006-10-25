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
/** \file wzd_mutex.c
  * \brief Mutexes implementation
  * \warning This file contains many platform-dependant code, and supports
  * only multithread code.
  */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#ifdef WIN32
# define _WIN32_WINNT    0x500
# include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#endif

struct wzd_context_t;

#include "wzd_mutex.h"

#include "wzd_debug.h"

#else /* WZD_USE_PCH */
#ifdef WIN32
#define _WIN32_WINNT    0x500
#include <windows.h>
#endif
#endif /* WZD_USE_PCH */

struct _wzd_mutex_t {
#ifndef WIN32
  pthread_mutex_t _mutex;
#else
  CRITICAL_SECTION _mutex;
#endif
};


/** create a mutex */
wzd_mutex_t * wzd_mutex_create(unsigned long key)
{
  int ret;
  struct _wzd_mutex_t * m;

  /* check unicity ?! */

  /* allocate new mutex */
  m = (struct _wzd_mutex_t*)wzd_malloc(sizeof(struct _wzd_mutex_t));

  /* initilization */
#ifndef WIN32
  {
    pthread_mutex_t pth = PTHREAD_MUTEX_INITIALIZER;
    memcpy((void*)&m->_mutex, (const void*)&pth, sizeof(pth));
    ret = pthread_mutex_init(&(m->_mutex), NULL);
  }
#else
  InitializeCriticalSection(&m->_mutex);
  ret = 0;
#endif

  if (ret) { wzd_free(m); return NULL; }

  return m;
}


/** destroy mutex */
void wzd_mutex_destroy(wzd_mutex_t * mutex)
{
  if (mutex) {
#ifndef WIN32
    pthread_mutex_destroy(&mutex->_mutex);
#else
    DeleteCriticalSection(&mutex->_mutex);
#endif
    wzd_free(mutex);
  }
}



/* lock a mutex */
int wzd_mutex_lock(wzd_mutex_t * mutex)
{
  if (mutex) {
#ifndef WIN32
    return pthread_mutex_lock(&mutex->_mutex);
#else
    EnterCriticalSection(&mutex->_mutex);
    return 0;
#endif
  }
  return 1;
}


/* try to lock a mutex */
int wzd_mutex_trylock(wzd_mutex_t * mutex)
{
  if (mutex) {
#ifndef WIN32
    return pthread_mutex_trylock(&mutex->_mutex);
#else
    TryEnterCriticalSection(&mutex->_mutex);
    return 0;
#endif
  }
  return 1;
}


/* unlock a mutex */
int wzd_mutex_unlock(wzd_mutex_t * mutex)
{
  if (mutex) {
#ifndef WIN32
    return pthread_mutex_unlock(&mutex->_mutex);
#else
    LeaveCriticalSection(&mutex->_mutex);
    return 0;
#endif
  }
  return 1;
}
