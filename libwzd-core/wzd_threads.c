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
/** \file wzd_threads.c
  * \brief Threads implementation
  * \warning This file contains many platform-dependant code
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

#include <signal.h>
#endif

struct wzd_context_t;

#include "wzd_log.h"
#include "wzd_threads.h"

#include "wzd_debug.h"

#else /* WZD_USE_PCH */
#ifdef WIN32
#define _WIN32_WINNT    0x500
#include <windows.h>
#endif
#endif /* WZD_USE_PCH */

/** \brief Create a new thread
 *
 * This function create a new thread, using native threads on Windows and pthreads
 * elsewhere. The new thread is started immediatly, unless specific attributes
 * have been defined.
 *
 * \param[out] thread location where the new thread id will be stored
 * \param[in] attr thread specific attributes
 * \param[in] start_routine the function to execute in the new thread
 * \param[in] arg an argument to be passed to start_routine
 */
int wzd_thread_create(wzd_thread_t * thread, wzd_thread_attr_t * attr, void * (start_routine)(void *), void * arg)
{
#ifndef WIN32
  int ret;

  {
    /* block signals so that other threads possibly created later (for ex.
     * in modules) do not receive signals like SIGINT
     */
    sigset_t oldmask, newmask;
    sigfillset(&newmask);
    ret = pthread_sigmask(SIG_BLOCK,&newmask,&oldmask);
    WZD_ASSERT( ret == 0 );
  }

  ret =  pthread_create( & thread->_t, & attr->_a, start_routine, arg);

  {
    /* restore signals so we can be stopped with SIGINT or restarted with SIGHUP */
    sigset_t oldmask, newmask;
    sigfillset(&newmask);
    ret = pthread_sigmask(SIG_UNBLOCK,&newmask,&oldmask);
    WZD_ASSERT( ret == 0 );
  }

  return ret;
#else
  unsigned long threadID;

  thread->_t = CreateThread( NULL /* not supported yet */, 0, (LPTHREAD_START_ROUTINE)start_routine, arg, 0 /* creation flags */, &threadID);

  return (thread->_v == NULL);
#endif
}

/** \brief Initialize an empty wzd_thread_attr_t structure
 *
 * \param[out] attr pointer to the new attributes structure
 *
 * \return 0 if ok
 */
int wzd_thread_attr_init(wzd_thread_attr_t * attr)
{
#ifndef WIN32
  return pthread_attr_init( & attr->_a );
#else
  attr->_v = NULL;
  return 0;
#endif
}

/** \brief Free resources used by a wzd_thread_attr_t structure
 *
 * \param[in] attr pointer to the attributes structure
 *
 * \return 0 if ok
 */
int wzd_thread_attr_destroy(wzd_thread_attr_t * attr)
{
#ifndef WIN32
  return pthread_attr_destroy( & attr->_a );
#else
  attr->_v = NULL;
  return 0;
#endif
}

/** \brief Set thread attribute to detachable state
 *
 * Resources used by a detached thread are freed immediatly when
 * the thread exits, and wzd_thread_join can't be used to get the
 * return code.
 *
 * \param[in] attr attributes structure
 *
 * \return 0 if ok
 */
int wzd_thread_attr_set_detached(wzd_thread_attr_t * attr)
{
#ifndef WIN32
  return pthread_attr_setdetachstate( & attr->_a, PTHREAD_CREATE_DETACHED);
#else
  return 0;
#endif
}

/** \brief Wait for termination of another thread
 *
 * Wait indefinitly, until thread terminates. The return code is stored
 * in thread_return, and the thread can be freed after.
 *
 * \param[in] thread the thread id to wait for
 * \param[out] thread_return the return value of thread
 *
 * \return 0 if ok
 */
int wzd_thread_join(wzd_thread_t * thread, void ** thread_return)
{
#ifndef WIN32
  return pthread_join(thread->_t, thread_return);
#else

  if (WaitForSingleObject(thread->_t, INFINITE) != WAIT_OBJECT_0)
  {
    out_log(LEVEL_CRITICAL, "Thread join failed.");
    CloseHandle(thread->_t);

    return -1;
  }
  CloseHandle(thread->_t);

  return 0;
#endif
}

/** \brief Cancel thread by sending a signal
 *
 * \param[in] thread the thread to cancel
 */
int wzd_thread_cancel(wzd_thread_t * thread)
{
#ifndef WIN32
  return pthread_cancel(thread->_t);
#else
  /** \todo use pthread_kill() equivalent for windows */
  out_log(LEVEL_CRITICAL, "Not Yet Implemented : wzd_thread_cancel\n");
  return -1;
#endif
}

