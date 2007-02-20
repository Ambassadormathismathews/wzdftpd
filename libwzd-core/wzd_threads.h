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

#ifndef __WZD_THREADS__
#define __WZD_THREADS__

#ifndef WIN32
#  ifdef HAVE_PTHREAD
#    include <pthread.h>
#  endif
#endif

/* use the WZD_THREAD_VOID macro to cast these types to void * */

typedef union wzd_thread_attr_t wzd_thread_attr_t;

typedef union wzd_thread_t wzd_thread_t;

#define WZD_THREAD_VOID(x) ((x)->_v)


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
int wzd_thread_create(wzd_thread_t * thread, wzd_thread_attr_t * attr, void * (start_routine)(void *), void * arg);

/** \brief Initialize an empty wzd_thread_attr_t structure
 *
 * \param[out] attr pointer to the new attributes structure
 *
 * \return 0 if ok
 */
int wzd_thread_attr_init(wzd_thread_attr_t * attr);

/** \brief Free resources used by a wzd_thread_attr_t structure
 *
 * \param[in] attr pointer to the attributes structure
 *
 * \return 0 if ok
 */
int wzd_thread_attr_destroy(wzd_thread_attr_t * attr);

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
int wzd_thread_attr_set_detached(wzd_thread_attr_t * attr);

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
int wzd_thread_join(wzd_thread_t * thread, void ** thread_return);

/** \brief Cancel thread by sending a signal
 *
 * \param[in] thread the thread to cancel
 */
int wzd_thread_cancel(wzd_thread_t * thread);


/* platform dependant types */

union wzd_thread_attr_t {
#ifndef WIN32
  pthread_attr_t _a;
#else
  HANDLE _a;
#endif
  void * _v;
};

union wzd_thread_t {
#ifndef WIN32
  pthread_t _t;
#else
  HANDLE _t;
#endif
  void * _v;
};

#endif /* __WZD_THREADS__ */
