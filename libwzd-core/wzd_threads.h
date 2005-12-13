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

/* use the WZD_THREAD_VOID macro to cast these types to void * */

typedef union wzd_thread_attr_t wzd_thread_attr_t;

typedef union wzd_thread_t wzd_thread_t;

#define WZD_THREAD_VOID(x) ((x)->_v)


/* thread creation */
int wzd_thread_create(wzd_thread_t * thread, wzd_thread_attr_t * attr, void * (start_routine)(void *), void * arg);


int wzd_thread_attr_init(wzd_thread_attr_t * attr);
int wzd_thread_attr_destroy(wzd_thread_attr_t * attr);

int wzd_thread_attr_set_detached(wzd_thread_attr_t * attr);

int wzd_thread_join(wzd_thread_t * thread, void ** thread_return);



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
