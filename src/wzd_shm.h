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

#ifndef __WZD_SHM__
#define __WZD_SHM__

/* this file is ultra platform dependant, as long as cygwin does not implement IPC */
/* note that read/write functions are encapsulated, to avoid concurrent access */


#ifdef WIN32
typedef void * wzd_sem_t;
#else /* WIN32 */
#ifdef WZD_MULTITHREAD
typedef struct sem_t * wzd_sem_t;
#else /* WZD_MULTITHREAD */
typedef int wzd_sem_t;
#endif /* WZD_MULTITHREAD */
#endif


/* You'd better NEVER touch this */
/** @brief Shared memory zone */
typedef struct {
#ifdef WIN32
  void * handle;
#else /* WIN32 */
  int shmid;
#endif /* WIN32 */
  void * datazone;
  wzd_sem_t semid;
} wzd_shm_t;


/* creates a semaphore */
wzd_sem_t wzd_sem_create(unsigned long key, int nsems, int flags);

/* destroy sem */
void wzd_sem_destroy(wzd_sem_t sem);

/* locks a semaphore */
int wzd_sem_lock(wzd_sem_t sem, int n);

/* unlocks a semaphore */
int wzd_sem_unlock(wzd_sem_t sem, int n);


/* creates an shm zone */
wzd_shm_t * wzd_shm_create(unsigned long key, int size, int flags);

/* returns an EXISTING shm zone */
wzd_shm_t * wzd_shm_get(unsigned long key, int flags);

/* read mem */
int wzd_shm_read(wzd_shm_t * shm, void * data, int size, int offset);

/* writes mem */
int wzd_shm_write(wzd_shm_t * shm, void * data, int size, int offset);

/* destroys shm */
void wzd_shm_free(wzd_shm_t * shm);

/* cleanup if previous exec has crashed */
void wzd_shm_cleanup(unsigned long key);

#endif /* __WZD_SHM__ */
