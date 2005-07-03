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
/** \file wzd_shm.c
  * \brief Semaphores and Shared Memory implementation
  * \warning This file contains many platform-dependant code.
  */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#ifdef __CYGWIN__
#include <w32api/windows.h>
#endif /* __CYGWIN__ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <semaphore.h>
#endif

#endif /* WZD_USE_PCH */

#include "wzd_structs.h"
#include "wzd_libmain.h" /* getlib_server_uid */
#include "wzd_log.h"
#include "wzd_shm.h"
#include "wzd_ServerThread.h"

#ifdef WZD_MULTITHREAD

#if !defined(WIN32)
#include <sys/ipc.h>
#include <sys/shm.h>
#endif /* __CYGWIN__ */


/** creates a semaphore */
wzd_sem_t wzd_sem_create(unsigned long key, int nsems, int flags)
{
  wzd_sem_t sem;
#ifndef WIN32
  sem = malloc(sizeof(sem_t));
  sem_init((sem_t*)sem,0,1);
#else
  sem = malloc(sizeof(CRITICAL_SECTION));
  InitializeCriticalSection(sem);
#endif
  return sem;
}

/** destroy sem */
void wzd_sem_destroy(wzd_sem_t sem)
{
#ifndef WIN32
  sem_destroy((sem_t*)sem);
#else
  DeleteCriticalSection(sem);
#endif
  free(sem);
}

/** locks a semaphore */
int wzd_sem_lock(wzd_sem_t sem, int n)
{
#ifndef WIN32
  return sem_wait((sem_t*)sem);
#else
  EnterCriticalSection(sem);
  return 0;
#endif
}

/** unlocks a semaphore */
int wzd_sem_unlock(wzd_sem_t sem, int n)
{
#ifndef WIN32
  return sem_post((sem_t*)sem);
#else
  LeaveCriticalSection(sem);
  return 0;
#endif
}

#endif /* WZD_MULTITHREAD */

#ifdef WIN32

#ifndef WZD_MULTITHREAD
/** create a semaphore */
wzd_sem_t wzd_sem_create(unsigned long key, int nsems, int flags)
{
  wzd_sem_t sem = malloc(sizeof(CRITICAL_SECTION));
  InitializeCriticalSection(sem);
  return sem;
}

/** destroy sem */
void wzd_sem_destroy(wzd_sem_t sem)
{
  DeleteCriticalSection(sem);
  free(sem);
}

/** locks a semaphore */
int wzd_sem_lock(wzd_sem_t sem, int n)
{
  EnterCriticalSection(sem);
  return 0;
}

/** unlocks a semaphore */
int wzd_sem_unlock(wzd_sem_t sem, int n)
{
  LeaveCriticalSection(sem);
  return 0;
}
#endif /* WZD_MULTITHREAD */

/** creates an shm zone */
wzd_shm_t * wzd_shm_create(unsigned long key, unsigned int size, int flags)
{
  wzd_shm_t *shm;
  char name[256];

  shm = malloc(sizeof(wzd_shm_t));
  if (!shm) return NULL;

  shm->datazone = NULL;
  sprintf(name,"%lu",key);
  shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE,NULL,
    PAGE_READWRITE, 0, size, name);
  if (shm->handle == NULL) {
fprintf(stderr,"Could not create file mapping\n");
    return NULL;
  }
  shm->datazone = MapViewOfFile(shm->handle,FILE_MAP_ALL_ACCESS,
    0, 0, 0);
  if (shm->datazone == NULL) {
fprintf(stderr,"Could not get file mapping view\n");
    CloseHandle(shm->handle);
    return NULL;
  }


  return shm;
}

/** returns an EXISTING shm zone */
wzd_shm_t * wzd_shm_get(unsigned long key, int flags)
{
  wzd_shm_t *shm;
  char name[256];

  shm = malloc(sizeof(wzd_shm_t));
  if (!shm) return NULL;

  shm->datazone = NULL;
  sprintf(name,"%lu",key);
  shm->handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,name);
  if (shm->handle == NULL) {
fprintf(stderr,"Could not open file mapping\n");
    return NULL;
  }
  shm->datazone = MapViewOfFile(shm->handle,FILE_MAP_ALL_ACCESS,
    0, 0, 0);
  if (shm->datazone == NULL) {
fprintf(stderr,"Could not get file mapping view\n");
    CloseHandle(shm->handle);
    return NULL;
  }


  return shm;
}

/** read mem */
int wzd_shm_read(wzd_shm_t * shm, void * data, int size, int offset)
{
  return 0;
}

/** writes mem */
int wzd_shm_write(wzd_shm_t * shm, void * data, int size, int offset)
{
  return 0;
}

/** destroys shm */
void wzd_shm_free(wzd_shm_t * shm)
{
  if (shm)
    UnmapViewOfFile(shm->handle);
}

/** cleanup if previous exec has crashed */
void wzd_shm_cleanup(unsigned long key)
{
}


#else /* WIN32 */

#include <sys/sem.h>

#ifndef WZD_MULTITHREAD

typedef union semun {
  int val;                  /* value for SETVAL */
  struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
  unsigned short *array;    /* array for GETALL, SETALL */
  struct seminfo *__buf;    /* buffer for IPC_INFO */
} semun_t;

/** creates a semaphore */
wzd_sem_t wzd_sem_create(unsigned long key, int nsems, int flags)
{
  wzd_sem_t sem;

  semun_t semun;
  unsigned short table[1];
  sem = semget(key,nsems,IPC_CREAT | IPC_EXCL | 0600);
  if (sem<0) return -1;
  table[0] = 1;
  semun.array = table;
  if (semctl(sem,0,SETALL,semun)<0) return -1;

  return sem;
}

/** destroy sem */
void wzd_sem_destroy(wzd_sem_t sem)
{
  /* TODO test ret */
  semctl(sem,IPC_RMID,0);
}

/** locks a semaphore */
int wzd_sem_lock(wzd_sem_t sem, int n)
{
  struct sembuf buf;

  buf.sem_num = 0;
  buf.sem_op = -n;
  buf.sem_flg = SEM_UNDO;
  return semop( sem, &buf, 1 );
}

/** unlocks a semaphore */
int wzd_sem_unlock(wzd_sem_t sem, int n)
{
  struct sembuf buf;

  buf.sem_num = 0;
  buf.sem_op = n;
  buf.sem_flg = SEM_UNDO;
  return semop( sem, &buf, 1 );
}
#endif /* WZD_MULTITHREAD */

/** creates an shm zone */
wzd_shm_t * wzd_shm_create(unsigned long key, unsigned int size, int flags)
{
  wzd_shm_t *shm;
/*  semun_t u_semun;
  unsigned short array[1];*/
  int have_set_uid=0;

  shm = malloc(sizeof(wzd_shm_t));
  if (!shm) return NULL;

  if (geteuid()==0) {
    setreuid(-1,getlib_server_uid());
    have_set_uid = 1;
  }

  shm->datazone = NULL;
  shm->shmid = shmget((key_t)key,size,IPC_CREAT | IPC_EXCL | 0600 );

  if (shm->shmid == -1) {
    if (errno == EEXIST) {
fprintf(stderr,"CRITICAL: shm exists with selected shm_key 0x%lx - check your config file\n",key);
    /* try to delete ipc ? */
/*      shm->shmid = shmget((key_t)key,size,0600);
      if (shm->shmid != -1) shmctl(shm->shmid,IPC_RMID,NULL);*/
    } else {
fprintf(stderr,"CRITICAL: could not shmget, key %lu, size %d - errno is %d (%s)\n",
    key,size,errno,strerror(errno));
    }
    if (have_set_uid) setreuid(-1,0); /* become root again */
    return NULL;
  }

  shm->datazone = shmat(shm->shmid,NULL,0);
  if (shm->datazone == (void*)-1) {
fprintf(stderr,"CRITICAL: could not shmat, key %lu, size %d - errno is %d (%s)\n",
    key,size,errno,strerror(errno));
    if (have_set_uid) setreuid(-1,0); /* become root again */
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }
  shm->semid = wzd_sem_create(key,1,0);

#if WZD_MULTITHREAD
  if (!shm->semid) {
#else
  if (shm->semid == -1) {
#endif
fprintf(stderr,"CRITICAL: could not semget, key %lu - errno is %d (%s)\n",key,errno,strerror(errno));
    if (have_set_uid) setreuid(-1,0); /* become root again */
    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }


  if (have_set_uid) setreuid(-1,0); /* become root again */

  return shm;
}

/** returns an EXISTING shm zone */
wzd_shm_t * wzd_shm_get(unsigned long key, int flags)
{
  wzd_shm_t *shm;
/*  int have_set_uid=0;*/

  shm = malloc(sizeof(wzd_shm_t));
  if (!shm) return NULL;

  /* usefull in simple get ? */
#if 0
  if (geteuid()==0) {
    setreuid(-1,wzd_server_uid);
    have_set_uid = 1;
  }
#endif

  shm->datazone = NULL;
  shm->shmid = shmget((key_t)key, 0, flags );

  if (shm->shmid == -1) {
    out_err(LEVEL_CRITICAL,"CRITICAL: could not shmget, key %lu, - errno is %d (%s)\n",
    key,errno,strerror(errno));
#if 0
    if (have_set_uid) setreuid(-1,0); /* become root again */
#endif
    return NULL;
  }

  shm->datazone = shmat(shm->shmid,NULL,0);
  if (shm->datazone == (void*)-1) {
fprintf(stderr,"CRITICAL: could not shmat, key %lu - errno is %d (%s)\n",
    key,errno,strerror(errno));
#if 0
    if (have_set_uid) setreuid(-1,0); /* become root again */
#endif
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }

  /* TODO XXX FIXME here we need to GET an existing semaphore ...
   * works on multiprocess, but in mt ?!
   */
#if WZD_MULTITHREAD
  shm->semid = (struct sem_t*)semget(key,1,0);
  if (!shm->semid) {
#else
  shm->semid = semget(key,1,0);
  if (shm->semid == -1) {
#endif
fprintf(stderr,"CRITICAL: could not semget, key %lu - errno is %d (%s)\n",key,errno,strerror(errno));
#if 0
    if (have_set_uid) setreuid(-1,0); /* become root again */
#endif
    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }

#if 0
  if (have_set_uid) setreuid(-1,0); /* become root again */
#endif

  return shm;
}

/** read mem */
int wzd_shm_read(wzd_shm_t * shm, void * data, int size, int offset)
{
/*  struct sembuf s;*/

  if (!shm) return -1;

#if 0
  /* get sem : P() */
  s.sem_num = 0;
  s.sem_op = -1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
#endif
  if (wzd_sem_lock(shm->semid,1)) {
fprintf(stderr,"CRITICAL: could not set sem value,  %ld - errno is %d (%s)\n",(unsigned long)shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  /* read data */
  memcpy(data,(char*)shm->datazone+offset,size);

#if 0
  /* restore sem : V() */
  s.sem_num = 0;
  s.sem_op = 1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
#endif
  if (wzd_sem_unlock(shm->semid,1)) {
fprintf(stderr,"CRITICAL: could not restore sem value, sem %ld - errno is %d (%s)\n",(unsigned long)shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  return 0;
}

/** writes mem */
int wzd_shm_write(wzd_shm_t * shm, void * data, int size, int offset)
{
/*  struct sembuf s;*/

  if (!shm) return -1;

#if 0
  /* get sem : P() */
  s.sem_num = 0;
  s.sem_op = -1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
#endif
  if (wzd_sem_lock(shm->semid,1)) {
fprintf(stderr,"CRITICAL: could not set sem value, sem %ld - errno is %d (%s)\n",(unsigned long)shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  /* write data */
  memcpy((char*)shm->datazone+offset,data,size);

#if 0
  /* restore sem : V() */
  s.sem_num = 0;
  s.sem_op = 1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
#endif
  if (wzd_sem_unlock(shm->semid,1)) {
fprintf(stderr,"CRITICAL: could not restore sem value, sem %ld - errno is %d (%s)\n",(unsigned long)shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  return 0;
}

/** destroys shm */
void wzd_shm_free(wzd_shm_t * shm)
{
  if (!shm) return;

/*  semctl(shm->semid,IPC_RMID,0);*/
  wzd_sem_destroy(shm->semid);
  shmdt(shm->datazone);
  shmctl(shm->shmid,IPC_RMID,NULL);
  free(shm);
}

/** cleanup if previous exec has crashed */
void wzd_shm_cleanup(unsigned long key)
{
#ifndef WZD_MULTITHREAD
  unsigned int semid;
#endif

  {
    int shmid;
    shmid = shmget((key_t)key,0,0600 );
    if (shmid != -1) shmctl(shmid,IPC_RMID,NULL);
  }
#ifndef WZD_MULTITHREAD
  semid = semget((key_t)key,0,0 );
  if (semid != -1) semctl(semid,IPC_RMID,0);
#endif
}


#endif /* WIN32 */
