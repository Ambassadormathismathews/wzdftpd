#ifdef __CYGWIN__
#include <w32api/windows.h>
#endif /* __CYGWIN__ */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"
#include "wzd_log.h"

#ifdef __CYGWIN__

/* creates an shm zone */
wzd_shm_t * wzd_shm_create(unsigned long key, int size, int flags)
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

/* returns an EXISTING shm zone */
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

/* read mem */
int wzd_shm_read(wzd_shm_t * shm, void * data, int size, int offset)
{
  return 0;
}

/* writes mem */
int wzd_shm_write(wzd_shm_t * shm, void * data, int size, int offset)
{
  return 0;
}

/* destroys shm */
void wzd_shm_free(wzd_shm_t * shm)
{
    UnmapViewOfFile(shm->handle);
}

/* cleanup if previous exec has crashed */
void wzd_shm_cleanup(unsigned long key)
{
}


#else /* __CYGWIN__ */


#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

typedef union semun {
  int val;                  /* value for SETVAL */
  struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
  unsigned short *array;    /* array for GETALL, SETALL */
  struct seminfo *__buf;    /* buffer for IPC_INFO */
} semun_t;

/* creates an shm zone */
wzd_shm_t * wzd_shm_create(unsigned long key, int size, int flags)
{
  wzd_shm_t *shm;
  semun_t u_semun;
  unsigned short array[1];
  int have_set_uid=0;

  shm = malloc(sizeof(wzd_shm_t));
  if (!shm) return NULL;

  if (geteuid()==0) {
    setreuid(-1,1000); /* XXX FIXME */
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

  shm->semid = semget((key_t)key,1,0);

  if ( ! (shm->semid==-1 && errno==ENOENT) ) {
fprintf(stderr,"CRITICAL: sem exists with selected sem_key 0x%lx - check your config file\n",key);
    if (have_set_uid) setreuid(-1,0); /* become root again */
    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }

  shm->semid = semget((key_t)key,1,IPC_CREAT|IPC_EXCL|0600);

  if (shm->semid == -1) {
fprintf(stderr,"CRITICAL: could not semget, key %lu - errno is %d (%s)\n",key,errno,strerror(errno));
    if (have_set_uid) setreuid(-1,0); /* become root again */
    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }

  /* set sem value to 0 */
  array[0] = 0;
  u_semun.array = array;
  if (semctl(shm->semid,0,SETALL,u_semun)<0) {
fprintf(stderr,"CRITICAL: could not set sem value, key %lu - errno is %d (%s)\n",key,errno,strerror(errno));
    if (have_set_uid) setreuid(-1,0); /* become root again */
    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);
    return NULL;
  }

  if (have_set_uid) setreuid(-1,0); /* become root again */
  return shm;
}

/* returns an EXISTING shm zone */
wzd_shm_t * wzd_shm_get(unsigned long key, int flags)
{
  return NULL;
}

/* read mem */
int wzd_shm_read(wzd_shm_t * shm, void * data, int size, int offset)
{
  struct sembuf s;

  if (!shm) return -1;

  /* get sem : P() */
  s.sem_num = 0;
  s.sem_op = -1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
fprintf(stderr,"CRITICAL: could not set sem value, sem %d - errno is %d (%s)\n",shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  /* read data */
  memcpy(data,shm->datazone+offset,size);

  /* restore sem : V() */
  s.sem_num = 0;
  s.sem_op = 1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
fprintf(stderr,"CRITICAL: could not restore sem value, sem %d - errno is %d (%s)\n",shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  return 0;
}

/* writes mem */
int wzd_shm_write(wzd_shm_t * shm, void * data, int size, int offset)
{
  struct sembuf s;

  if (!shm) return -1;

  /* get sem : P() */
  s.sem_num = 0;
  s.sem_op = -1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
fprintf(stderr,"CRITICAL: could not set sem value, sem %d - errno is %d (%s)\n",shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  /* write data */
  memcpy(shm->datazone+offset,data,size);

  /* restore sem : V() */
  s.sem_num = 0;
  s.sem_op = 1;
  s.sem_flg = SEM_UNDO;
  if (semop(shm->semid,&s,1)<0) {
fprintf(stderr,"CRITICAL: could not restore sem value, sem %d - errno is %d (%s)\n",shm->semid,errno,strerror(errno));
/*    shmdt(shm->datazone);
    shmctl(shm->shmid,IPC_RMID,NULL);*/
    return 1;
  }

  return 0;
}

/* destroys shm */
void wzd_shm_free(wzd_shm_t * shm)
{
  if (!shm) return;

  semctl(shm->semid,IPC_RMID,0);
  shmdt(shm->datazone);
  shmctl(shm->shmid,IPC_RMID,NULL);
}

/* cleanup if previous exec has crashed */
void wzd_shm_cleanup(unsigned long key)
{
  unsigned int shmid, semid;

  shmid = shmget((key_t)key,0,0600 );
  if (shmid != -1) shmctl(shmid,IPC_RMID,NULL);
  semid = semget((key_t)key,0,0 );
  if (semid != -1) semctl(semid,IPC_RMID,0);
}


#endif /* __CYGWIN__ */
