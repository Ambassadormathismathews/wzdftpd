#ifndef __WZD_SHM__
#define __WZD_SHM__

/* this file is ultra platform dependant, as long as cygwin does not implement IPC */
/* note that read/write functions are encapsulated, to avoid concurrent access */

#ifdef __CYGWIN__
typedef void * wzd_sem_t;
#else /* __CYGWIN__ */
#ifdef WZD_MULTITHREAD
typedef struct sem_t * wzd_sem_t;
#else /* WZD_MULTITHREAD */
typedef int wzd_sem_t;
#endif /* WZD_MULTITHREAD */
#endif


/* You'd better NEVER touch this */
typedef struct {
#ifdef __CYGWIN__
  void * handle;
#else /* __CYGWIN__ */
  int shmid;
#endif /* __CYGWIN__ */
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
