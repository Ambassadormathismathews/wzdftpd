#ifndef __WZD_SHM__
#define __WZD_SHM__

/* this file is ultra platform dependant, as long as cygwin does not implement IPC */
/* note that read/write functions are encapsulated, to avoid concurrent access */


/* You'd better NEVER touch this */
typedef struct {
#ifdef __CYGWIN__
  void * handle;
#else /* __CYGWIN__ */
  int shmid;
#endif /* __CYGWIN__ */
  void * datazone;
  int semid;
} wzd_shm_t;


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

#endif /* __WZD_SHM__ */
