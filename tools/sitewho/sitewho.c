#ifdef __CYGWIN__
#include <w32api/windows.h>
#else /* __CYGWIN__ */
# include <sys/types.h>
# include <sys/ipc.h>
# include <sys/shm.h>
#endif /* __CYGWIN__ */

#include <stdio.h>
#include <wzd.h>
/*#include <wzd_shm.h>*/

#define	SHM_KEY	0x1331c0d3

/* FIXME ... this is an unresolved symbol */
unsigned int wzd_server_uid;

int main(int argc, char *argv[])
{
  int shmid;
  unsigned int length=0;
  char * datazone;
  wzd_context_t * context_list;
  wzd_user_t * user_list;
  wzd_group_t * group_list;
  int i,found=0;
/*  wzd_shm_t * shm;*/
#ifdef __CYGWIN__
  void * handle;
  char name[256];
#endif

  length += HARD_USERLIMIT*sizeof(wzd_context_t);
  length += HARD_DEF_USER_MAX*sizeof(wzd_user_t);
  length += HARD_DEF_GROUP_MAX*sizeof(wzd_group_t);

#ifdef __CYGWIN__
  sprintf(name,"%lu",SHM_KEY);
  handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,name);
  if (handle == NULL)
#else
  shmid = shmget(SHM_KEY,0,0400);
/*  shm = wzd_shm_get(SHM_KEY,0400);*/
  if (shmid == -1)
/*  if (!shm) */
#endif
  {
    fprintf(stderr,"shmget failed\n");
    fprintf(stderr,"This is probably due to\n");
    fprintf(stderr,"\t* server not started\n");
    fprintf(stderr,"\t* wrong key\n");
    return -1;
  }

#ifdef __CYGWIN__
  datazone = MapViewOfFile(handle,FILE_MAP_ALL_ACCESS,0, 0, 0);
  if (datazone == NULL)
#else
  datazone = shmat(shmid,NULL,SHM_RDONLY);
  if (datazone == (void*)-1)
#endif
  {
    fprintf(stderr,"shmat failed\n");
    return -1;
  }
/*  datazone = shm->datazone;*/

  context_list = (wzd_context_t*)datazone;
  i = HARD_USERLIMIT;
  i = HARD_USERLIMIT*sizeof (wzd_context_t);
  user_list = ((void*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t));
  group_list = ((void*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t)) + (HARD_DEF_USER_MAX*sizeof(wzd_user_t)); 

  /* find non-empty contexts */
  for (i=0; i<HARD_USERLIMIT; i++) {
    if (context_list[i].magic == CONTEXT_MAGIC) {
      found=1;
      break;
    }
  }
  if (!found) {
    fprintf(stdout,"Nobody here !\n");
  }
  else {
    fprintf(stdout,"|---------------.------------------.----------------.---------------------|\n");
    fprintf(stdout,"|           name|           tagline|       ip       |           action    |\n");
    fprintf(stdout,"|---------------.------------------.----------------.---------------------|\n");
    for (i=0; i<HARD_USERLIMIT; i++) {
      if (context_list[i].magic == CONTEXT_MAGIC) {
        wzd_user_t * user;
	wzd_context_t * context;
	char hostip[18];
        unsigned int id;
	context = &context_list[i];
        id = context_list[i].userid;
        user = &user_list[id];
	snprintf(hostip,18,"%d.%d.%d.%d",
	    context->hostip[0],context->hostip[1],context->hostip[2],
	    context->hostip[3]);
	/* XXX hide ip */
	strcpy(hostip,"xxx.xxx.xxx.xxx");
        fprintf(stdout,"|%15s|   %15s|%16s|%20s |\n",
            user->username?user->username:"NULL",
            user->username?user->tagline:"NULL",
	    hostip,
	    context->last_command);
	if (strncasecmp(context->last_command,"retr",4)==0) {
	  fprintf(stdout,"|  %.1f kB/s  |\n",context->current_dl_limiter.current_speed/1024.f);
	} else {
	  if (strncasecmp(context->last_command,"stor",4)==0) {
	    fprintf(stdout,"|  %.1f kB/s  |\n",context->current_ul_limiter.current_speed/1024.f);
	  }
	}
      }
    }
    fprintf(stdout,"|---------------.------------------.----------------.---------------------|\n");
  }

#ifdef __CYGWIN__
  CloseHandle(handle);
#else
  shmdt(datazone);
  /* FIXME wzd_shm_free does NOT work as it tries to destroy a semaphore
   * resulting in a SIGSEGV ...
   */
/*  wzd_shm_free(shm);*/
/*  shmdt(shm->datazone);*/
#endif
  return 0;
}
