# include <sys/types.h>
# include <sys/ipc.h>
# include <sys/shm.h>

#include <stdio.h>
#include <wzd.h>

#define	SHM_KEY	0x1331c0d3

int main(int argc, char *argv[])
{
  int shmid;
  unsigned int length=0;
  char * datazone;
  wzd_context_t * context_list;
  wzd_user_t * user_list;
  wzd_group_t * group_list;
  int i,found=0;

  length += HARD_USERLIMIT*sizeof(wzd_context_t);
  length += HARD_DEF_USER_MAX*sizeof(wzd_user_t);
  length += HARD_DEF_GROUP_MAX*sizeof(wzd_group_t);

  shmid = shmget(SHM_KEY,0,0400);
  if (shmid == -1) {
    fprintf(stderr,"shmget failed\n");
    fprintf(stderr,"This is probably due to\n");
    fprintf(stderr,"\t* server not started\n");
    fprintf(stderr,"\t* wrong key\n");
    return -1;
  }

  datazone = shmat(shmid,NULL,SHM_RDONLY);
  if (datazone == (void*)-1) {
    fprintf(stderr,"shmat failed\n");
    return -1;
  }

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
        fprintf(stdout,"|%15s|   %15s|%16s|%20s |\n",
            user->username?user->username:"NULL",
            user->username?user->tagline:"NULL",
	    hostip,
	    context->last_command);
      }
    }
    fprintf(stdout,"|---------------.------------------.----------------.---------------------|\n");
  }

  shmdt(datazone);
  return 0;
}
