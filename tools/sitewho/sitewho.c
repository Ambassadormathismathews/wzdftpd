#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>

#ifdef _MSC_VER
#include <io.h>
#endif

#else

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif /* __CYGWIN__ && WINSOCK_SUPPORT */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*#include <wzd.h>*/

/* speed up compilation */
#define SSL void
#define SSL_CTX void

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_libmain.h"
#include "wzd_mod.h" /* essential to define WZD_MODULE_INIT */
/*#include <wzd_shm.h>*/

#define	SHM_KEY	0x1331c0d3

unsigned long key;

#ifdef _MSC_VER /* FIXME VISUAL */
  int optind;
#endif

static const wzd_user_t user_null = {
  -1,        /* uid;*/
  "unknown", /* username[HARD_USERNAME_LENGTH]; */
  "nopass",  /* userpass[MAX_PASS_LENGTH]; */
  "nowhere", /* rootpath[WZD_MAX_PATH]; */
  "notag",   /* tagline[256]; */
  0,         /* group_num; */
  { 0 },     /* groups[MAX_GROUPS_PER_USER]; */
  0,         /* max_idle_time; */
  0,         /* userperms; */
  "",        /* flags[MAX_FLAGS_NUM]; */
  0,         /* max_ul_speed; */
  0,         /* max_dl_speed; */
  0,         /* num_logins; */
  { 0 },     /* ip_allowed[HARD_IP_PER_USER][MAX_IP_LENGTH]; */
  { 0 },     /* stats; */
  0,         /* credits; */
  0,         /* ratio; */
  0,         /* user_slots; */
  0,         /* leech_slots; */
  0          /* last_login; */
};

void usage(const char *progname)
{
  fprintf(stderr,"Usage: %s [-k shm_key]\r\n",progname);
} 

int parse_args(int argc, char **argv)
{
  unsigned long l;
  char *ptr;
  
#ifndef _MSC_VER /* FIXME VISUAL */
  int opt;

   /* please keep options ordered ! */
  while ((opt=getopt(argc, argv, "hk:")) != -1) {
    switch (opt) {
    case 'h':
      usage(argv[0]);
      return 1;
    case 'k':
      l = strtoul(optarg,&ptr,0);
      if (*ptr != '\0') {
        usage(argv[0]); 
        return 1;
      }
      key = l;
      break;
    }
  }
#else /* _MSC_VER */
  optind = 1;
  while (optind < argc)
  {
	  if (argv[optind][0] == '-') {
		if (argv[optind][1] == 'h') { usage(argv[0]); return 1; }
		else if (argv[optind][1] == 'k') {
		  if (optind + 1 >= argc) { usage(argv[0]); return 1; }
          l = strtoul(argv[optind+1],&ptr,0);
          if (*ptr != '\0') { usage(argv[0]); return 1; }
          key = l;
		  optind += 2;
		}
		else { usage(argv[0]); return 1; }
	  }
	  else {
		  break;
	  }
  }
#endif /* _MSC_VER */

  return 0;
}

wzd_user_t * find_id(wzd_user_t * user_list,unsigned int id)
{
  unsigned int i=0;

  while (i<HARD_DEF_USER_MAX)
  {
    if (user_list[i].username[0] != '\0' && user_list[i].uid == id) {
        return &user_list[i];
    }
    i++;
  }
  return NULL;
}

int main(int argc, char *argv[])
{
  char command_buffer[4096];
  unsigned int length=0;
  char * datazone;
  wzd_context_t * context_list;
  wzd_user_t * user_list;
  wzd_group_t * group_list;
  int i,found=0;
/*  wzd_shm_t * shm;*/
#ifdef WIN32
  void * handle;
  char name[256];
#else
  int shmid;
#endif

  length += HARD_USERLIMIT*sizeof(wzd_context_t);
  length += HARD_DEF_USER_MAX*sizeof(wzd_user_t);
  length += HARD_DEF_GROUP_MAX*sizeof(wzd_group_t);

  /* default values */
  key = SHM_KEY;

  if (parse_args(argc,argv)) {
    usage(argv[0]);
    exit(1);
  }

#ifdef WIN32
  sprintf(name,"%lu",key);
  handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,name);
  if (handle == NULL)
#else
  shmid = shmget(key,0,0400);
/*  shm = wzd_shm_get(key,0400);*/
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

#ifdef WIN32
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
#ifndef _MSC_VER
  user_list = (void*)((char*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t));
  group_list = (void*)((char*)context_list) + (HARD_USERLIMIT*sizeof(wzd_context_t)) + (HARD_DEF_USER_MAX*sizeof(wzd_user_t));
#else
  user_list = (char*)context_list + HARD_USERLIMIT*sizeof(wzd_context_t);
  group_list = (char*)context_list + HARD_USERLIMIT*sizeof(wzd_context_t) + HARD_DEF_USER_MAX*sizeof(wzd_user_t);
#endif

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
/*        user = &user_list[id];*/
        user = find_id(user_list,id);
	snprintf(hostip,18,"%d.%d.%d.%d",
	    context->hostip[0],context->hostip[1],context->hostip[2],
	    context->hostip[3]);
	/* XXX hide ip */
	strcpy(hostip,"xxx.xxx.xxx.xxx");
	/* XXX if command is a site command, hide arguments */
	strncpy(command_buffer,context->last_command,4090);
	if (strncasecmp(command_buffer,"SITE ",5)==0) {
	  strcpy(command_buffer+5,"xxx");
	}
	if (strncasecmp(command_buffer,"PASS ",5)==0) {
	  strcpy(command_buffer+5,"xxx");
	}

        fprintf(stdout,"|%15s|   %15s|%16s|%20s |\n",
            user->username?user->username:"NULL",
            user->username?user->tagline:"NULL",
	    hostip,
	    command_buffer);
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

#ifdef WIN32
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
