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
#include "wzd_vars.h"

#define	SHM_KEY	0x1331c0d3

unsigned long key;

wzd_config_t * config;
wzd_context_t * context_list;
wzd_user_t * user_list;
wzd_group_t * group_list;

#ifdef _MSC_VER /* FIXME VISUAL */
  int optind;
#endif

#ifndef __CYGWIN__
char *time_to_str(time_t time); /* defined in wzd_misc.c */
#else
char *time_to_str(time_t time)
{ /* This support functionw as written by George Shearer (Dr_Delete) */

  static char workstr[100];
  unsigned short int days=(time/86400),hours,mins,secs;
  hours=((time-(days*86400))/3600);
  mins=((time-(days*86400)-(hours*3600))/60);
  secs=(time-(days*86400)-(hours*3600)-(mins*60));

  workstr[0]=(char)0;
  if(days)
    sprintf(workstr,"%dd",days);
  if(hours)
    sprintf(workstr,"%s%s%dh",workstr,(workstr[0])?", ":"",hours);
  if(mins)
    sprintf(workstr,"%s%s%dm",workstr,(workstr[0])?", ":"",mins);
  if(secs)
    sprintf(workstr,"%s%s%ds",workstr,(workstr[0])?", ":"",secs);
  if (!days && !hours && !mins && !secs)
    sprintf(workstr,"0 seconds");

  return(workstr);
}
#endif


void usage(const char *progname)
{
  fprintf(stderr,"Usage: %s [-k shm_key] get|set [paramname value]\r\n",progname);
}

int parse_args(int argc, char **argv)
{
#ifndef _MSC_VER /* FIXME VISUAL */
  int opt;
#endif
  unsigned long l;
  char *ptr;

#ifndef _MSC_VER /* FIXME VISUAL */
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

void print_config(wzd_config_t * config)
{
  char buffer[1024];

  if (config->site_closed) {
    printf("Server is CLOSED\n");
  }

  if (vars_get("max_threads",buffer,1024,config)) return;
  printf("Max threads allowed: %s\n",buffer);

  if (vars_get("port",buffer,1024,config)) return;
  printf("Port: %s\n",buffer);

  if (vars_get("pasv_low",buffer,1024,config)) return;
  printf("Passive Range: %s",buffer);
  if (vars_get("pasv_high",buffer,1024,config)) return;
  printf(" -> %s\n",buffer);

  if (vars_get("max_dl",buffer,1024,config)) return;
  printf("Max dl speed: %s\n",buffer);
  if (vars_get("max_ul",buffer,1024,config)) return;
  printf("Max ul speed: %s\n",buffer);
  
  if (vars_get("loglevel",buffer,1024,config)) return;
  printf("loglevel: %s\n",buffer);

  if (vars_get("uptime",buffer,1024,config)) return;
  printf("Uptime: %s\n",buffer);
}

void help_request_get(void)
{
  printf("Valid arguments are: all, loglevel, max_dl, max_threads, max_ul\n");
  printf("  pasv_low, pasv_high, port, uptime\n");
}

int request_get(const char *arg)
{
  char buffer[1024];

  if (!arg || strlen(arg)<=0) return -1;

  if (strcasecmp(arg,"all")==0) {
    print_config(config);
    return 0;
  }
  if (vars_get(arg,buffer,1024,config)==0) {
    printf("%s\n",buffer);
    return 0;
  }

  help_request_get();

  return 1;
}

void help_request_set(void)
{
  printf("Valid arguments are:\n");
  printf("  loglevel\n");
  printf("  serverstop:  set this to 1 to stop server\n");
}

int request_set(const char *arg, const char *value)
{
  if (!arg || strlen(arg)<=0) return -1;

  if (strcasecmp(arg,"serverstop")==0) {
    if (strcmp(value,"1")==0) config->serverstop=1;
    return 0;
  }
  if (vars_set(arg,(void*)value,strlen(value),config)==0) {
    return 0;
  }

  help_request_set();

  return 1;
}


int main(int argc, char *argv[])
{
  char * datazone;
  unsigned int i;
#ifdef WIN32
  void * handle;
  char name[256];
#else
  int shmid;
#endif

  /* default values */
  key = SHM_KEY;

  if (parse_args(argc,argv)) {
    usage(argv[0]);
    exit(1);
  }

#ifdef WIN32
  sprintf(name,"%lu",key-1);
  handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,name);
  if (handle == NULL)
#else
  shmid = shmget(key-1,0,0400);
  if (shmid == -1)
#endif
  {
    fprintf(stderr,"shmget failed\n");
    fprintf(stderr,"This is probably due to\n");
    fprintf(stderr,"\t* server not started\n");
    fprintf(stderr,"\t* wrong key\n");
    return -1;
  }

#ifdef WIN32
  config = MapViewOfFile(handle,FILE_MAP_ALL_ACCESS,0, 0, 0);
  if (config == NULL)
#else
  config = shmat(shmid,NULL,0);
  if (config == (void*)-1)
#endif
  {
    fprintf(stderr,"shmat failed\n");
    return -1;
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


  /************ begin user part *************************/

  if (optind+1 >= argc) {
    usage(argv[0]);
    exit(1);
  }

  if (strcasecmp(argv[optind],"get")==0) {
    request_get(argv[optind+1]);
  }
  else if (strcasecmp(argv[optind],"set")==0) {
    if (optind+2 >= argc) {
      usage(argv[0]);
      exit(1);
    }
    request_set(argv[optind+1],argv[optind+2]);
  } else {
    usage(argv[0]);
    exit(1);
  }
/*  print_config(config);*/

  /************ end user part ***************************/

#ifdef  WIN32
  CloseHandle(handle);
#else
  shmdt(config);
  shmdt(datazone);
#endif
  return 0;
}
