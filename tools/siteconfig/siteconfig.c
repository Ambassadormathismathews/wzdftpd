#ifdef __CYGWIN__
#include <w32api/windows.h>
#else /* __CYGWIN__ */
# include <sys/types.h>
# include <sys/ipc.h>
# include <sys/shm.h>
#endif /* __CYGWIN__ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <wzd.h>
/*#include <wzd_shm.h>*/

#define	SHM_KEY	0x1331c0d3

unsigned long key;

/* avoid bring undefined reference */
unsigned int wzd_server_uid;

wzd_config_t * config;

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
  int opt;
  unsigned long l;
  char *ptr;

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
  
  return 0;
}

void print_config(wzd_config_t * config)
{
  time_t t;

  if (config->site_closed) {
    printf("Server is CLOSED\n");
  }

  printf("Max threads allowed: %d\n",config->max_threads);

  printf("Port: %d\n",config->port);

  printf("Passive Range: %d -> %d\n",config->pasv_low_range,config->pasv_high_range);

  printf("Max dl speed: %d\n",config->global_dl_limiter.maxspeed);
  printf("Max ul speed: %d\n",config->global_ul_limiter.maxspeed);
  
  printf("Loglevel: %s\n",loglevel2str(config->loglevel));

  time(&t);
  t = t - config->server_start;
  printf("Uptime: %s\n",time_to_str(t));
}

void help_request_get(void)
{
  printf("Valid arguments are: all, loglevel, max_dl, max_threads, max_ul\n");
  printf("  pasv_low, pasv_high, port, uptime\n");
}

int request_get(const char *arg)
{
  time_t t;

  if (!arg || strlen(arg)<=0) return -1;

  if (strcasecmp(arg,"all")==0) {
    print_config(config);
    return 0;
  }
  if (strcasecmp(arg,"max_threads")==0) {
    printf("%d\n",config->max_threads);
    return 0;
  }
  if (strcasecmp(arg,"port")==0) {
    printf("%d\n",config->port);
    return 0;
  }
  if (strcasecmp(arg,"max_dl")==0) {
    printf("%d\n",config->global_dl_limiter.maxspeed);
    return 0;
  }
  if (strcasecmp(arg,"max_ul")==0) {
    printf("%d\n",config->global_ul_limiter.maxspeed);
    return 0;
  }
  if (strcasecmp(arg,"loglevel")==0) {
    printf("%s\n",loglevel2str(config->loglevel));
    return 0;
  }
  if (strcasecmp(arg,"pasv_low")==0) {
    printf("%d\n",config->pasv_low_range);
    return 0;
  }
  if (strcasecmp(arg,"pasv_high")==0) {
    printf("%d\n",config->pasv_high_range);
    return 0;
  }
  if (strcasecmp(arg,"uptime")==0) {
    time(&t);
    t = t - config->server_start;

    printf("%s\n",time_to_str(t));
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
  int i;

  if (!arg || strlen(arg)<=0) return -1;

  if (strcasecmp(arg,"loglevel")==0) {
    i = str2loglevel(value);
    if (i==-1) {
      printf("Invalid level\n");
      return 1;
    }
    config->loglevel = i;
    return 0;
  }
  if (strcasecmp(arg,"serverstop")==0) {
    if (strcmp(value,"1")==0) config->serverstop=1;
    return 0;
  }

  help_request_set();

  return 1;
}


int main(int argc, char *argv[])
{
  int shmid;
#ifdef __CYGWIN__
  void * handle;
  char name[256];
#endif

  /* default values */
  key = SHM_KEY;

  if (parse_args(argc,argv)) {
    usage(argv[0]);
    exit(1);
  }

#ifdef __CYGWIN__
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

#ifdef __CYGWIN__
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

#ifdef  __CYGWIN__
  CloseHandle(handle);
#else
  shmdt(config);
#endif
  return 0;
}
