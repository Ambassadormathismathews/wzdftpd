#ifndef __WZD__
#define __WZD__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#ifdef __CYGWIN__
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define INVALID_SOCKET -1
#endif

#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>

typedef struct {
	int		max_threads;
	char *	logfilename;
	char *	logfilemode;
	FILE *	logfile;
	int		loglevel;
	int		mainSocket;
	int		port;
} wzd_config_t;

extern wzd_config_t mainConfig;


/* DEBUG & LOG */
#define LEVEL_LOWEST	1
#define	LEVEL_FLOOD		1
#define	LEVEL_INFO		3
#define	LEVEL_NORMAL	5
#define	LEVEL_HIGH		7
#define	LEVEL_CRITICAL	9


typedef struct {
  int sock,idletime,usertype,pid;
  int resume,state,perm;
  int userip[4],dataip[4];
  unsigned short int dataport;
  int pasvsock;
  char rootdir[256],reldir[256],username[128];
  char url[256];
} wzd_child_t;


#include "wzd_messages.h"
#include "wzd_log.h"
#include "wzd_init.h"
#include "wzd_ServerThread.h"
#include "wzd_ClientThread.h"

#endif /* __WZD__ */
