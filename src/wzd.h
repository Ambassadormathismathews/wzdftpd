#ifndef __WZD__
#define __WZD__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#if 0
/*#ifdef __CYGWIN__*/

#include <winsock2.h>

#else

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#define INVALID_SOCKET -1
#define	closesocket close


#define Sleep(x)	usleep((x)*1000)

#endif

#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>
#include <poll.h>


/* must be first */
#include "wzd_hardlimits.h"

#include "wzd_backend.h"

typedef struct {
  wzd_backend_t	backend;
  int		max_threads;
  char *	logfilename;
  char *	logfilemode;
  FILE *	logfile;
  int		loglevel;
  int		mainSocket;
  int		port;
} wzd_config_t;

typedef enum {
  ASCII=0,
  BINARY
} xfer_t;

typedef enum {
  LIST_TYPE_SHORT=0,
  LIST_TYPE_LONG
} list_type_t;

typedef struct {
  int		sockfd;
  int		pid_child;
  int		portsock;
  int		pasvsock;
  int		dataport;
  int		dataip[4];
  char		currentpath[2048];
  wzd_user_t	userinfo;
  xfer_t	current_xfer_type;
} wzd_context_t;

extern wzd_config_t mainConfig;


/* DEBUG & LOG */
#define LEVEL_LOWEST	1
#define	LEVEL_FLOOD	1
#define	LEVEL_INFO	3
#define	LEVEL_NORMAL	5
#define	LEVEL_HIGH	7
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
#include "ls.h"

#endif /* __WZD__ */
