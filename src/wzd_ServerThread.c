#include "wzd.h"

/************ PROTOTYPES ***********/
void serverMainThreadProc(void *arg);
void serverMainThreadExit(int);

/************ VARS *****************/
int serverstop;

wzd_context_t *context_list;

time_t server_start;


/************ PUBLIC **************/
int runMainThread(int argc, char **argv)
{
	serverMainThreadProc(0);

	return 0;
}

/************ PRIVATE *************/
void cleanchild(int nr) {
  wzd_context_t * context;

  while (wait3(NULL, WNOHANG, NULL) > 0);

  context = &context_list[0];
  out_log(LEVEL_FLOOD,"Child %d exiting\n",nr);
  if (nr == context->pid_child) {
    context->pid_child = 0;
  }
}

void login_new(int socket_accept_fd)
{
  unsigned long remote_host;
  unsigned int remote_port;
  int userip[4];
  int newsock;
  wzd_context_t	* context;
  unsigned char *p;

  newsock = socket_accept(mainConfig.mainSocket, &remote_host, &remote_port);
  if (newsock <0)
  {
    out_log(LEVEL_HIGH,"Error while accepting\n");
    serverMainThreadExit(-1);
  }

  p=(unsigned char *)&remote_host;

  userip[0]=*p++;
  userip[1]=*p++;
  userip[2]=*p++;
  userip[3]=*p++;

  /* TODO here we can check IP BEFORE starting session */

  out_log(LEVEL_NORMAL,"Connection opened from %d.%d.%d.%d\n",
    userip[0],userip[1],userip[2],userip[3]);

  /* start child process */
  /* 1. create new context */
  context = malloc(sizeof(wzd_context_t));
  context->controlfd = newsock;
  context->datafd = 0;
  context->portsock = 0;
  context->pasvsock = 0;
  context->dataport=0;
  context->resume = 0;
  context->pid_child = 0;
  context->datamode = DATA_PORT;

  /* switch to tls mode ? */
#if SSL_SUPPORT
  if (mainConfig.tls_type == TLS_IMPLICIT)
    tls_auth("SSL",context);
  context->ssl.data_mode = TLS_CLEAR;
#endif

/*  if (fork()==0) {
    close (mainConfig.mainSocket);*/
    clientThreadProc(context);
/*  } else {
    close (newsock);
  }*/
}

void serverMainThreadProc(void *arg)
{
  int ret;
  fd_set r;
  struct timeval tv;

  context_list = malloc(HARD_USERLIMIT*sizeof(wzd_context_t)); /* FIXME 256 */

  /* if no backend available, we must bail out - otherwise there would be no login/pass ! */
  if (mainConfig.backend.handle == NULL) {
    out_log(LEVEL_CRITICAL,"I have no backend ! I must die, otherwise you will have no login/pass !!\n");
    exit (1);
  }

  out_log(LEVEL_INFO,"Thread %ld ok\n",pthread_self());

  /* catch broken pipe ! */
#ifdef __SVR4
  sigignore(SIGPIPE);
  sigset(SIGCHLD,cleanchild);
#else
  signal(SIGPIPE,SIG_IGN);
  signal(SIGCHLD,cleanchild);
#endif

  ret = mainConfig.mainSocket = socket_make(&mainConfig.port);
  if (ret == -1) {
    out_log(LEVEL_CRITICAL,"Error creating socket %s:%d\n",
      __FILE__, __LINE__);
    serverMainThreadExit(-1);
  }

  /* sets start time, for uptime */
  time(&server_start);

  /* now the blocking call: accept */
  out_log(LEVEL_INFO,"Entering accept mode (main)\n");

  serverstop=0;
  while (!serverstop) {
    FD_ZERO(&r);
    FD_SET(mainConfig.mainSocket,&r);
    tv.tv_sec = HARD_REACTION_TIME; tv.tv_usec = 0;
    ret = select(mainConfig.mainSocket+1, &r, NULL, NULL, &tv);
    
    switch (ret) {
    case -1: /* error */
      if (errno == EINTR) continue; /* retry */
      out_log(LEVEL_CRITICAL,"select failed (%s) :%s:%c\n",
        strerror(errno), __FILE__, __LINE__);
      serverMainThreadExit(-1);
      /* we abort, so we never returns */
    case 0: /* timeout */
      /* check for timeout logins */
      break;
    default: /* input */
      if (FD_ISSET(mainConfig.mainSocket,&r)) {
        login_new(mainConfig.mainSocket);
      }
    }
  } /* while (!serverstop) */


  serverMainThreadExit(0);
}

void serverMainThreadExit(int retcode)
{
  out_log(LEVEL_INFO,"Server exiting, retcode %d\n",retcode);
	close(mainConfig.mainSocket);
#if SSL_SUPPORT
  tls_exit();
#endif
  free(context_list);
	exit (retcode);
}
