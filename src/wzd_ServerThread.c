#include "wzd.h"

/************ PROTOTYPES ***********/
void serverMainThreadProc(void *arg);
void serverMainThreadExit(int);

/************ VARS *****************/
wzd_config_t *	mainConfig;
wzd_shm_t *	mainConfig_shm;

wzd_context_t *	context_list;
wzd_shm_t *	context_shm;

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
  int i;
  pid_t pid;

  while (1) {
    
    if ( (pid = wait3(NULL, WNOHANG, NULL)) > 0)
    {
      context = &context_list[0];
      out_log(LEVEL_FLOOD,"Child %u exiting\n",pid);
      /* TODO search context list and cleanup context */
      for (i=0; i<HARD_USERLIMIT; i++)
      {
	if (context_list[i].pid_child == pid) {
#ifdef DEBUG
	  fprintf(stderr,"Context found for pid %u - cleaning up\n",pid);
#endif
          client_die(&context_list[i]);
	  break;
	}
      }
      if (i == HARD_USERLIMIT) break; /* context not found ?! */
    } else { /* no more childs */
      break;
    } /* if */
  } /* while */

/*  if (nr == context->pid_child) {
    context->pid_child = 0;
  }*/
}

void context_init(wzd_context_t * context)
{
  context->magic = 0;
  memset(context->hostip,0,4);
  context->controlfd = -1;
  context->datafd = 0;
  context->portsock = 0;
  context->pasvsock = 0;
  context->dataport=0;
  context->resume = 0;
  context->pid_child = 0;
  context->datamode = DATA_PORT;
  context->current_action.token = TOK_UNKNOWN;
  context->current_limiter = NULL;
#if SSL_SUPPORT
  context->ssl.obj = NULL;
  context->ssl.data_ssl = NULL;
#endif
  context->read_fct = (read_fct_t)clear_read;
  context->write_fct = (write_fct_t)clear_write;
}

wzd_context_t * context_find_free(wzd_context_t * context_list)
{
  wzd_context_t * context=NULL;
  int i=0;

  while (i<HARD_USERLIMIT) {
    if (context_list[i].magic == 0) {
      /* cleanup context */
      context_init(context_list+i);
      return (context_list+i);
    }
#ifdef DEBUG
    if (context_list[i].magic != CONTEXT_MAGIC) {
fprintf(stderr,"*** CRITICAL *** context list could be corrupted at index %d\n",i);
    }
#endif /* DEBUG */
    i++;
  }

  return context;
}

/* returns 1 if ip is ok, 0 if ip is denied, -1 if ip is not in list */
int global_check_ip_allowed(int userip[4])
{
  char ip[30];

  snprintf(ip,30,"%d.%d.%d.%d",userip[0],userip[1],userip[2],userip[3]);
  switch (mainConfig->login_pre_ip_check) {
  case 1: /* order allow, deny */
    if (ip_inlist(mainConfig->login_pre_ip_allowed,ip)==1) return 1;
    if (ip_inlist(mainConfig->login_pre_ip_denied,ip)==1) return 0;
    break;
  case 2: /* order deny, allow */
    if (ip_inlist(mainConfig->login_pre_ip_denied,ip)==1) return 0;
    if (ip_inlist(mainConfig->login_pre_ip_allowed,ip)==1) return 1;
    break;
  }
  return -1;
}

void login_new(int socket_accept_fd)
{
  unsigned long remote_host;
  unsigned int remote_port;
  int userip[4];
  int newsock;
  wzd_context_t	* context;
  unsigned char *p;
#ifdef WZD_MULTIPROCESS
#ifdef __CYGWIN__
  unsigned long shm_key = mainConfig->shm_key;
#endif /* __CYGWIN__ */
#endif /* WZD_MULTIPROCESS */

  newsock = socket_accept(mainConfig->mainSocket, &remote_host, &remote_port);
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

  /* Here we check IP BEFORE starting session */
  /* do this iff login_pre_ip_check is enabled */
  if (mainConfig->login_pre_ip_check &&
        global_check_ip_allowed(userip)<=0) { /* IP was rejected */
    /* FIXME we should not be in raw mode here ... */
    char * reject_msg = "421-Your ip was rejected\r\n";
    clear_write(newsock,reject_msg,strlen(reject_msg),0,HARD_XFER_TIMEOUT,context);
    close(newsock);
    out_log(LEVEL_HIGH,"Failed login from %d.%d.%d.%d: global ip rejected\n",
      userip[0],userip[1],userip[2],userip[3]);
    return;
  }

  out_log(LEVEL_NORMAL,"Connection opened from %d.%d.%d.%d\n",
    userip[0],userip[1],userip[2],userip[3]);

  /* start child process */
#ifdef WZD_MULTIPROCESS
  if (fork()==0) { /* child */
    /* 0. get shared memory zones */
#ifdef __CYGWIN__
    mainConfig_shm = wzd_shm_create(shm_key-1,sizeof(wzd_config_t),0);
    if (mainConfig_shm == NULL) {
      /* NOTE we do not have any out_log here, since we have no config !*/
      out_err(LEVEL_CRITICAL,"I can't open main config shm ! (child)\n");
      exit(1);
    }
    mainConfig = mainConfig_shm->datazone;
    context_shm = wzd_shm_create(shm_key,HARD_USERLIMIT*sizeof(wzd_context_t),0);
    if (context_shm == NULL) {
      out_err(LEVEL_CRITICAL,"I can't open context shm ! (child)\n");
      exit(1);
    }
    context_list = context_shm->datazone;
#endif /* __CYGWIN__ */

    /* close unused fd */
    close (mainConfig->mainSocket);
    out_log(LEVEL_FLOOD,"Child %d created\n",getpid());
#endif /* WZD_MULTIPROCESS */
    
    /* 1. create new context */
/*  context = malloc(sizeof(wzd_context_t));*/
    context = context_find_free(context_list);
    if (!context) {
      out_log(LEVEL_CRITICAL,"Could not get a free context - hard user limit reached ?\n");
      close(newsock);
      return;
    }

    /* don't forget init is done before */
    context->magic = CONTEXT_MAGIC;
    context->controlfd = newsock;
    context->hostip[0] = userip[0];
    context->hostip[1] = userip[1];
    context->hostip[2] = userip[2];
    context->hostip[3] = userip[3];

    /* switch to tls mode ? */
#if SSL_SUPPORT
    if (mainConfig->tls_type == TLS_IMPLICIT)
      tls_auth("SSL",context);
    context->ssl.data_mode = TLS_CLEAR;
#endif

#ifdef WZD_MULTIPROCESS
    context->pid_child = getpid();
#endif
    clientThreadProc(context);
#ifdef WZD_MULTIPROCESS
    exit (0);
  } else { /* parent */
    close (newsock);
  }
#endif
}


/* IMPERATIVE STOP REQUEST - exit */
void interrupt(int signum)
{
  /* closing properly ?! */
#ifndef __CYGWIN__
fprintf(stderr,"Received signal %s\n",sys_siglist[signum]);
#else
fprintf(stderr,"Received signal %d\n",signum);
#endif
  serverMainThreadExit(0);
}

/*********************** SERVER MAIN THREAD *****************************/

void serverMainThreadProc(void *arg)
{
  int ret;
  fd_set r;
  struct timeval tv;
  int i;

/*  context_list = malloc(HARD_USERLIMIT*sizeof(wzd_context_t));*/ /* FIXME 256 */
  context_shm = wzd_shm_create(mainConfig->shm_key,HARD_USERLIMIT*sizeof(wzd_context_t),0);
  if (context_shm == NULL) {
    out_log(LEVEL_CRITICAL,"Could not get share memory with key 0x%lx - check your config file\n",mainConfig->shm_key);
    exit(1);
  }
  context_list = context_shm->datazone;
  for (i=0; i<HARD_USERLIMIT; i++) {
    context_init(context_list+i);
  }

  /* if no backend available, we must bail out - otherwise there would be no login/pass ! */
  if (mainConfig->backend.handle == NULL) {
    out_log(LEVEL_CRITICAL,"I have no backend ! I must die, otherwise you will have no login/pass !!\n");
    exit (1);
  }

  out_log(LEVEL_INFO,"Process %d ok\n",getpid());

  /* catch broken pipe ! */
#ifdef __SVR4
  sigignore(SIGPIPE);
  sigset(SIGCHLD,cleanchild);
#else
  signal(SIGPIPE,SIG_IGN);
  signal(SIGCHLD,cleanchild);
#endif

  signal(SIGINT,interrupt);
  signal(SIGTERM,interrupt);
  signal(SIGKILL,interrupt);

#ifdef POSIX /* NO, winblows is NOT posix ! */
  /* set fork() limit */
  {
    struct rlimit rlim;

    getrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = rlim.rlim_max;
    setrlim(RLIMIT_NOFILE, &rlim);

    /* no core file ! */
    getrlim(RLIMIT_CORE, &rlim);
    rlim.rlim_cur = 0;
    setrlim(RLIMIT_CORE, &rlim);
  }
#endif /* POSIX */

  ret = mainConfig->mainSocket = socket_make(&mainConfig->port,5);
  if (ret == -1) {
    out_log(LEVEL_CRITICAL,"Error creating socket %s:%d\n",
      __FILE__, __LINE__);
    serverMainThreadExit(-1);
  }

  /* sets start time, for uptime */
  time(&server_start);

  out_log(LEVEL_INFO,"%s started (build %lu)\n",WZD_VERSION_STR,WZD_BUILD_NUM);

  /* now waiting for a connection */
  out_log(LEVEL_FLOOD,"Waiting for connections (main)\n");

  mainConfig->serverstop=0;
  while (!mainConfig->serverstop) {
    FD_ZERO(&r);
    FD_SET(mainConfig->mainSocket,&r);
    tv.tv_sec = HARD_REACTION_TIME; tv.tv_usec = 0;
    ret = select(mainConfig->mainSocket+1, &r, NULL, NULL, &tv);
    
    switch (ret) {
    case -1: /* error */
      if (errno == EINTR) continue; /* retry */
      out_log(LEVEL_CRITICAL,"select failed (%s) :%s:%d\n",
        strerror(errno), __FILE__, __LINE__);
      serverMainThreadExit(-1);
      /* we abort, so we never returns */
    case 0: /* timeout */
      /* check for timeout logins */
      break;
    default: /* input */
      if (FD_ISSET(mainConfig->mainSocket,&r)) {
        login_new(mainConfig->mainSocket);
      }
    }
  } /* while (!serverstop) */


  serverMainThreadExit(0);
}

void free_config(wzd_config_t * config)
{
  wzd_ip_t * current_ip, * next_ip;

  limiter_free(mainConfig->limiter_ul);
  limiter_free(mainConfig->limiter_dl);

  current_ip = mainConfig->login_pre_ip_allowed;
  while (current_ip) {
    next_ip = current_ip->next_ip;
    free(current_ip->regexp);
    free(current_ip);
    current_ip = next_ip;
  }

  current_ip = mainConfig->login_pre_ip_denied;
  while (current_ip) {
    next_ip = current_ip->next_ip;
    free(current_ip->regexp);
    free(current_ip);
    current_ip = next_ip;
  }

  fclose(mainConfig->logfile);
  wzd_shm_free(mainConfig_shm);
}

void serverMainThreadExit(int retcode)
{
  out_log(LEVEL_INFO,"Server exiting, retcode %d\n",retcode);
	close(mainConfig->mainSocket);
#if SSL_SUPPORT
  tls_exit();
#endif
  hook_free(&mainConfig->hook);
  vfs_free(&mainConfig->vfs);
/*  free(context_list);*/
  wzd_shm_free(context_shm);
  /* free(mainConfig); */
  free_config(mainConfig);
  exit (retcode);
}
