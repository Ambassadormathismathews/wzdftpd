#include "wzd.h"

/************ PROTOTYPES ***********/
void serverMainThreadProc(void *arg);
void serverMainThreadExit(int);

/************ VARS *****************/
int serverstop;

/* FIXME */
#define HARD_USERLIMIT	256
#define REACTION_TIME 1L

wzd_child_t *pchild[HARD_USERLIMIT];


/************ PUBLIC **************/
int runMainThread(int argc, char **argv)
{
	serverMainThreadProc(0);

	return 0;
}

/************ PRIVATE *************/
void cleanchild(int nr) {
  while (wait3(NULL, WNOHANG, NULL) > 0);
}

void serverMainThreadProc(void *arg)
{
	int userip[4];
	struct sockaddr_in sockname;
	struct sockaddr_in sa;
	int socksize;
	int optval;
	int newsock;
	int ret;
	unsigned char *p;

	out_log(LEVEL_INFO,"Thread %ld ok\n",GetCurrentThreadId());

	  /* catch broken pipe ! */
#ifdef __SVR4
	  sigignore(SIGPIPE);
	sigset(SIGCHLD,cleanchild);
#else
	signal(SIGPIPE,SIG_IGN);
	signal(SIGCHLD,cleanchild);
#endif

	/* creation */
	ret = mainConfig.mainSocket = socket(PF_INET,SOCK_STREAM,0);
	if (mainConfig.mainSocket <0) {
		out_log(LEVEL_CRITICAL,"Could not open main socket - Bailing out\n");
		serverMainThreadExit(-1);
	}

	/* reusable attribute */
	ret = setsockopt(mainConfig.mainSocket,SOL_SOCKET,SO_REUSEADDR,(const char *)&optval,sizeof(int));

	/* fill sockname struc */
	memset ((char*)&sockname,0,sizeof(struct sockaddr_in));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons((unsigned short)mainConfig.port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);

	/* bind */
	ret = bind(mainConfig.mainSocket,(const struct sockaddr*)&sockname,sizeof(struct sockaddr_in));
	if ( ret<0 ) {
		out_log(LEVEL_CRITICAL,"Could not bind main socket - Bailing out\n");
		serverMainThreadExit(-1);
	}

	/* listen */
	out_log(LEVEL_INFO,"Entering listen mode (main)\n");
	ret = listen(mainConfig.mainSocket,mainConfig.max_threads);
	if ( ret<0)
	{
		out_log(LEVEL_HIGH,"Error while listening\n");
		interpret_wsa_error();
		serverMainThreadExit(-1);
	}

	/* now the blocking call: accept */
	socksize = sizeof(sa);
	out_log(LEVEL_INFO,"Entering accept mode (main)\n");

	serverstop=0;
/* 	while (!serverstop) {*/
		newsock = accept(mainConfig.mainSocket,(struct sockaddr*)&sa,&socksize);
		if (newsock <0)
		{
			out_log(LEVEL_HIGH,"Error while accepting\n");
			interpret_wsa_error();
			serverMainThreadExit(-1);
		}

		p=(unsigned char *)&sa.sin_addr;

		userip[0]=*p++;
		userip[1]=*p++;
		userip[2]=*p++;
		userip[3]=*p++;

		out_log(LEVEL_NORMAL,"Connection opened from %d.%d.%d.%d\n",
			userip[0],userip[1],userip[2],userip[3]);

		/* start child thread */
		/* _beginthread(clientThreadProc,0,NULL); */
		clientThreadProc(&newsock);
/* 	}*/

/* 	Sleep(2000);*/

	serverMainThreadExit(0);
}

void serverMainThreadExit(int retcode)
{
	closesocket(mainConfig.mainSocket);
}