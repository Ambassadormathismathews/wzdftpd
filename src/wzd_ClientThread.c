#include "wzd.h"

#define BUFFER_LEN	4096

#define	TOK_UNKNOWN	0
#define	TOK_USER	1
#define	TOK_PASS	2
#define	TOK_AUTH	3
#define	TOK_QUIT	4
#define	TOK_TYPE	5
#define	TOK_MODE	6
#define	TOK_PORT	7
#define	TOK_PASV	8
#define	TOK_PWD		9
#define	TOK_NOOP	10
#define	TOK_SYST	11
#define	TOK_CWD		12
#define	TOK_CDUP	13
#define	TOK_LIST	14
#define	TOK_NLST	15
#define	TOK_MKD		16
#define	TOK_RMD		17

/*************** identify_token **********************/

int identify_token(const char *token)
{
  if (strcasecmp("USER",token)==0)
    return TOK_USER;
  if (strcasecmp("PASS",token)==0)
    return TOK_PASS;
  if (strcasecmp("AUTH",token)==0)
    return TOK_AUTH;
  if (strcasecmp("QUIT",token)==0)
    return TOK_QUIT;
  if (strcasecmp("TYPE",token)==0)
    return TOK_TYPE;
  if (strcasecmp("MODE",token)==0)
    return TOK_MODE;
  if (strcasecmp("PORT",token)==0)
    return TOK_PORT;
  if (strcasecmp("PASV",token)==0)
    return TOK_PASV;
  if (strcasecmp("PWD",token)==0)
    return TOK_PWD;
  if (strcasecmp("NOOP",token)==0)
    return TOK_NOOP;
  if (strcasecmp("SYST",token)==0)
    return TOK_SYST;
  if (strcasecmp("CWD",token)==0)
    return TOK_CWD;
  if (strcasecmp("CDUP",token)==0)
    return TOK_CDUP;
  if (strcasecmp("LIST",token)==0)
    return TOK_LIST;
  if (strcasecmp("NLST",token)==0)
    return TOK_NLST;
  if (strcasecmp("MKD",token)==0)
    return TOK_MKD;
  if (strcasecmp("RMD",token)==0)
    return TOK_RMD;
  return TOK_UNKNOWN;
}

/*************** send_message ************************/

int send_message(int code, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  int ret;

  snprintf(buffer,BUFFER_LEN,"%d %s\r\n",code,getMessage(code));
#ifdef DEBUG
fprintf(stderr,"I answer: %s\n",buffer);
#endif
  ret = send(context->sockfd,buffer,strlen(buffer),0);

  return ret;
}

/*************** send_message_with_args **************/

int send_message_with_args(int code, wzd_context_t * context, ...)
{
  va_list argptr;
  char buffer[BUFFER_LEN];
  char buffer2[BUFFER_LEN];
  int ret;

  va_start(argptr,context); /* note: ansi compatible version of va_start */
  vsnprintf(buffer,BUFFER_LEN,getMessage(code),argptr);
  snprintf(buffer2,BUFFER_LEN,"%d %s\r\n",code,buffer);
#ifdef DEBUG
fprintf(stderr,"I answer: %s\n",buffer2);
#endif
  ret = send(context->sockfd,buffer2,strlen(buffer2),0);

  return 0;
}

/*************** getmyip *****************************/

unsigned char * getmyip(int sock)
{
  static unsigned char myip[4];
  struct sockaddr_in sa;
  int size;

  memset(myip,0,sizeof(myip));
  if (getsockname(sock,(struct sockaddr *)&sa,&size)==0)
  {
    memcpy(myip,&sa.sin_addr,sizeof(myip));
  }

  return myip;
}

/*************** check_timeout ***********************/

void check_timeout(wzd_context_t * context)
{
  time_t t;

  /* check the timeouts of all 3 phases */
  t = time(NULL);
}

/*************** checkpath ***************************/

int checkpath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char allowed[2048];
  char cmd[2048];

  sprintf(allowed,"%s/",context->userinfo.rootpath);
  sprintf(cmd,"%s%s",context->userinfo.rootpath,context->currentpath);
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      strcat(cmd,wanted_path);
    } else {
      strcpy(cmd,allowed);
      strcat(cmd,wanted_path+1);
    }
  }
#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif
  if (!realpath(cmd,path)) return 1;
#ifdef DEBUG
printf("Converted to: '%s'\n",path);
#endif
  strcat(path,"/");
  strcpy(cmd,path);
  cmd[strlen(allowed)]='\0';
  if (strncmp(cmd,allowed,strlen(allowed))) return 1;
  return 0;
}

/*************** do_chdir ****************************/

int do_chdir(const char * wanted_path, wzd_context_t *context)
{
  char allowed[2048],path[2048];
  struct stat buf;

  if (checkpath(wanted_path,path,context)) return 1;
  snprintf(allowed,2048,"%s/",context->userinfo.rootpath);

  if (!stat(path,&buf)) {
    if (S_ISDIR(buf.st_mode))
      strncpy(context->currentpath,&path[strlen(allowed)-1],2048);
    else return 1;
  }
  else return 1;

#ifdef DEBUG
printf("current path: '%s'\n",context->currentpath);
#endif

  return 0;
}

/*************** childtimeout ************************/

void childtimeout(int nr)
{
  exit(0);
}

/*************** waitaccept **************************/

int waitaccept(wzd_context_t * context)
{
  int socksize, sock;
  struct sockaddr_in sai;

  signal(SIGALRM,childtimeout);
  alarm(HARD_REACTION_TIME);
  socksize = sizeof(struct sockaddr_in);
#ifdef DEBUG
fprintf(stderr,"Entering PASV mode for socket %d\n",context->pasvsock);
#endif
  sock = accept(context->pasvsock,(struct sockaddr *)&sai,&socksize);
#ifdef DEBUG
if (sock>0)
fprintf(stderr,"New socket accepted: %d\n",sock);
#endif
  signal(SIGALRM,SIG_IGN);
  return sock;
}

/*************** list_callback ***********************/

int list_callback(int sock, wzd_context_t * context, char *line)
{
  fd_set fds;
  struct timeval tv;

  do {
    FD_ZERO(&fds);
    FD_SET(sock,&fds);
    tv.tv_sec=HARD_XFER_TIMEOUT; tv.tv_usec=0L; /* FIXME - HARD_XFER_TIMEOUT should be a variable */

    if (select(sock+1,NULL,&fds,NULL,&tv) <= 0) {
#ifdef DEBUG
      fprintf(stderr,"LIST timeout to client.\n");
#endif
      closesocket(sock);
      send_message_with_args(501,context,"LIST timeout");
      return 0;
    }
  } while (!FD_ISSET(sock,&fds));

  send(sock,line,strlen(line),0);

  return 1;
}

/*************** do_list *****************************/

void do_list(char *param, list_type_t listtype, wzd_context_t * context)
{
  char mask[1024],cmd[2048],path[2048];
  int ret,sock;
  char nullch[8];
  char * cmask;
  unsigned long addr;
  unsigned int socksize;
  struct sockaddr_in sai;

  if (context->pasvsock <= 0 && context->dataport == 0)
  {
    ret = send_message_with_args(501,context,"No data connection available.");
    exit(0);
  }

  strcpy(nullch,".");
  mask[0] = '\0';
  if (param) {
    printf("PARAM: '%s'\n",param);

    strcpy(cmd,param);
    if (strrchr(cmd,'*') || strrchr(cmd,'?')) /* wildcards */
    {
      if (strrchr(cmd,'/')) { /* probably not in current path - need to readjust path */
	strncpy(cmd,strrchr(cmd,'/')+1,2048);
	*strrchr(cmd,'/') = '\0';
      } else { /* simple wildcard */
	strcpy(mask,cmd);
	cmd[0] = '\0';
      }
    }
    if (strrchr(cmd,'*') || strrchr(cmd,'?')) { /* wildcards in path ? ough */
      ret = send_message_with_args(501,context,"You can't put wildcards in the middle of path, only in the last part.");
      exit(0);
    }
  } else { /* no param, assume list of current dir */
    cmd[0] = '\0';
    param = nullch;
  }

  if (param[0]=='/') param++;
  if (param[0]=='/') {
    ret = send_message_with_args(501,context,"Too many / in the path - is it a joke ?");
    exit(0);
  }

  cmask = strrchr(mask,'/');
  if (cmask) {	/* search file in path (with /), but without wildcards */
    *cmask='\0';
    strcat(cmd,"/");
    strcat(cmd,mask);
    strcpy(mask,cmask);
  }

#ifdef DEBUG
printf("path before: '%s'\n",cmd);
#endif

  if (checkpath(cmd,path,context) || !strncmp(mask,"..",2)) {
    ret = send_message_with_args(501,context,"invalid filter/path");
    exit(0);
  }

#ifdef DEBUG
printf("path: '%s'\n",path);
#endif

  if (context->pasvsock <= 0) { /* PORT ! */
    /* IP-check needed (FXP ?!) */
    snprintf(cmd,2048,"%d.%d.%d.%d",
	context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
    addr = inet_addr(cmd);
    if ((int)addr==-1) {
      snprintf(cmd,2048,"Invalid ip address %d.%d.%d.%d in PORT",context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
      ret = send_message_with_args(501,context,cmd);
      exit(0);
    }

    if ((sock=socket(AF_INET,SOCK_STREAM,0)) <= 0) {
      ret = send_message_with_args(501,context,"Could not create socket");
      exit(0);
    }

    socksize = sizeof(struct sockaddr_in);
    memset(&sai,0,socksize);
    sai.sin_family = AF_INET;
    sai.sin_port = htons(context->dataport);
    memcpy(&sai.sin_addr,&addr,sizeof(addr));
    /* FIXME - timeout ? */
    if (connect(sock,(struct sockaddr *)&sai, socksize) < 0) {
      ret = send_message(425,context);
      exit(0);
    }
  } else { /* PASV ! */
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      exit(0);
    }
  }

  ret = send_message(150,context); /* about to open data connection */

  if (strlen(mask)==0) strcpy(mask,"*");

#ifdef DEBUG
printf("Finally call list: '%s', '%s'\n",path,mask);
#endif

  if (list(sock,context,listtype,path,mask,list_callback))
    ret = send_message(226,context);
  else
    ret = send_message_with_args(501,context,"Error processing list");

  ret = close(sock);

  exit(0);
}

/*************** do_mkdir ****************************/

int do_mkdir(char *param, wzd_context_t * context)
{
  char cmd[32], path[2048];
  char buffer[2048];
  int ret;

  if (!param || !param[0]) return 1;

  strcpy(cmd,".");
  if (checkpath(cmd,path,context)) return 1;

  strncat(path,param,2047);

  ret = checkpath(param,buffer,context);

#ifdef DEBUG
fprintf(stderr,"Making directory '%s' (%d)\n",buffer,ret);
#endif
  if ((!ret) || (errno != ENOENT)) return 1;
    /* CAUTION: here we invert the result, coz realpath will exit 1 if dir does not exist,
     * which in our case is normal !
     */

  return mkdir(buffer,0755); /* TODO umask ? - should have a variable here */
}

/*************** do_rmdir ****************************/

int do_rmdir(char * param, wzd_context_t * context)
{
  char path[2048];

  if (!param || !param[0]) return 1;

  if (checkpath(param,path,context)) return 1;

#ifdef DEBUG
fprintf(stderr,"Removing directory '%s'\n",path);
#endif

  return rmdir(path);
}

/*************** do_pasv *****************************/
void do_pasv(wzd_context_t * context)
{
  int ret,addr;
  unsigned int size,port;
  struct sockaddr_in sai;
  unsigned char *myip;

  /* close existing pasv connections */
  if (context->pasvsock > 0) {
    closesocket(context->pasvsock);
    context->pasvsock = 0;
  }

  /* create socket */
  if ((context->pasvsock=socket(AF_INET,SOCK_STREAM,0)) < 0) {
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  size = sizeof(struct sockaddr_in);
  port = 1025; /* FIXME use pasv range min */
  while (port < 65536) { /* FIXME use pasv range max */
    memset(&sai,0,size);

    sai.sin_family = AF_INET;
    sai.sin_port = htons(port);
    addr = INADDR_ANY;
    memcpy(&sai.sin_addr.s_addr,&addr,sizeof(int));

    if (bind(context->pasvsock,(struct sockaddr *)&sai,size)==0) break;
    port++; /* retry with next port */
  }


  if (port >= 65536) {
    closesocket(context->pasvsock);
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    closesocket(context->pasvsock);
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->sockfd); /* FIXME use a variable to get pasv ip ? */

  ret = send_message_with_args(227,context,myip[0], myip[1], myip[2], myip[3],(port>>8)&0xff, port&0xff);
}

/*************** login sequence **********************/
int seq_login(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * token;
  char * username;
  int ret;
  int command;

  /** wait the USER john **/
  ret = recv(context->sockfd,buffer,BUFFER_LEN,0);
  /* XXX strto_r: to be reentrant ! */
  token = strtok_r(buffer," \t\r\n",&ptr);
  if (identify_token(token) != TOK_USER)
  {
    out_log(LEVEL_INFO,"Invalid login sequence: '%s'\n",buffer);
    return 0;  /* FIXME - abort thread */
  }
  token = strtok_r(NULL," \t\r\n",&ptr);
  /** validation **/
  ret = (*mainConfig.backend.back_validate_login)(token,&context->userinfo);
  if (ret) {
    /* user was not accepted */
    ret = send_message(530,context);
    return 0;  /* FIXME - abort thread */
  }
  /** user ok */
  username = strdup(token);
  ret = send_message_with_args(331,context,username);
  /** wait the PASS - XXX or AUTH TLS sequence **/
  ret = recv(context->sockfd,buffer,BUFFER_LEN,0);
  token = strtok_r(buffer," \t\r\n",&ptr);
  command = identify_token(token);
  if (command == TOK_PASS) {
    ret = (*mainConfig.backend.back_validate_pass)(username,token,&context->userinfo);
    if (ret) {
      /* pass was not accepted */
      ret = send_message(530,context);
      return 0;  /* FIXME - abort thread */
    }
    /* user+pass ok */
    ret = send_message(230,context);
    /* normalize rootpath */
    if (!realpath(context->userinfo.rootpath,buffer)) return 1;
    strncpy(context->userinfo.rootpath,buffer,1024);
    /* initial dir */
    strcpy(context->currentpath,"/");
    if (do_chdir(context->currentpath,context))
    {
      /* could not chdir to home !!!! */
      out_log(LEVEL_CRITICAL,"Could not chdir to home '%', user '%s'\n",context->currentpath,context->userinfo.username);
      ret = send_message(530,context);
    }
    /* XXX - now we can wait (or not) the ACCT */
  } else {
      ret = send_message(502,context);
      return 0;  /* FIXME - goto password */
  }

  return 1;
}

/*****************************************************/
/*************** client main proc ********************/
/*****************************************************/
void clientThreadProc(void *arg)
{
  struct timeval tv;
  fd_set fds,efds;
  wzd_context_t	 * context;
  int p1,p2;
  char buffer[BUFFER_LEN];
  char buffer2[BUFFER_LEN];
  char * param;
  int save_errno;
	int sockfd;
	int ret;
	int exitclient;
	char *token;
	char *ptr;
	int command;

	context = arg;
	sockfd = context->sockfd;
	
	out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);

	/* welcome msg */
	ret = send_message(220,context);

	ret = seq_login(context);

	/* main loop */
	exitclient=0;

	while (!exitclient) {
	  save_errno = 666;
	  memset(buffer,0,BUFFER_LEN);
	  param=NULL;
          /* 1. read */
          FD_ZERO(&fds);
	  FD_ZERO(&efds);
	  FD_SET(sockfd,&fds);
	  FD_SET(sockfd,&efds);
	  tv.tv_sec=HARD_REACTION_TIME; tv.tv_usec=0L;
	  ret = select(sockfd+1,&fds,NULL,&efds,&tv);
	  save_errno = errno;
	  /* check timeout */
	  check_timeout(context);
	  if (FD_ISSET(sockfd,&efds)) {
	    if (save_errno == EINTR) continue;
	    out_log(LEVEL_CRITICAL,"Major error during recv: errno %d error %s\n",save_errno,strerror(save_errno));
	    interpret_wsa_error();
	    exit(1);
	  }
	  if (!FD_ISSET(sockfd,&fds))
	  {
	    continue;
	  }
	  ret = recv(sockfd,buffer,BUFFER_LEN,0);

	  /* remote host has closed session */
          if (ret==0) {
	    out_log(LEVEL_INFO,"Host disconnected improperly!\n");
	    exitclient=1;
	    break;
	  }

	  if (buffer[0]=='\0') continue;
printf("RAW: '%s'\n",buffer);

	  /* 2. get next token */
	  token = strtok_r(buffer," \t\r\n",&ptr);
	  command = identify_token(token);

	  switch (command) {
	  case TOK_QUIT:
	    ret = send_message(221,context);
	    exitclient=1;
	    /* check if pending xfers */
	    break;
	  case TOK_TYPE:
	    token = strtok_r(NULL," \t\r\n",&ptr);
	    if (strcasecmp(token,"I")==0)
	      context->current_xfer_type = BINARY;
	    else if (strcasecmp(token,"A")==0)
	      context->current_xfer_type = ASCII;
	    else {
	      ret = send_message(502,context);
	      break;
	    }
	    ret = send_message(200,context);
	    break;
	  case TOK_PORT:
	    if (context->pasvsock) {
	      closesocket(context->pasvsock);
	      context->pasvsock = 0;
	    }
	    /* context->resume = 0; */
	    token = strtok_r(NULL,"\r\n",&ptr);
	    if ((sscanf(token,"%d,%d,%d,%d,%d,%d",
		    &context->dataip[0],&context->dataip[1],&context->dataip[2],&context->dataip[3],
		    &p1,&p2))<6) {
	      ret = send_message(502,context);
	      break;
	    }

	    context->dataport = ((p1&0xff)<<8) | (p2&0xff);
	    ret = send_message(200,context);

	    break;
	  case TOK_PASV:
	    do_pasv(context);
	    break;
	  case TOK_PWD:
	    ret = send_message_with_args(257,context,context->currentpath,"is current directory");
	    break;
	  case TOK_NOOP:
	    ret = send_message(200,context);
	    break;
	  case TOK_SYST:
	    ret = send_message(215,context);
	    break;
	  case TOK_CDUP:
	    strcpy(buffer,"..");
	    param = buffer;
	    /* break through !!! */
	  case TOK_CWD:
	    if (!param) {
              token = strtok_r(NULL,"\r\n",&ptr);
	      param = token;
	    }
	    /* avoir error if current is "/" and action is ".." */
	    if (param && !strcmp("/",context->currentpath) && !strcmp("..",param)) {
	      ret = send_message_with_args(250,context,context->currentpath,"now current directory.");
	      break;
	    }
	    if (do_chdir(param,context)) {
	      ret = send_message_with_args(550,context,param,"No such file or directory.");
	      break;
	    }
	    ret = send_message_with_args(250,context,context->currentpath,"now current directory.");
	    break;
	  case TOK_LIST:
	    /* context->resume = 0; */
	    token = strtok_r(NULL,"\r\n",&ptr);
	    if ((context->pid_child=fork())==0)
	      do_list(token,LIST_TYPE_LONG,context);
	    break;
	  case TOK_NLST:
	    /* context->resume = 0; */
	    token = strtok_r(NULL,"\r\n",&ptr);
	    if ((context->pid_child=fork())==0)
	      do_list(token,LIST_TYPE_SHORT,context);
	    break;
	  case TOK_MKD:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    /* TODO check perms !! */
	    if (do_mkdir(token,context)) { /* CAUTION : do_mkdir handle the case token==NULL or strlen(token)==0 ! */
	      /* could not create dir */
	      snprintf(buffer2,BUFFER_LEN-1,"could not create dir '%s'",(token)?token:"(NULL)");
	      ret = send_message_with_args(553,context,buffer2);
	    } else {
	      /* success */
	      snprintf(buffer2,BUFFER_LEN-1,"\"%s\" created",token);
	      ret = send_message_with_args(257,context,buffer2,"");
	    }
	    break;
	  case TOK_RMD:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    /* TODO check perms !! */
	    if (do_rmdir(token,context)) { /* CAUTION : do_rmdir handle the case token==NULL or strlen(token)==0 ! */
	      snprintf(buffer2,BUFFER_LEN-1,"could not delete dir '%s'",(token)?token:"(NULL)");
	      ret = send_message_with_args(553,context,buffer2);
	    } else {
	      /* success */
	      snprintf(buffer2,BUFFER_LEN-1,"\"%s\" deleted",token);
	      ret = send_message_with_args(258,context,buffer2,"");
	    }
	    break;	      
	  default:
	    ret = send_message(202,context);
	    break;
	  }
	} /* while (!exitclient) */

/*	Sleep(2000);*/

	out_log(LEVEL_INFO,"Client dying (socket %d)\n",sockfd);
	close(sockfd);
}
