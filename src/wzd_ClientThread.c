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
#define	TOK_RETR	18
#define	TOK_STOR	19
#define	TOK_REST	20
#define	TOK_MDTM	21
#define	TOK_SIZE	22
#define	TOK_DELE	23
#define	TOK_ABOR	24

#if SSL_SUPPORT
#define	TOK_PBSZ	25
#define	TOK_PROT	26
#endif

#define	TOK_SITE	27
#define	TOK_FEAT	28

/*************** identify_token **********************/

int identify_token(const char *token)
{
/* TODO order the following by probability order */
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
  if (strcasecmp("RETR",token)==0)
    return TOK_RETR;
  if (strcasecmp("STOR",token)==0)
    return TOK_STOR;
  if (strcasecmp("REST",token)==0)
    return TOK_REST;
  if (strcasecmp("MDTM",token)==0)
    return TOK_MDTM;
  if (strcasecmp("SIZE",token)==0)
    return TOK_SIZE;
  if (strcasecmp("DELE",token)==0)
    return TOK_DELE;
  if (strcasecmp("ABOR",token)==0)
    return TOK_ABOR;
#if SSL_SUPPORT
  if (strcasecmp("PBSZ",token)==0)
    return TOK_PBSZ;
  if (strcasecmp("PROT",token)==0)
    return TOK_PROT;
#endif
  if (strcasecmp("SITE",token)==0)
    return TOK_SITE;
  if (strcasecmp("FEAT",token)==0)
    return TOK_FEAT;
  return TOK_UNKNOWN;
}

/*************** clear_read **************************/

int clear_read(int sock, char *msg, unsigned int length, int flags, int timeout, wzd_context_t * context)
{
  int ret;
  int save_errno;
  fd_set fds, efds;
  struct timeval tv;

  if (timeout==0)
    ret = recv(sock,msg,length,0);
  else {
    while (1) {
      FD_ZERO(&fds);
      FD_ZERO(&efds);
      FD_SET(sock,&fds);
      FD_SET(sock,&efds);
      tv.tv_sec = timeout; tv.tv_usec = 0;

      ret = select(sock+1,&fds,NULL,&efds,&tv);
      save_errno = errno;

      if (FD_ISSET(sock,&efds)) {
	if (save_errno == EINTR) continue;
	out_log(LEVEL_CRITICAL,"Error during recv: %s\n",strerror(save_errno));
	return -1;
      }
      if (!FD_ISSET(sock,&fds)) /* timeout */
	return 0;
      break;
    }
    ret = recv(sock,msg,length,0);
  } /* timeout */

  return ret;
}

/*************** clear_write *************************/

int clear_write(int sock, const char *msg, unsigned int length, int flags, int timeout, wzd_context_t * context)
{
  int ret;
fprintf(stderr,".");
fflush(stderr);
  ret = send(sock,msg,length,0);

  return ret;
}

/*************** send_message ************************/

int send_message(int code, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  int ret;

  format_message(code,BUFFER_LEN,buffer);
#ifdef DEBUG
fprintf(stderr,"I answer: %s\n",buffer);
#endif
  ret = (mainConfig.write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);

  return ret;
}

/*************** send_message_with_args **************/

int send_message_with_args(int code, wzd_context_t * context, ...)
{
  va_list argptr;
  char buffer[BUFFER_LEN];
  int ret;

  va_start(argptr,context); /* note: ansi compatible version of va_start */
  v_format_message(code,BUFFER_LEN,buffer,argptr);
#ifdef DEBUG
fprintf(stderr,"I answer: %s\n",buffer);
#endif
  ret = (mainConfig.write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);

  return 0;
}

/*************** getmyip *****************************/

unsigned char * getmyip(int sock)
{
  static unsigned char myip[4];
  struct sockaddr_in sa;
  int size;

  size = sizeof(struct sockaddr_in);
  memset(myip,0,sizeof(myip));
  if (getsockname(sock,(struct sockaddr *)&sa,&size)!=-1)
  {
    memcpy(myip,&sa.sin_addr,sizeof(myip));
  } else { /* failed, using localhost */
    exit (1);
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
  fd_set fds;
  struct timeval tv;
  int sock;
  unsigned long remote_host;
  unsigned int remote_port;
  int ret;

  sock = context->pasvsock;
  do {
    FD_ZERO(&fds);
    FD_SET(sock,&fds);
    tv.tv_sec=HARD_XFER_TIMEOUT; tv.tv_usec=0L; /* FIXME - HARD_XFER_TIMEOUT should be a variable */

    if (select(sock+1,&fds,NULL,NULL,&tv) <= 0) {
#ifdef DEBUG
      fprintf(stderr,"accept timeout to client %s:%d.\n",__FILE__,__LINE__);
#endif
      close(sock);
      send_message_with_args(501,context,"PASV timeout");
      return -1;
/*      exit (0);*/
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, &remote_host, &remote_port);
  if (sock == -1) {
    close(sock);
    send_message_with_args(501,context,"PASV timeout");
      return -1;
/*      exit (0);*/
  }

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_init_datamode(sock, context);
#endif

  close (context->pasvsock);
  context->pasvsock = sock;

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
      close(sock);
      send_message_with_args(501,context,"LIST timeout");
      return 0;
    }
  } while (!FD_ISSET(sock,&fds));

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_CLEAR)
    clear_write(sock,line,strlen(line),0,HARD_XFER_TIMEOUT,context);
  else
#endif
    (mainConfig.write_fct)(sock,line,strlen(line),0,HARD_XFER_TIMEOUT,context);

  return 1;
}

/*************** do_list *****************************/

int do_list(char *param, list_type_t listtype, wzd_context_t * context)
{
  char mask[1024],cmd[2048],path[2048];
  int ret,sock,n;
  char nullch[8];
  char * cmask;
  unsigned long addr;

  if (context->pasvsock <= 0 && context->dataport == 0)
  {
    ret = send_message_with_args(501,context,"No data connection available.");
    return 1;
  }

  strcpy(nullch,".");
  mask[0] = '\0';
  if (param) {
fprintf(stderr,"PARAM: '%s'\n",param);
    while (param[0]=='-') {
      n=1;
      while (param[n]!=' ' && param[n]!=0) n++;
      if (param[n]==' ') param = param+n+1;
      else param = param+n;
    }

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
    return 1;;
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
    return 1;
  }

#ifdef DEBUG
printf("path: '%s'\n",path);
#endif

  ret = backend_chek_perm(&context->userinfo,RIGHT_LIST,path); /* CHECK PERM */

  if (ret) { /* no access */
    ret = send_message_with_args(550,context,"LIST","No access");
    return 1;
  }

  if (context->pasvsock <= 0) { /* PORT ! */
    /* IP-check needed (FXP ?!) */
    snprintf(cmd,2048,"%d.%d.%d.%d",
	    context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
    addr = inet_addr(cmd);
    if ((int)addr==-1) {
      snprintf(cmd,2048,"Invalid ip address %d.%d.%d.%d in PORT",context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
      ret = send_message_with_args(501,context,cmd);
      return 1;
    }

    sock = socket_connect(addr,context->dataport);
    if (sock == -1) {
      ret = send_message(425,context);
      return 1;
    }
  } else { /* PASV ! */
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return 1;
    }
  }

  ret = send_message(150,context); /* about to open data connection */

  if (strlen(mask)==0) strcpy(mask,"*");

  if (list(sock,context,listtype,path,mask,list_callback))
    ret = send_message(226,context);
  else
    ret = send_message_with_args(501,context,"Error processing list");

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = close(sock);

  return 0;
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
fprintf(stderr,"Making directory '%s' (%d, %s %d %d)\n",buffer,ret,strerror(errno),errno,ENOENT);
#endif

  if (buffer[strlen(buffer)-1]=='/')
    buffer[strlen(buffer)-1]='\0';

  if (strcmp(path,buffer) != 0) {
fprintf(stderr,"strcmp(%s,%s) != 0\n",path,buffer);
    return 1;
  }

  ret = mkdir(buffer,0755); /* TODO umask ? - should have a variable here */

#ifndef __CYGWIN__
  if (!ret) {
    chown(buffer,context->userinfo.uid,-1);
  }
#endif

#ifdef DEBUG
fprintf(stderr,"mkdir returned %d (%s)\n",errno,strerror(errno));
#endif
  return ret;
}

/*************** do_rmdir ****************************/

int do_rmdir(char * param, wzd_context_t * context)
{
  char path[2048];
  struct stat s;

  if (!param || !param[0]) return 1;

  if (checkpath(param,path,context)) return 1;

  if (stat(path,&s)) return 1;

  /* check permissions */
#ifndef __CYGWIN__
  if (s.st_uid != context->userinfo.uid) {
    /* check if group or others permissions are ok */
    return 1;
  }
#endif

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

  size = sizeof(struct sockaddr_in);
  port = 1025; /* FIXME use pasv range min */

  /* close existing pasv connections */
  if (context->pasvsock > 0) {
    close(context->pasvsock);
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = 0;
  }

  /* create socket */
  if ((context->pasvsock=socket(AF_INET,SOCK_STREAM,0)) < 0) {
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

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
    close(context->pasvsock);
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    close(context->pasvsock);
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

  ret = send_message_with_args(227,context,myip[0], myip[1], myip[2], myip[3],(port>>8)&0xff, port&0xff);
}

/*************** do_retr *****************************/
int do_retr(char *param, wzd_context_t * context)
{
  char path[2048],cmd[2048];
  FILE *fp;
  unsigned long bytestot, bytesnow, byteslast;
  struct timeval tv;
  time_t tm_start,tm;
  int n;
  unsigned long addr;
  int sock;
  fd_set fds;
  int ret;

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock <= 0) && (context->dataport == 0))return 1;

  if (checkpath(param,path,context)) return 1;
  
  if (context->pasvsock <= 0) { /* PORT ! */
    /* IP-check needed (FXP ?!) */
    snprintf(cmd,2048,"%d.%d.%d.%d",
	    context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
    addr = inet_addr(cmd);
    if ((int)addr==-1) {
      snprintf(cmd,2048,"Invalid ip address %d.%d.%d.%d in PORT",context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
      ret = send_message_with_args(501,context,cmd);
      return 1;
    }

    sock = socket_connect(addr,context->dataport);
    if (sock == -1) {
      ret = send_message(425,context);
      return 1;
    }
  } else { /* PASV ! */
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return 1;
    }
  }

  /* trailing / ? */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1] = '\0';

  if ((fp=fopen(path,"r"))==NULL) { /* XXX allow access to files being uploaded ? */
    close(sock);
    return 1;
  }

  /* get length */
  fseek(fp,0,SEEK_END);
  bytestot = ftell(fp);
  bytesnow = byteslast=context->resume;
  /* FIXME */
/*  sprintf(cmd, "150 Opening BINARY data connection for '%s' (%ld bytes).\r\n",
    param, bytestot);*/
  ret = send_message(150,context);
  fseek(fp,context->resume,SEEK_SET);

#ifdef DEBUG
fprintf(stderr,"Download: User %s starts downloading %s (%ld bytes)\n",
  context->userinfo.username,param,bytestot);
#endif

  tm_start = time(NULL);

  while ((n=fread(cmd,1,sizeof(cmd),fp))>0) {
    do {
      FD_ZERO(&fds);
      FD_SET(sock,&fds);
      tv.tv_sec=HARD_XFER_TIMEOUT; tv.tv_usec=0L;
      if (select(sock+1,NULL,&fds,NULL,&tv)<=0) {
#ifdef DEBUG
fprintf(stderr,"Send timeout to client (user %s)\n",context->userinfo.username);
#endif
        fclose(fp);
        close(sock);
        return 1;
      }
    } while (!FD_ISSET(sock,&fds));

  ret = (mainConfig.write_fct)(sock,cmd,n,0,HARD_XFER_TIMEOUT,context); /* FIXME test ret ! */
  bytesnow += n;
  /* TODO understand !!!!! */
  if (bytesnow-byteslast > TRFMSG_INTERVAL) {
    byteslast+=TRFMSG_INTERVAL;
    tm=time(NULL);
#ifdef DEBUG
fprintf(stderr,"User %s, %ld / %ld kB (%ld %%) at %ld kB/s\n",context->userinfo.username,
    bytesnow/1024,
    bytestot/1024,
    (((bytesnow>>7)*100)/(bytestot>>7)),
    (bytesnow/(tm-tm_start))/1024
    );
#if 0
fprintf(stderr,"User %s, %ld/%ldkB (%ld%%) at %ldkB/s\n",
  context->userinfo.username,
  bytesnow/1024,bytestot/1024,
  (((bytesnow>>7)*100)/(bytestot>>7)),
  (bytesnow/(tm-tm_start))/1024);
#endif /* 0 */
#endif
    }
  } /* while fread */

  fclose(fp);
#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = close(sock);

  return 0;
}

/*************** do_stor *****************************/
int do_stor(char *param, wzd_context_t * context)
{
  char path[2048],path2[2048],cmd[2048];
  FILE *fp;
  unsigned long bytestot, bytesnow, byteslast;
  struct timeval tv;
  time_t tm_start,tm;
  int n;
  unsigned long addr;
  int sock;
  fd_set fds;
  int ret;

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock <= 0) && (context->dataport == 0))return 1;

  if (!param) return 1;

  /* FIXME these 2 lines forbids STOR dir/filename style - normal ? */
  if (strrchr(param,'/'))
    param = strrchr(param,'/')+1;
  if (strlen(param)==0) return 1;

  strcpy(cmd,".");
  if (checkpath(cmd,path,context)) return 1;
  strcat(path,param);

  /* TODO call checkpath again ? see do_mkdir */

  /* TODO understand !!! */
  /* BUGFIX */
  if ((ret=readlink(path,path2,sizeof(path2)-1)) >= 0) {
    path2[ret] = '\0';
#ifdef DEBUG
fprintf(stderr,"Link is:  %s %d ... checking\n",path2,ret);
#endif
    strcpy(path,path2);
    if (strrchr(path2,'/')) {
      *(param=strrchr(path2,'/'))='\0';
      param++;

      if (checkpath(path2,path,context)) return 1;
      if (path[strlen(path)-1] != '/') strcat(path,"/");
      strcat(path,param);
#ifdef DEBUG
fprintf(stderr,"Resolved: %s\n",path);
#endif
    }
  }
  /* END OF BUGFIX */

  /* overwrite protection */
  /* TODO make permissions per-dir + per-group + per-user ? */
/*  if (context->userinfo.perms & PERM_OVERWRITE) {
    fp=fopen(path,"r"),
    if (!fp) {
      fclose(fp);
      return 2;
    }*/
  if (context->pasvsock <= 0) { /* PORT ! */
    /* IP-check needed (FXP ?!) */
    snprintf(cmd,2048,"%d.%d.%d.%d",
	    context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
    addr = inet_addr(cmd);
    if ((int)addr==-1) {
      snprintf(cmd,2048,"Invalid ip address %d.%d.%d.%d in PORT",context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
      ret = send_message_with_args(501,context,cmd);
      return 1;
    }

    sock = socket_connect(addr,context->dataport);
    if (sock == -1) {
      ret = send_message(425,context);
      return 1;
    }
  } else { /* PASV ! */
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return 1;
    }
  }

  if ((fp=fopen(path,"w"))==NULL) { /* XXX allow access to files being uploaded ? */
    close(sock);
    return 1;
  }

#ifndef __CYGWIN__
  /* XXX - test: change owner while file is opened ?! XXX */
  chown (path,context->userinfo.uid,-1);
#endif

  bytesnow = byteslast = 0;
  /* FIXME */
/*  sprintf(cmd, "150 Opening BINARY data connection for '%s'.\r\n",
    param);*/
  ret = send_message(150,context);
  fseek(fp,context->resume,SEEK_SET);

#ifdef DEBUG
fprintf(stderr,"Download: User %s starts uploading %s\n",
  context->userinfo.username,param);
#endif

  tm_start = time(NULL);

  while (1) { /* i love while (1) and goto ;) */
    FD_ZERO(&fds);
    FD_SET(sock,&fds);
    tv.tv_sec=HARD_XFER_TIMEOUT; tv.tv_usec=0L;
    if (select(sock+1,&fds,NULL,NULL,&tv)<=0) {
#ifdef DEBUG
fprintf(stderr,"Recv timeout from client (user %s)\n",context->userinfo.username);
#endif
      fclose(fp);
      close(sock);
      return 3;
    } /* !if select */
    if (FD_ISSET(sock,&fds)) {
/*      n = recv(sock,cmd,sizeof(cmd),0); */
      n = (mainConfig.read_fct)(sock,cmd,sizeof(cmd),0,HARD_XFER_TIMEOUT,context);
        /* FIXME test ret ! */
      /* FIXME rewrite following test */
      if (n<=0) break; /* user closed conn, file complete ? should be ! */
      fwrite(cmd,1,n,fp);
      bytesnow += n;
      /* TODO understand !!!!! */
      if (bytesnow-byteslast > TRFMSG_INTERVAL) {
        byteslast+=TRFMSG_INTERVAL;
        tm=time(NULL);
#ifdef DEBUG
fprintf(stdout,"User %s, %ld/%ldkB (%ld%%) at %ldkB/s\n",
  context->userinfo.username,
  bytesnow/1024,bytestot/1024,
  (((bytesnow>>7)*100)/(bytestot>>7)),
  (bytesnow/(tm-tm_start))/1024);
#endif
      }
    } /* !if FD_ISSET */
  } /* !while (1) */

  fclose(fp);
#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = close(sock);

#ifdef DEBUG
fprintf(stderr,"Uploading %s finished\n",param);
#endif

  return 0;
}

/*************** do_mdtm *****************************/
void do_mdtm(char *param, wzd_context_t * context)
{
  char path[2048], tm[32];
  struct stat s;
  int ret;

  if (!checkpath(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

    if (stat(path,&s)==0) {
      strftime(tm,sizeof(tm),"%Y%m%d%H%M%S",gmtime(&s.st_mtime));
      ret = send_message_with_args(213,context,tm);
      return;
    }
  }
  ret = send_message_with_args(501,context,"File inexistant or no access ?");
}

/*************** do_size *****************************/
void do_size(char *param, wzd_context_t * context)
{
  char path[2048];
  char buffer[1024];
  struct stat s;
  int ret;

  if (!checkpath(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

    if (stat(path,&s)==0) {
      snprintf(buffer,1024,"%ld",(long int)s.st_size);
      ret = send_message_with_args(213,context,buffer);
      return;
    }
  }
  ret = send_message_with_args(501,context,"File inexistant or no access ?");
}

/*************** do_dele *****************************/
int do_dele(char *param, wzd_context_t * context)
{
  char path[2048];

  if (!param || strlen(param)==0 || checkpath(param,path,context)) return 1;

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

#ifdef DEBUG
fprintf(stderr,"Removing file '%s'\n",path);
#endif

  return unlink(path);
}

/*************** do_pass *****************************/

int do_pass(const char *username, const char * pass, wzd_context_t * context)
{
  char buffer[4096];
  int ret;

  ret = (*mainConfig.backend.back_validate_pass)(username,pass,&context->userinfo);
  if (ret) {
    /* pass was not accepted */
    return 1;  /* FIXME - abort thread */
  }
  /* normalize rootpath */
  if (!realpath(context->userinfo.rootpath,buffer)) return 1;
  strncpy(context->userinfo.rootpath,buffer,1024);
  /* initial dir */
  strcpy(context->currentpath,"/");
  if (do_chdir(context->currentpath,context))
  {
    /* could not chdir to home !!!! */
    out_log(LEVEL_CRITICAL,"Could not chdir to home '%', user '%s'\n",context->currentpath,context->userinfo.username);
    return 1;
  }

  /* XXX - now we can wait (or not) the ACCT */

  return 0;
}

/*************** do_user *****************************/

int do_user(const char *username, wzd_context_t * context)
{
  int ret;

  ret = (*mainConfig.backend.back_validate_login)(username,&context->userinfo);
  
  return ret;
}

/*************** do_login_loop ***********************/

int do_login_loop(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * token;
  char * username;
  int ret;
  int user_ok=0, pass_ok=0;
#if SSL_SUPPORT
  int tls_ok=0;
#endif
  int command;

  while (1) {
    /** wait response **/
    ret = (mainConfig.read_fct)(context->controlfd,buffer,BUFFER_LEN,0,HARD_XFER_TIMEOUT,context);

    if (ret == 0) {
fprintf(stderr,"Connection closed or timeout\n");
      return 1;
    }
    if (ret==-1) {
fprintf(stderr,"Error reading client response\n");
      return 1;
    }

#ifdef DEBUG
fprintf(stderr,"RAW: '%s'\n",buffer);
#endif

    /* XXX strtok_r: to be reentrant ! */
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    switch (command) {
    case TOK_USER:
      if (user_ok) { /* USER command issued 2 times */
	ret = send_message(530,context);
	return 1;
      }
      token = strtok_r(NULL," \t\r\n",&ptr);
      ret = do_user(token,context);
      if (ret) { /* user was not accepted */
	ret = send_message(530,context);
	return 1;
      }
      username = strdup(token);
      ret = send_message_with_args(331,context,username);
      user_ok = 1;
      break;
    case TOK_PASS:
      if (!user_ok || pass_ok) {
	ret = send_message(530,context);
	return 1;
      }
      token = strtok_r(NULL," \t\r\n",&ptr);
      ret = do_pass(username,token,context);
      if (ret) { /* pass was not accepted */
	ret = send_message(530,context);
	return 1;
      }
      /* IF SSL, we should check HERE if the connection has been switched to tls or not */
#if SSL_SUPPORT
      if (mainConfig.tls_type == TLS_STRICT_EXPLICIT && !tls_ok) {
	ret = send_message_with_args(421,context,"TLS session MUST be engaged");
	return 1;
      }
#endif
      return 0; /* user + pass ok */
      break;
#if SSL_SUPPORT
    case TOK_AUTH:
      token = strtok_r(NULL,"\r\n",&ptr);
      ret = tls_auth(token,context);
      if (ret) { /* couldn't switch to ssl */
	/* XXX should we send a message ? - with ssl aborted we can't be sure there won't be problems */
	ret = send_message_with_args(421,context,"Failed TLS negotiation, exiting");
	return 1;
      }
      tls_ok = 1;
      break;
    case TOK_PBSZ:
      token = strtok_r(NULL,"\r\n",&ptr);
      /* TODO convert token to int, set the PBSZ size */
      ret = send_message_with_args(200,context,"Command okay");
      break;
    case TOK_PROT:
      /* TODO if user is NOT in TLS mode, insult him */
      token = strtok_r(NULL,"\r\n",&ptr);
      if (strcasecmp("P",token)==0)
        context->ssl.data_mode = TLS_PRIV;
      else if (strcasecmp("C",token)==0)
        context->ssl.data_mode = TLS_CLEAR;
      else {
        ret = send_message_with_args(550,context,"PROT","must be C or P");
        break;
      }
      ret = send_message_with_args(200,context,"PROT command OK");
      break;
#endif
    default:
      out_log(LEVEL_INFO,"Invalid login sequence: '%s'\n",buffer);
      ret = send_message(530,context);
      return 1;
    } /* switch (command) */

  } /* while (1) */

  return ret;
}

/*************** login sequence **********************/
int do_login(wzd_context_t * context)
{
  int ret;

  /* welcome msg */
  ret = send_message(220,context);

  /* mini server loop, login */
  ret = do_login_loop(context);

  return ret;
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
  unsigned long i,j;
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
	sockfd = context->controlfd;
	
	out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);

	ret = do_login(context);

	if (ret) { /* USER not logged in */
	  close (sockfd);
	  out_log(LEVEL_INFO,"LOGIN FAILURE Client dying (socket %d)\n",sockfd);
	  return;
	}

        /* user+pass ok */
        ret = send_message(230,context);


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
	    exit(1);
	  }
	  if (!FD_ISSET(sockfd,&fds))
	  {	  
	    continue;
	  }
/*	  ret = recv(sockfd,buffer,BUFFER_LEN,0);*/
	  ret = (mainConfig.read_fct)(sockfd,buffer,BUFFER_LEN,0,0,context); /* timeout = 0, we know there's something to read */

	  /* remote host has closed session */
    if (ret==0) {
	    out_log(LEVEL_INFO,"Host disconnected improperly!\n");
	    exitclient=1;
	    break;
	  }

	  if (buffer[0]=='\0') continue;
#ifdef DEBUG
fprintf(stderr,"RAW: '%s'\n",buffer);
#endif

	  /* 2. get next token */
	  ptr = &buffer[0];
	  token = strtok_r(buffer," \t\r\n",&ptr);
	  command = identify_token(token);

    context->state = command;

	  switch (command) {
	  case TOK_QUIT:
	    ret = send_message(221,context);
	    exitclient=1;
	    /* check if pending xfers */
	    break;
	  case TOK_TYPE:
	    context->resume = 0;
	    token = strtok_r(NULL," \t\r\n",&ptr);
	    if (strcasecmp(token,"I")==0)
	      context->current_xfer_type = BINARY;
	    else if (strcasecmp(token,"A")==0)
	      context->current_xfer_type = ASCII;
	    else {
	      ret = send_message(502,context);
	      break;
	    }
            ret = send_message_with_args(200,context,"Command okay");
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
            ret = send_message_with_args(200,context,"Command okay");

	    break;
	  case TOK_PASV:
	    do_pasv(context);
	    break;
	  case TOK_PWD:
	    context->resume = 0;
	    ret = send_message_with_args(257,context,context->currentpath,"is current directory");
	    break;
	  case TOK_NOOP:
            ret = send_message_with_args(200,context,"Command okay");
	    break;
	  case TOK_SYST:
	    context->resume = 0;
	    ret = send_message(215,context);
	    break;
	  case TOK_CDUP:
	    strcpy(buffer,"..");
	    param = buffer;
	    /* break through !!! */
	  case TOK_CWD:
	    context->resume = 0;
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
	    context->resume = 0;
/*	    if (context->pid_child) {
	      ret = send_message(491,context);
	      break;
	    }*/
	    token = strtok_r(NULL,"\r\n",&ptr);
/*	    if ((context->pid_child=fork())==0)*/
	      do_list(token,LIST_TYPE_LONG,context);
	    break;
	  case TOK_NLST:
	    context->resume = 0;
/*	    if (context->pid_child) {
	      ret = send_message(491,context);
	      break;
	    }*/
	    token = strtok_r(NULL,"\r\n",&ptr);	    
/*	    if ((context->pid_child=fork())==0)*/
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
	  case TOK_RETR:
/*	    if (context->pid_child) {
	      ret = send_message(491,context);
	      break;
	    }*/
	    token = strtok_r(NULL,"\r\n",&ptr);
/*	    if ((context->pid_child=fork())==0) {*/
	      if (do_retr(token,context))
	        ret = send_message_with_args(501,context,"RETR failed");
	      else
	        ret = send_message(226,context);
/*	      exit(0);
	    }*/
	    context->resume=0;
	    break;
	  case TOK_STOR:
/*	    if (context->pid_child) {
	      ret = send_message(491,context);
	      break;
	    }*/
	    token = strtok_r(NULL,"\r\n",&ptr);
/*	    if ((context->pid_child=fork())==0) {*/
	      switch (do_stor(token,context)) {
	      case 1:
	        ret = send_message_with_args(501,context,"STOR failed");
	        break;
	      case 2:
	        ret = send_message_with_args(553,context,"You can't overwrite !\n");
	        break;
	      case 3:
	        ret = send_message(451,context);
	        break;
	      default:
	        ret = send_message(226,context);
	        out_log(LEVEL_INFO,"STOR: %s sent %s\n",
	          context->userinfo.username, param);
	        break;
	      }
/*	      exit(0);
	    }*/
	    context->resume=0;
	    break;
	  case TOK_REST:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    j=0;
	    i = sscanf(token,"%ld",&j);
	    if (i>0 && j>=0) {
	      ret = send_message_with_args(350,context,j);
	      context->resume = j;
	    } else {
	      ret = send_message_with_args(501,context,"Invalid REST marker");
	    }
	    break;
	  case TOK_MDTM:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    context->resume = 0L;
	    do_mdtm(token,context);
	    break;
	  case TOK_SIZE:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    context->resume=0;
	    do_size(token,context);
	    break;
	  case TOK_DELE:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    if (!do_dele(token,context))
	      ret = send_message_with_args(250,context,"DELE","command successfull");
	    else
	      ret = send_message_with_args(501,context,"DELE failed");
	    break;
	  case TOK_ABOR:
	    if (context->pid_child) kill(context->pid_child,SIGTERM);
	    context->pid_child = 0;
	    if (context->pasvsock) {
	      close(context->pasvsock);
	      context->pasvsock=0;
	    }
	    ret = send_message(226,context);
	    break;
#if SSL_SUPPORT
	  case TOK_PROT:
	    /* TODO if user is NOT in TLS mode, insult him */
	    token = strtok_r(NULL,"\r\n",&ptr);
	    if (strcasecmp("P",token)==0)
	      context->ssl.data_mode = TLS_PRIV;
	    else if (strcasecmp("C",token)==0)
	      context->ssl.data_mode = TLS_CLEAR;
	    else {
	      ret = send_message_with_args(550,context,"PROT","must be C or P");
	      break;
	    }
	    ret = send_message_with_args(200,context,"PROT command OK");
	    break;
#endif
	  case TOK_SITE:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    do_site(token,context); /* do_site send message ! */
	    break;
	  case TOK_FEAT:
#if SSL_SUPPORT
	    ret = send_message_with_args(211,context,"AUTH TLS\n PBSZ\n PROT\n MDTM\n SIZE\n SITE\n REST");
#else
	    ret = send_message_with_args(211,context,"MDTM\n SIZE\n SITE\n REST");
#endif
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
