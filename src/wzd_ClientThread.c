#include "wzd.h"

#define BUFFER_LEN	4096

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
  if (strcasecmp("ALLO",token)==0)
    return TOK_ALLO;
  if (strcasecmp("RNFR",token)==0)
    return TOK_RNFR;
  if (strcasecmp("RNTO",token)==0)
    return TOK_RNTO;
  if (strcasecmp("ABOR",token)==0)
    return TOK_ABOR;
  /* XXX FIXME TODO the following sequence can be divided into parts, and MUST be followwed by either
   * STAT or ABOR or QUIT
   * we should return TOK_PREPARE_SPECIAL_CMD or smthing like this
   * and wait the next command
   */
  if (strcasecmp("\xff\xf2",token)==0)
    return TOK_NOTHING;
  return TOK_UNKNOWN;
}

/*************** clear_read **************************/

int clear_read(int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext)
{
/*  wzd_context_t * context = (wzd_context_t*)vcontext;*/
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

int clear_write(int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext)
{
/*  wzd_context_t * context = (wzd_context_t*)vcontext;*/
  int ret;
  int save_errno;
  fd_set fds, efds;
  struct timeval tv;

  if (timeout==0)
    ret = send(sock,msg,length,0);
  else {
    while (1) {
      FD_ZERO(&fds);
      FD_ZERO(&efds);
      FD_SET(sock,&fds);
      FD_SET(sock,&efds);
      tv.tv_sec = timeout; tv.tv_usec = 0;

      ret = select(sock+1,NULL,&fds,&efds,&tv);
      save_errno = errno;

      if (FD_ISSET(sock,&efds)) {
        if (save_errno == EINTR) continue;
        out_log(LEVEL_CRITICAL,"Error during send: %s\n",strerror(save_errno));
        return -1;
      }
      if (!FD_ISSET(sock,&fds)) /* timeout */
      {
	out_log(LEVEL_CRITICAL,"Timeout during send\n");
        return 0;
      }
      break;
    }
    ret = send(sock,msg,length,0);
  } /* timeout */

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
  ret = (context->write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);

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
  ret = (context->write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);

  return 0;
}

/*************** send_message_raw ********************/

int send_message_raw(const char *msg, wzd_context_t * context)
{
  int ret;

/*#ifdef DEBUG
fprintf(stderr,"I answer: %s\n",msg);
#endif*/
  ret = (context->write_fct)(context->controlfd,msg,strlen(msg),0,HARD_XFER_TIMEOUT,context);

  return ret;
}

/*************** getmyip *****************************/

unsigned char * getmyip(int sock)
{
  static unsigned char myip[4];
  struct sockaddr_in sa;
  unsigned int size;

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

/***************** client_die ************************/

void client_die(wzd_context_t * context)
{
  int ret;

  FORALL_HOOKS(EVENT_LOGOUT)
    typedef int (*login_hook)(unsigned long, const char*);
#if BACKEND_STORAGE
    ret = (*(login_hook)hook->hook)(EVENT_LOGOUT,context->userinfo.username);
#endif
    ret = (*(login_hook)hook->hook)(EVENT_LOGOUT,mainConfig->user_list[context->userid].username);
  END_FORALL_HOOKS

#if BACKEND_STORAGE
  if (context->userinfo.flags)
    free(context->userinfo.flags);
#endif

#ifdef DEBUG
  if (context->current_limiter) {
out_err(LEVEL_HIGH,"clientThread: limiter is NOT null at exit\n");
  }
#endif

  limiter_free(context->current_limiter);
  context->magic = 0;

  out_log(LEVEL_INFO,"Client dying (socket %d)\n",context->controlfd);
  close(context->datafd);
  close(context->controlfd);
}

/*************** check_timeout ***********************/

int check_timeout(wzd_context_t * context)
{
  time_t t, delay;
  wzd_group_t group, *gptr;
  int gid;
  int i, ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0)
    user = &context->userinfo;
  else
#endif
    user = &mainConfig->user_list[context->userid];

  /* reset global ul/dl counters */
  mainConfig->global_ul_limiter.bytes_transfered = 0;
  gettimeofday(&(mainConfig->global_ul_limiter.current_time),NULL);
  mainConfig->global_dl_limiter.bytes_transfered = 0;
  gettimeofday(&(mainConfig->global_dl_limiter.current_time),NULL);
  
  /* check the timeout of control connection */
  t = time(NULL);
  delay = t - context->idle_time_start;

  /* check timeout if transfer in progress ? */
  if (context->current_action.token == TOK_STOR || context->current_action.token == TOK_RETR)
  {
    time_t data_delay;
    data_delay = t - context->idle_time_data_start;
    if (data_delay > HARD_XFER_TIMEOUT) {
      close(context->current_action.current_file);
      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->current_action.token = TOK_UNKNOWN;
      data_close(context);
      ret = send_message(426,context);
      limiter_free(context->current_limiter);
      context->current_limiter = NULL;
    }
  }

  /* if user has 'idle' flag we check nothing */
  if (user->flags && strchr(user->flags,FLAG_IDLE))
    return 0;

  /* first we check user specific timeout */
  if (user->max_idle_time>0) {
    if (delay > user->max_idle_time) {
      /* TIMEOUT ! */
      send_message_with_args(421,context,"Timeout, closing connection");
      client_die(context);
#ifdef WZD_MULTIPROCESS
      exit(0);
#else /* WZD_MULTIPROCESS */
      return 1;
#endif /* WZD_MULTIPROCESS */
    }
  }

  /* next we check for all groups */
  for (i=0; i<user->group_num; i++) {
    ret = backend_find_group(user->groups[i],&group,&gid);
    if (ret) continue;
#if BACKEND_STORAGE
    if (mainConfig->backend.backend_storage == 0)
      gptr = &group;
    else
#endif
      gptr = &mainConfig->group_list[gid];
    if (gptr->max_idle_time > 0) {
      if (delay > gptr->max_idle_time) {
        /* TIMEOUT ! */
        send_message_with_args(421,context,"Timeout, closing connection");
        client_die(context);
#ifdef WZD_MULTIPROCESS
        exit(0);
#else /* WZD_MULTIPROCESS */
        return 1;
#endif /* WZD_MULTIPROCESS */
      }
    } /* if max_idle_time*/
  }

  return 0;
}

/*************** checkpath ***************************/

char *stripdir(char * dir, char *buf, int maxlen)
{
  char * in, * out;
  char * last; 
  int ldots;
        
  in   = dir;
  out  = buf;
  last = buf + maxlen;
  ldots = 0; 
  *out  = 0;
        
  if (*in != '/') {
    if (getcwd(buf, maxlen - 2) ) {
      out = buf + strlen(buf) - 1;
      if (*out != '/') *(++out) = '/';
      out++;
    }       
    else
      return NULL;
  }               

  while (out < last) {
    *out = *in;

    if (*in == '/')
    {
      while (*(++in) == '/') ;
        in--;
    }

    if (*in == '/' || !*in)
    {
      if (ldots == 1 || ldots == 2) {
        while (ldots > 0 && --out > buf)
        {
          if (*out == '/')
            ldots--;
        }
        *(out+1) = 0;
      }
      ldots = 0;

    } else if (*in == '.') {
      ldots++;
    } else {
      ldots = 0;
    }

    out++;

    if (!*in)
      break;
                        
    in++;
  }       
        
  if (*in) {
    errno = ENOMEM;
    return NULL;
  }       
        
  while (--out != buf && (*out == '/' || !*out)) *out=0;
    return buf;
}       


int checkpath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char allowed[2048];
  char cmd[2048];
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0) {
    sprintf(allowed,"%s/",context->userinfo.rootpath);
    sprintf(cmd,"%s%s",context->userinfo.rootpath,context->currentpath);
  } else
#endif
  {
    sprintf(allowed,"%s/",mainConfig->user_list[context->userid].rootpath);
    sprintf(cmd,"%s%s",mainConfig->user_list[context->userid].rootpath,context->currentpath);
  }
  if (cmd[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      strcat(cmd,wanted_path);
    } else {
      strcpy(cmd,allowed);
      strcat(cmd,wanted_path+1);
    } 
  } 
/*#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif*/
/*  if (!realpath(cmd,path)) return 1;*/
  if (!stripdir(cmd,path,2048)) return 1;
/*#ifdef DEBUG
printf("Converted to: '%s'\n",path);
#endif*/
  if (path[strlen(path)-1] != '/')
    strcat(path,"/");
  strcpy(cmd,path);
  cmd[strlen(allowed)]='\0';
  /* check if user is allowed to even see the path */
  if (strncmp(cmd,allowed,strlen(allowed))) return 1;
  /* in the case of VFS, we need to convert here to a realpath */
  vfs_replace(mainConfig->vfs,path,2048);
  return 0;
}

/*************** do_chdir ****************************/

int do_chdir(const char * wanted_path, wzd_context_t *context)
{
  char allowed[2048],path[2048];
  struct stat buf;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  if (checkpath(wanted_path,path,context)) return 1;
  snprintf(allowed,2048,"%s/",user->rootpath);


  {
    int ret;
    int length;
    char tmppath[4096];

    strncpy(tmppath,path,4096);
    /* remove trailing / */
    length = strlen(tmppath);
    if (length>1 && tmppath[length-1]=='/')
      tmppath[length-1] = '\0';
    ret = _checkPerm(tmppath,RIGHT_CWD,user);
  
    if (ret) { /* no access */
      return 1;
    }
  }


  if (!stat(path,&buf)) {
    if (S_ISDIR(buf.st_mode)) {
      char buffer[2048], buffer2[2048];
      if (wanted_path[0] == '/') { /* absolute path */
        strcpy(buffer,wanted_path);
      } else {
        strcpy(buffer,context->currentpath);
        if (buffer[strlen(buffer)-1] != '/')
          strcat(buffer,"/");
        strcat(buffer,wanted_path);
      }
      stripdir(buffer,buffer2,2047);
/*out_err(LEVEL_INFO,"DIR: %s NEW DIR: %s\n",buffer,buffer2);*/
      strncpy(context->currentpath,buffer2,2047);
    }
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
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, &remote_host, &remote_port);
  if (sock == -1) {
    close(sock);
    send_message_with_args(501,context,"PASV timeout");
      return -1;
  }

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_init_datamode(sock, context);
#endif

  close (context->pasvsock);
  context->pasvsock = sock;

  context->datafd = sock;
  context->datamode = DATA_PASV;

  return sock;
}

/*************** waitconnect *************************/

int waitconnect(wzd_context_t * context)
{
  char str[1024];
/*  fd_set fds;
  struct timeval tv;
  unsigned int remote_port;*/
  unsigned long remote_host;
  int sock;
  int ret;

  snprintf(str,64,"%d.%d.%d.%d",
      context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
  remote_host = inet_addr(str);
  if (remote_host == (unsigned long)-1) {
    snprintf(str,1024,"Invalid ip address %d.%d.%d.%d in PORT",
	context->dataip[0],context->dataip[1], context->dataip[2], context->dataip[3]);
     ret = send_message_with_args(501,context,str);
     return -1;
  }

  ret = send_message(150,context); /* about to open data connection */
  sock = socket_connect(remote_host,context->dataport);
  if (sock == -1) {
    ret = send_message(425,context);
    return -1;
  }
  
  return sock;
#if 0
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
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, &remote_host, &remote_port);
  if (sock == -1) {
    close(sock);
    send_message_with_args(501,context,"PASV timeout");
      return -1;
  }

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_init_datamode(sock, context);
#endif

  close (context->pasvsock);
  context->pasvsock = sock;

  context->datafd = sock;
  context->datamode = DATA_PASV;

  return sock;
#endif
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
    (context->write_fct)(sock,line,strlen(line),0,HARD_XFER_TIMEOUT,context);

  return 1;
}

/*************** do_list *****************************/

int do_list(char *param, list_type_t listtype, wzd_context_t * context)
{
  char mask[1024],cmd[2048],path[2048];
  int ret,sock,n;
  char nullch[8];
  char * cmask;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

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
      while (param[n]!=' ' && param[n]!=0) {
	switch (param[n]) {
	case 'a':
	  listtype |= LIST_SHOW_HIDDEN;
	}
	n++;
      }
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

/*#ifdef DEBUG
printf("path before: '%s'\n",cmd);
#endif*/

  if (checkpath(cmd,path,context) || !strncmp(mask,"..",2)) {
    ret = send_message_with_args(501,context,"invalid filter/path");
    return 1;
  }

/*#ifdef DEBUG
printf("path: '%s'\n",path);
#endif*/

  /* CHECK PERM */
  ret = _checkPerm(path,RIGHT_LIST,user);

  if (ret) { /* no access */
    ret = send_message_with_args(550,context,"LIST","No access");
    return 1;
  }

  if (context->pasvsock <= 0) { /* PORT ! */
    sock = waitconnect(context);
    if (sock < 0) {
      return 1;
    }
#if 0
    /* IP-check needed (FXP ?!) */
    snprintf(cmd,2048,"%d.%d.%d.%d",
	    context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
    addr = inet_addr(cmd);
    if ((int)addr==-1) {
      snprintf(cmd,2048,"Invalid ip address %d.%d.%d.%d in PORT",context->dataip[0], context->dataip[1], context->dataip[2], context->dataip[3]);
      ret = send_message_with_args(501,context,cmd);
      return 1;
    }

    ret = send_message(150,context); /* about to open data connection */
    sock = socket_connect(addr,context->dataport);
    if (sock == -1) {
      ret = send_message(425,context);
      return 1;
    }
#endif
  } else { /* PASV ! */
    ret = send_message(150,context); /* about to open data connection */
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return 1;
    }
  }


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
  char cmd[2048], path[2048];
  char buffer[2048];
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  if (!param || !param[0]) return 1;
  if (strlen(param)>2047) return 1;

  if (param[0] != '/') {
    strcpy(cmd,".");
    if (checkpath(cmd,path,context)) return 1;

    strncat(path,param,2047);
  } else {
    strcpy(cmd,param);
    if (checkpath(cmd,path,context)) return 1;
    if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';
  }

  ret = checkpath(param,buffer,context);

#ifdef DEBUG
fprintf(stderr,"Making directory '%s' (%d, %s %d %d)\n",buffer,ret,strerror(errno),errno,ENOENT);
#endif

  if (buffer[strlen(buffer)-1]=='/')
    buffer[strlen(buffer)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return 1;
  }

  if (strcmp(path,buffer) != 0) {
fprintf(stderr,"strcmp(%s,%s) != 0\n",path,buffer);
    return 1;
  }

  ret = mkdir(buffer,0755); /* TODO umask ? - should have a variable here */

  if (!ret) {
    file_chown(buffer,user->username,NULL,context);
  }

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

  /* if path is / terminated, lstat will return the dir itself in case
   * of a symlink
   */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    send_message_with_args(501,context,"Go away bastard");
    return 1;
  }

  if (lstat(path,&s)) return 1;

  /* check permissions */
#if 0
#ifndef __CYGWIN__
  if (s.st_uid != context->userinfo.uid) {
    /* check if group or others permissions are ok */
    return 1;
  }
#endif
#endif /* 0 */

  /* is dir empty ? */
  {
    DIR * dir;
    struct dirent *entr;
    char path_perm[2048];

    if ((dir=opendir(path))==NULL) return 0;
    
    while ((entr=readdir(dir))!=NULL) {
      if (strcmp(entr->d_name,".")==0 ||
	  strcmp(entr->d_name,"..")==0 ||
	  strcmp(entr->d_name,HARD_PERMFILE)==0) /* XXX hide perm file ! */
	continue;
      return 1; /* dir not empty */
    }

    closedir(dir);

    /* remove permission file */
    strcpy(path_perm,path); /* path is already ended by / */
    strcat(path_perm,HARD_PERMFILE);
    unlink(path_perm);
  }

#ifdef DEBUG
fprintf(stderr,"Removing directory '%s'\n",path);
#endif

#ifndef __CYGWIN__
  if (S_ISLNK(s.st_mode))
    return unlink(path);
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
  port = mainConfig->pasv_low_range; /* use pasv range min */

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

  while (port < mainConfig->pasv_up_range) { /* use pasv range max */
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

  if (mainConfig->pasv_ip[0] == 0) {
    ret = send_message_with_args(227,context,myip[0], myip[1], myip[2], myip[3],(port>>8)&0xff, port&0xff);
  } else {
    /* do NOT send pasv_ip if used from private network */
    if (context->hostip[0]==10 ||
      (context->hostip[0] == 172 && context->hostip[1] == 16) ||
      (context->hostip[0] == 192 && context->hostip[1] == 168 && context->hostip[2] == 0) ||
      (context->hostip[0] == 127 && context->hostip[1] == 0 && context->hostip[2] == 0 && context->hostip[3] == 1))
      ret = send_message_with_args(227,context,myip[0], myip[1], myip[2], myip[3],(port>>8)&0xff, port&0xff);
    else
      ret = send_message_with_args(227,context,mainConfig->pasv_ip[0], mainConfig->pasv_ip[1],
	mainConfig->pasv_ip[2], mainConfig->pasv_ip[3],(port>>8)&0xff, port&0xff);
  }
}

/*************** do_retr *****************************/
int do_retr(char *param, wzd_context_t * context)
{
  char path[2048],cmd[2048];
  int fd;
  unsigned long bytestot, bytesnow, byteslast;
  unsigned long addr;
  int sock;
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock <= 0) && (context->dataport == 0)) {
    ret = send_message_with_args(501,context,"No data connection available - issue PORT or PASV first");
    return 1;
  }

  if (checkpath(param,path,context)) {
    ret = send_message_with_args(501,context,"Invalid file name");
    return 1;
  }

  /* trailing / ? */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1] = '\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return 1;
  }

  if ((fd=file_open(path,O_RDONLY,RIGHT_RETR,context))==0) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(501,context,"nonexistant file or permission denied");
    close(sock);
    return 1;
  }

  /* get length */
  bytestot = lseek(fd,0,SEEK_END);
  bytesnow = byteslast=context->resume;

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

    /* FIXME */
/*    sprintf(cmd, "150 Opening BINARY data connection for '%s' (%ld bytes).\r\n",
      param, bytestot);*/
    ret = send_message(150,context);
    sock = socket_connect(addr,context->dataport);
    if (sock == -1) {
      ret = send_message(425,context);
      return 1;
    }
  } else { /* PASV ! */
    /* FIXME */
/*    sprintf(cmd, "150 Opening BINARY data connection for '%s' (%ld bytes).\r\n",
      param, bytestot);*/
    ret = send_message(150,context);
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return 1;
    }
  }

  context->datafd = sock;

  lseek(fd,context->resume,SEEK_SET);

  out_log(LEVEL_FLOOD,"Download: User %s starts downloading %s (%ld bytes)\n",
    user->username,param,bytestot);

  context->current_action.token = TOK_RETR;
  strncpy(context->current_action.arg,path,4096);
  context->current_action.current_file = fd;
  context->current_action.bytesnow = 0;
  context->idle_time_data_start = context->current_action.tm_start = time(NULL);

  if (user->max_dl_speed)
    context->current_limiter = limiter_new(user->max_dl_speed);
  else
    context->current_limiter = NULL;

  return 0;
}

/*************** do_stor *****************************/
int do_stor(char *param, wzd_context_t * context)
{
  char path[2048],path2[2048],cmd[2048];
  int fd;
  unsigned long bytesnow, byteslast;
  unsigned long addr;
  int sock;
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock <= 0) && (context->dataport == 0))return 1;

  if (!param) return 1;

  /* FIXME these 2 lines forbids STOR dir/filename style - normal ? */
/* XXX if (strrchr(param,'/'))
    param = strrchr(param,'/')+1; XXX */
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

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return 1;
  }

  /* overwrite protection */
  /* TODO make permissions per-dir + per-group + per-user ? */
/*  if (context->userinfo.perms & PERM_OVERWRITE) {
    fp=file_open(path,"r",RIGHT_STOR,context),
    if (!fp) {
      fclose(fp);
      return 2;
    }*/

  if ((fd=file_open(path,O_WRONLY|O_CREAT,RIGHT_STOR,context))==0) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(501,context,"nonexistant file or permission denied");
    close(sock);
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

    /* FIXME */
/*    sprintf(cmd, "150 Opening BINARY data connection for '%s'.\r\n",
      param);*/
    ret = send_message(150,context);
    sock = socket_connect(addr,context->dataport);
    if (sock == -1) {
      ret = send_message(425,context);
      return 1;
    }
  } else { /* PASV ! */
    /* FIXME */
/*    sprintf(cmd, "150 Opening BINARY data connection for '%s'.\r\n",
      param);*/
    ret = send_message(150,context);
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return 1;
    }
  }

  context->datafd = sock;

  /* sets owner */
  file_chown (path,user->username,NULL,context);

  bytesnow = byteslast = 0;
  lseek(fd,context->resume,SEEK_SET);

  FORALL_HOOKS(EVENT_PREUPLOAD)
    typedef int (*login_hook)(unsigned long, const char*, const char *);
    ret = (*(login_hook)hook->hook)(EVENT_PREUPLOAD,user->username,path);
  END_FORALL_HOOKS

#ifdef DEBUG
fprintf(stderr,"Download: User %s starts uploading %s\n",
  user->username,param);
#endif

  context->current_action.token = TOK_STOR;
  strncpy(context->current_action.arg,path,4096);
  context->current_action.current_file = fd;
  context->current_action.bytesnow = 0;
  context->idle_time_data_start = context->current_action.tm_start = time(NULL);

  if (user->max_ul_speed)
    context->current_limiter = limiter_new(user->max_ul_speed);
  else
    context->current_limiter = NULL;

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

    /* deny retrieve to permissions file */
    if (is_perm_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return;
    }

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

  /* deny retrieve to permissions file */
    if (is_perm_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return;
    }


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
  int ret;

  if (!param || strlen(param)==0 || checkpath(param,path,context)) return 1;

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return 1;
  }

#ifdef DEBUG
fprintf(stderr,"Removing file '%s'\n",path);
#endif

  return unlink(path);
}

/*************** do_rnfr *****************************/
void do_rnfr(const char *filename, wzd_context_t * context)
{
  char path[2048];
  int ret;

  if (!filename || strlen(filename)==0 || checkpath(filename,path,context)) {
    ret = send_message_with_args(550,context,"RNFR","file does not exist");
    return;
  }

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return;
  }

  context->current_action.token = TOK_RNFR;
  strncpy(context->current_action.arg,path,4096);
  context->current_action.current_file = 0;
  context->current_action.bytesnow = 0;
  context->current_action.tm_start = time(NULL);

  ret = send_message_with_args(350,context,"OK, send RNTO");
}

/*************** do_rnto *****************************/
void do_rnto(const char *filename, wzd_context_t * context)
{
  char path[2048];
  int ret;

  if (!filename || strlen(filename)==0) {
    ret = send_message_with_args(553,context,"RNTO","wrong file name ?");
    return;
  }

  checkpath(filename,path,context);
  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return;
  }
  context->current_action.token = TOK_UNKNOWN;
  context->current_action.current_file = 0;
  context->current_action.bytesnow = 0;

  ret = file_rename(context->current_action.arg,path,context);
  if (ret) {
    ret = send_message_with_args(550,context,"RNTO","command failed");
  } else {
    ret = send_message_with_args(250,context,"RNTO","command OK");
  }
}

/*************** do_pass *****************************/

int do_pass(const char *username, const char * pass, wzd_context_t * context)
{
/*  char buffer[4096];*/
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
/*    user = &mainConfig->user_list[context->userid];*/
    user = NULL;

  ret = backend_validate_pass(username,pass,user,&context->userid);
  if (ret) {
    /* pass was not accepted */
    return 1;  /* FIXME - abort thread */
  }
  /* normalize rootpath */

/*  if (!realpath(context->userinfo.rootpath,buffer)) return 1;
  strncpy(context->userinfo.rootpath,buffer,1024);*/

  /* initial dir */
  strcpy(context->currentpath,"/");
  if (do_chdir(context->currentpath,context))
  {
    /* could not chdir to home !!!! */
    out_log(LEVEL_CRITICAL,"Could not chdir to home '%s', user '%s'\n",context->currentpath,user->username);
    return 1;
  }

  /* XXX - now we can wait (or not) the ACCT */

  return 0;
}

/*************** do_user *****************************/

int do_user(const char *username, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
/*    user = &mainConfig->user_list[context->userid];*/
    user = NULL;

  ret = backend_validate_login(username,user,&context->userid);
  
  return ret;
}

/*************** do_user_ip **************************/

int do_user_ip(const char *username, wzd_context_t * context)
{
  char ip[30];
  const unsigned char *userip = context->hostip;
  wzd_user_t * user;
  wzd_group_t *group;
  int i;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  snprintf(ip,30,"%d.%d.%d.%d",userip[0],userip[1],userip[2],userip[3]);
  if (user_ip_inlist(user,ip)==1)
    return 0;
  
  /* user ip not found, try groups */
  for (i=0; i<user->group_num; i++) {
    group = &mainConfig->group_list[user->groups[i]];
    if (group_ip_inlist(group,ip)==1)
      return 0;
  }

  return 1;
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
    ret = (context->read_fct)(context->controlfd,buffer,BUFFER_LEN,0,HARD_XFER_TIMEOUT,context);

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
	ret = send_message_with_args(421,context,"USER command issued twice");
	return 1;
      }
      token = strtok_r(NULL," \t\r\n",&ptr);
      ret = do_user(token,context);
      if (ret) { /* user was not accepted */
	ret = send_message_with_args(421,context,"User rejected");
	return 1;
      }
      /* validate ip for user */
      ret = do_user_ip(token,context);
      if (ret) { /* user was not accepted */
	ret = send_message_with_args(421,context,"IP not allowed");
	return 1;
      }
      username = strdup(token);
      ret = send_message_with_args(331,context,username);
      user_ok = 1;
      break;
    case TOK_PASS:
      if (!user_ok || pass_ok) {
	ret = send_message_with_args(421,context,"Incorrect login sequence");
	return 1;
      }
      token = strtok_r(NULL," \t\r\n",&ptr);
      ret = do_pass(username,token,context);
      if (ret) { /* pass was not accepted */
	ret = send_message_with_args(421,context,"Password rejected");
	return 1;
      }
      /* IF SSL, we should check HERE if the connection has been switched to tls or not */
#if SSL_SUPPORT
      if (mainConfig->tls_type == TLS_STRICT_EXPLICIT && !tls_ok) {
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
      ret = send_message_with_args(530,context,"Invalid login sequence");
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
  fd_set fds_r,fds_w,efds;
  wzd_context_t	 * context;
  int p1,p2;
  unsigned long i,j;
  char buffer[BUFFER_LEN];
  char * param;
  int save_errno;
  int sockfd;
  int ret;
  int exitclient;
  char *token;
  char *ptr;
  int command;
  wzd_user_t * user;

  context = arg;
  sockfd = context->controlfd;
	
  out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);

  ret = do_login(context);

  if (ret) { /* USER not logged in */
    close (sockfd);
    out_log(LEVEL_INFO,"LOGIN FAILURE Client dying (socket %d)\n",sockfd);
    return;
  }

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  /* user+pass ok */
  FORALL_HOOKS(EVENT_LOGIN)
    typedef int (*login_hook)(unsigned long, const char*);
    ret = (*(login_hook)hook->hook)(EVENT_LOGIN,user->username);
  END_FORALL_HOOKS
  ret = send_message(230,context);


  /* main loop */
  exitclient=0;
  context->idle_time_start = time(NULL);

  while (!exitclient) {
    save_errno = 666;
    memset(buffer,0,BUFFER_LEN);
    param=NULL;
    /* 1. read */
    FD_ZERO(&fds_r);
    FD_ZERO(&fds_w);
    FD_ZERO(&efds);
    /* set control fd */
    FD_SET(sockfd,&fds_r);
    FD_SET(sockfd,&efds);
    /* set data fd */
    ret = data_set_fd(context,&fds_r,&fds_w,&efds);
    if (sockfd > ret) ret = sockfd;

    tv.tv_sec=HARD_REACTION_TIME; tv.tv_usec=0L;
    ret = select(ret+1,&fds_r,&fds_w,&efds,&tv);
    save_errno = errno;

    if (ret==-1) {
     if (errno == EINTR) continue;
      else {
        out_log(LEVEL_CRITICAL,"Major error during recv: errno %d error %s\n",save_errno,strerror(save_errno));
        exitclient = 1;
      }
    }
    if (FD_ISSET(sockfd,&efds)) {
/*      if (save_errno == EINTR) continue;*/
/*      out_log(LEVEL_CRITICAL,"Major error during recv: errno %d error %s\n",save_errno,strerror(save_errno));*/
/*out_err(LEVEL_CRITICAL,"ret %d sockfd: %d %d datafd %d %d\n",ret,sockfd,FD_ISSET(sockfd,&efds),context->datafd,FD_ISSET(context->datafd,&efds));
out_err(LEVEL_CRITICAL,"read %d %d write %d %d error %d %d\n",FD_ISSET(sockfd,&fds_r),FD_ISSET(context->datafd,&fds_r),
    FD_ISSET(sockfd,&fds_w),FD_ISSET(context->datafd,&fds_w),
    FD_ISSET(sockfd,&efds),FD_ISSET(context->datafd,&efds));*/
/*      continue;*/
    }
    ret = data_check_fd(context,&fds_r,&fds_w,&efds);
    if (ret == -1) {
      /* we had an error reading data connection */
    }

    if (!FD_ISSET(sockfd,&fds_r)) {
      /* we check for data iff control is not set - control is prior */
      if (ret==1) {
        if (context->current_action.token == TOK_UNKNOWN) {
          /* we are receiving / sending data without RETR/STOR */
          continue;
        }
        /* we have data ready */
        ret = data_execute(context,&fds_r,&fds_w);
        continue;
      }
      /* nothing to read */
      /* XXX CHECK FOR TIMEOUT: control & data if needed */
      /* check timeout */
      if (check_timeout(context)) break;
      continue;
    }
    ret = (context->read_fct)(sockfd,buffer,BUFFER_LEN,0,0,context); /* timeout = 0, we know there's something to read */

	  /* remote host has closed session */
    if (ret==0 || ret==-1) {
      out_log(LEVEL_INFO,"Host disconnected improperly!\n");
      exitclient=1;
      break;
    }

    if (buffer[0]=='\0') continue;

    {
      int length = strlen(buffer);
      while (length >= 0 && (buffer[length-1]=='\r' || buffer[length-1]=='\n'))
	buffer[length-- -1] = '\0';
      strncpy(context->last_command,buffer,2048);
    }
    context->idle_time_start = time(NULL);
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
	      close(context->pasvsock);
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
	  case TOK_ALLO:
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
	      ret = send_message_with_args(550,context,param,"No such file or directory (no access ?).");
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
          {
            char buffer2[BUFFER_LEN];
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
          }
	  case TOK_RMD:
          {
            char buffer2[BUFFER_LEN];
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
          }
	  case TOK_RETR:
	    if (context->current_action.token != TOK_UNKNOWN) {
	      ret = send_message(491,context);
	      break;
	    }
	    token = strtok_r(NULL,"\r\n",&ptr);
	    do_retr(token,context);
#if 0
	    if (do_retr(token,context))
	      ret = send_message_with_args(501,context,"RETR failed");
	    else
	      ret = send_message(226,context);
#endif
	    context->resume=0;
	    break;
	  case TOK_STOR:
	    if (context->current_action.token != TOK_UNKNOWN) {
	      ret = send_message(491,context);
	      break;
	    }
	    token = strtok_r(NULL,"\r\n",&ptr);
	    ret = do_stor(token,context);
#if 0
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
#endif
	    context->resume=0;
	    break;
	  case TOK_REST:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    j=0;
	    i = sscanf(token,"%lu",&j);
	    if (i>0) {
	      char buf[256];
	      snprintf(buf,256,"Restarting at %ld. Send STORE or RETRIEVE.",j);
	      ret = send_message_with_args(350,context,buf);
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
/*	    if (context->pid_child) kill(context->pid_child,SIGTERM);
	    context->pid_child = 0;*/
	    if (context->pasvsock) {
	      close(context->pasvsock);
	      context->pasvsock=0;
	    }
	    if (context->current_action.current_file) {
              context->current_action.current_file = 0;
              context->current_action.bytesnow = 0;
              context->current_action.token = TOK_UNKNOWN;
              data_close(context);
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
	  case TOK_RNFR:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    do_rnfr(token,context);
	    break;
	  case TOK_RNTO:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    do_rnto(token,context);
	    break;
	  case TOK_NOTHING:
	    break;
	  default:
	    ret = send_message(202,context);
	    break;
	  }
	} /* while (!exitclient) */

/*	Sleep(2000);*/

      client_die(context);

#if SSL_SUPPORT
      tls_free(context);
#endif
}
