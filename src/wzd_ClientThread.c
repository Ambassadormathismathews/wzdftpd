/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#if defined __CYGWIN__ && defined WINSOCK_SUPPORT
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h> /* gethostbyaddr */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_data.h"
#include "wzd_messages.h"
#include "wzd_vfs.h"
#include "wzd_file.h"
#include "wzd_ratio.h"
#include "wzd_section.h"
#include "wzd_site.h"
#include "wzd_socket.h"
#include "wzd_tls.h"
#include "ls.h"
#include "wzd_ClientThread.h"


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
  if (strcasecmp("APPE",token)==0)
    return TOK_APPE;
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
#ifdef SSL_SUPPORT
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

#if defined __CYGWIN__ && defined WINSOCK_SUPPORT
      ret = select(0,&fds,NULL,&efds,&tv);
#else
      ret = select(sock+1,&fds,NULL,&efds,&tv);
#endif
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

#if defined __CYGWIN__ && defined WINSOCK_SUPPORT
      ret = select(0,NULL,&fds,&efds,&tv);
#else
      ret = select(sock+1,NULL,&fds,&efds,&tv);
#endif
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
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_LOGOUT,context->userinfo.username);
#endif
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_LOGOUT,GetUserByID(context->userid)->username);
  END_FORALL_HOOKS

#if BACKEND_STORAGE
  if (context->userinfo.flags)
    free(context->userinfo.flags);
#endif

#ifdef DEBUG
/*  if (context->current_limiter) {
out_err(LEVEL_HIGH,"clientThread: limiter is NOT null at exit\n");
  }*/
#endif

/*  limiter_free(context->current_limiter);*/
  context->magic = 0;

  out_log(LEVEL_INFO,"Client dying (socket %d)\n",context->controlfd);
  socket_close(context->datafd);
  socket_close(context->controlfd);
}

/*************** check_timeout ***********************/

int check_timeout(wzd_context_t * context)
{
  time_t t, delay;
  wzd_group_t *gptr;
  int i, ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0)
    user = &context->userinfo;
  else
#endif
    user = GetUserByID(context->userid);

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
      /* send events here allow sfv checker to mark file as bad if
       * partially uploaded
       */
      FORALL_HOOKS(EVENT_POSTUPLOAD)
	typedef int (*upload_hook)(unsigned long, const char*, const char *);
	ret = (*(upload_hook)hook->hook)(EVENT_POSTUPLOAD,user->username,context->current_action.arg);
      END_FORALL_HOOKS
      close(context->current_action.current_file);
      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->current_action.token = TOK_UNKNOWN;
      data_close(context);
      ret = send_message(426,context);
/*      limiter_free(context->current_limiter);
      context->current_limiter = NULL;*/
    }
    /* during a xfer, connection timeouts are not checked */
    return 0;
  }

  /* if user has 'idle' flag we check nothing */
  if (user->flags && strchr(user->flags,FLAG_IDLE))
    return 0;

  /* first we check user specific timeout */
  if (user->max_idle_time>0) {
    if (delay > user->max_idle_time) {
      /* TIMEOUT ! */
      send_message_with_args(421,context,"Timeout, closing connection");
      {
	const char * groupname = NULL;
	const char * userip = context->hostip;
	const char * remote_host;
	struct hostent *h;
	h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),AF_INET);
	if (h==NULL)
	  remote_host = inet_ntoa( *((struct in_addr*)context->hostip) );
	else
	  remote_host = h->h_name;
	if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
	log_message("TIMEOUT","%s (%u.%u.%u.%u) timed out after being idle %d seconds",
	    user->username,
	    userip[0],userip[1],userip[2],userip[3],
	    delay
	    );
      }
      client_die(context);
#ifdef WZD_MULTIPROCESS
      exit(0);
#else /* WZD_MULTIPROCESS */
      return 0;
#endif /* WZD_MULTIPROCESS */
    }
  }

  /* next we check for all groups */
  for (i=0; i<user->group_num; i++) {
    gptr = GetGroupByID(user->groups[i]);
    if (gptr->max_idle_time > 0) {
      if (delay > gptr->max_idle_time) {
        /* TIMEOUT ! */
        send_message_with_args(421,context,"Timeout, closing connection");
	{
	  const char * groupname = NULL;
	  const char * userip = context->hostip;
	  const char * remote_host;
	  struct hostent *h;
	  h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),AF_INET);
	  if (h==NULL)
	    remote_host = inet_ntoa( *((struct in_addr*)context->hostip) );
	  else
	    remote_host = h->h_name;
	  if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
	  log_message("TIMEOUT","%s (%u.%u.%u.%u) timed out after being idle %d seconds",
	      user->username,
	      userip[0],userip[1],userip[2],userip[3],
	      delay
	      );
	}
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
    user = GetUserByID(context->userid);

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
out_err(LEVEL_INFO,"current path: '%s'\n",context->currentpath);
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
      out_err(LEVEL_FLOOD,"accept timeout to client %s:%d.\n",__FILE__,__LINE__);
      socket_close(sock);
      send_message_with_args(501,context,"PASV timeout");
      return -1;
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, &remote_host, &remote_port);
  if (sock == -1) {
    socket_close(sock);
    send_message_with_args(501,context,"PASV timeout");
      return -1;
  }

#ifdef SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_init_datamode(sock, context);
#endif

  socket_close (context->pasvsock);
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
  sock = socket_connect(remote_host,context->dataport,mainConfig->port-1,context->controlfd);
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
      socket_close(sock);
      send_message_with_args(501,context,"PASV timeout");
      return -1;
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, &remote_host, &remote_port);
  if (sock == -1) {
    socket_close(sock);
    send_message_with_args(501,context,"PASV timeout");
      return -1;
  }

#ifdef SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_init_datamode(sock, context);
#endif

  socket_close (context->pasvsock);
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
      out_err(LEVEL_FLOOD,"LIST timeout to client.\n");
      socket_close(sock);
      send_message_with_args(501,context,"LIST timeout");
      return 0;
    }
  } while (!FD_ISSET(sock,&fds));

#ifdef SSL_SUPPORT
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
    user = GetUserByID(context->userid);

  if (context->pasvsock <= 0 && context->dataport == 0)
  {
    ret = send_message_with_args(501,context,"No data connection available.");
    return 1;
  }

  strcpy(nullch,".");
  mask[0] = '\0';
  if (param) {
  out_err(LEVEL_FLOOD,"PARAM: '%s'\n",param);
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
    if (cmd[strlen(cmd)-1]=='/') cmd[strlen(cmd)-1]='\0';

    if (strrchr(cmd,'*') || strrchr(cmd,'?')) /* wildcards */
    {
      char *ptr;
      if (strrchr(cmd,'/')) { /* probably not in current path - need to readjust path */
	if (strrchr(cmd,'/') > strrchr(cmd,'*')) {
	  /* char / is AFTER *, dir style: toto / * / .., we refuse */
          ret = send_message_with_args(501,context,"You can't put wildcards in the middle of path, only in the last part.");
          return 1;
	}
	ptr = strrchr(cmd,'/');
	strncpy(cmd,ptr+1,2048);
	*ptr = '\0';
//	strncpy(cmd,strrchr(cmd,'/')+1,2048);
//	*strrchr(cmd,'/') = '\0';
      } else { /* simple wildcard */
	strcpy(mask,cmd);
	cmd[0] = '\0';
      }
    }
    if (strrchr(cmd,'*') || strrchr(cmd,'?')) { /* wildcards in path ? ough */
      ret = send_message_with_args(501,context,"You can't put wildcards in the middle of path, only in the last part.");
      return 1;
    }
  } else { /* no param, assume list of current dir */
    cmd[0] = '\0';
    param = nullch;
  }

  if (param[0]=='/') param++;
  if (param[0]=='/') {
    ret = send_message_with_args(501,context,"Too many / in the path - is it a joke ?");
    return 1;
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
  {
    ret = send_message(-226,context); /* - means ftp reply will continue */
    write_message_footer(226,context);
  }
  else
    ret = send_message_with_args(501,context,"Error processing list");

#ifdef SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = socket_close(sock);

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
    user = GetUserByID(context->userid);

  if (!param || !param[0]) return 1;
  if (strlen(param)>2047) return 1;
  if (strcmp(param,"/")==0) return 0;

  if (param[0] != '/') {
    strcpy(cmd,".");
    if (checkpath(cmd,path,context)) return 1;
    if (path[strlen(path)-1]!='/') strcat(path,"/");
    strncat(path,param,2047);
  } else {
    strcpy(cmd,param);
    if (checkpath(cmd,path,context)) return 1;
    if (path[strlen(path)-1]!='/') strcat(path,"/");
/*    if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';*/
  }
  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  ret = checkpath(param,buffer,context);

  out_err(LEVEL_FLOOD,"Making directory '%s' (%d, %s %d %d)\n",buffer,ret,strerror(errno),errno,ENOENT);

  if (buffer[strlen(buffer)-1]=='/')
    buffer[strlen(buffer)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_perm_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return 1;
  }

  if (strcmp(path,buffer) != 0) {
    out_err(LEVEL_FLOOD,"strcmp(%s,%s) != 0\n",path,buffer);
    return 1;
  }

  /* TODO XXX FIXME check section path-filter */
  {
    char *ptr;
    wzd_section_t * section;
    strcpy(path,buffer);
    ptr = strrchr(path,'/');
    if (ptr) {
      *ptr='\0';
      out_err(LEVEL_HIGH,"searching path %s\n",path);
      section = section_find(mainConfig->section_list,path);
      if (section) {
	out_err(LEVEL_HIGH,"Found matching section\n");
      }
    }
  }

  ret = file_mkdir(buffer,0755,context); /* TODO umask ? - should have a variable here */

  if (!ret) {
    const char *groupname=NULL;
    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }
    file_chown(buffer,user->username,groupname,context);

    strcpy(buffer,context->currentpath);
    strcat(buffer,"/");
    strcat(buffer,param);
    stripdir(buffer,path,2047);
    
    log_message("NEWDIR","\"%s\" \"%s\" \"%s\" \"%s\"",
	path, /* ftp-absolute path */
	user->username,
	(groupname)?groupname:"No Group",
	user->tagline
	);
	
  }

  out_err(LEVEL_FLOOD,"mkdir returned %d (%s)\n",errno,strerror(errno));

  return ret;
}

/*************** do_rmdir ****************************/

int do_rmdir(char * param, wzd_context_t * context)
{
  char path[2048];
  struct stat s;
  int ret;

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
  ret = file_rmdir(path,context);

  if (!ret) {
    const char *groupname=NULL;
    wzd_user_t * user;
    char buffer[2048], path[2048];

#if BACKEND_STORAGE
    if (mainConfig->backend.backend_storage==0) {
      user = &context->userinfo;
    } else
#endif
      user = GetUserByID(context->userid);

    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }

    strcpy(buffer,context->currentpath);
    strcat(buffer,"/");
    strcat(buffer,param);
    stripdir(buffer,path,2047);
    
    log_message("DELDIR","\"%s\" \"%s\" \"%s\" \"%s\"",
	path, /* ftp-absolute path */
	user->username,
	(groupname)?groupname:"No Group",
	user->tagline
	);
	
  }

  return ret;
}

/*************** do_pasv *****************************/
void do_pasv(wzd_context_t * context)
{
  int ret;
  unsigned long addr;
  unsigned int size,port;
  struct sockaddr_in sai;
  unsigned char *myip;
  unsigned char pasv_bind_ip[4];

  size = sizeof(struct sockaddr_in);
  port = mainConfig->pasv_low_range; /* use pasv range min */

  /* close existing pasv connections */
  if (context->pasvsock > 0) {
    socket_close(context->pasvsock);
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = 0;
  }

  /* create socket */
  if ((context->pasvsock=socket(AF_INET,SOCK_STREAM,0)) < 0) {
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

  if (mainConfig->pasv_ip[0] == 0) {
    memcpy(pasv_bind_ip,myip,4);
  } else {
    /* do NOT send pasv_ip if used from private network */
    if (context->hostip[0]==10 ||
      (context->hostip[0] == 172 && context->hostip[1] == 16) ||
      (context->hostip[0] == 192 && context->hostip[1] == 168 && context->hostip[2] == 0) ||
      (context->hostip[0] == 127 && context->hostip[1] == 0 && context->hostip[2] == 0 && context->hostip[3] == 1))
      memcpy(pasv_bind_ip,myip,4);
    else
      memcpy(pasv_bind_ip,mainConfig->pasv_ip,4);
  }
/*  out_err(LEVEL_CRITICAL,"PASV_IP: %d.%d.%d.%d\n",
      pasv_bind_ip[0], pasv_bind_ip[1], pasv_bind_ip[2], pasv_bind_ip[3]);*/

  while (port < mainConfig->pasv_high_range) { /* use pasv range max */
    memset(&sai,0,size);

    sai.sin_family = AF_INET;
    sai.sin_port = htons(port);
    /* XXX TODO FIXME bind to specific address works, but not for NAT */
    /* XXX TODO FIXME always bind to 'myip' ?! */
    addr = INADDR_ANY;
/*    memcpy( (void*)&addr, pasv_bind_ip, sizeof(unsigned long));*/
    
    memcpy(&sai.sin_addr.s_addr,&addr,sizeof(unsigned long));

    if (bind(context->pasvsock,(struct sockaddr *)&sai,size)==0) break;
    port++; /* retry with next port */
  }


  if (port >= 65536) {
    socket_close(context->pasvsock);
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    socket_close(context->pasvsock);
    context->pasvsock = 0;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

  ret = send_message_with_args(227,context,pasv_bind_ip[0], pasv_bind_ip[1], pasv_bind_ip[2], pasv_bind_ip[3],(port>>8)&0xff, port&0xff);
  
#if 0
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
#endif
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
    user = GetUserByID(context->userid);

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

  /* check user ratio */
  if (ratio_check_download(path,context)) {
    ret = send_message_with_args(501,context,"Insufficient credits - Upload first");
    return 0;
  }

  if ((fd=file_open(path,O_RDONLY,RIGHT_RETR,context))==-1) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(501,context,"nonexistant file or permission denied");
/*    socket_close(sock);*/
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
    sock = socket_connect(addr,context->dataport,mainConfig->port,context->controlfd);
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

/*  if (user->max_dl_speed)
    context->current_limiter = limiter_new(user->max_dl_speed);
  else
    context->current_limiter = NULL;*/

/*  if (user->max_dl_speed)
  {*/
    context->current_dl_limiter.maxspeed = user->max_dl_speed;
    context->current_dl_limiter.bytes_transfered = 0;
    gettimeofday(&context->current_dl_limiter.current_time,NULL);
/*  }
  else
    context->current_dl_limiter.maxspeed = 0;*/

  /* we increment the counter of downloaded files at the beggining
   * of the download
   */
  user->files_dl_total++;
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
    user = GetUserByID(context->userid);

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock <= 0) && (context->dataport == 0)) {
    ret = send_message_with_args(503,context,"Issue PORT or PASV First");
    return 1;
  }

  if (!param || strlen(param)==0) {
    ret = send_message_with_args(501,context,"Incorrect filename");
    return 1;
  }

  /* FIXME these 2 lines forbids STOR dir/filename style - normal ? */
/* XXX if (strrchr(param,'/'))
    param = strrchr(param,'/')+1; XXX */

  strcpy(cmd,".");
  if (checkpath(cmd,path,context)) {
    ret = send_message_with_args(501,context,"Incorrect filename");
    return 1;
  }
  if (path[strlen(path)-1] != '/') strcat(path,"/");
  strcat(path,param);

  /* TODO call checkpath again ? see do_mkdir */

  /* TODO understand !!! */
  /* BUGFIX */
  if ((ret=readlink(path,path2,sizeof(path2)-1)) >= 0) {
    path2[ret] = '\0';
    out_err(LEVEL_FLOOD,"Link is:  %s %d ... checking\n",path2,ret);
    strcpy(path,path2);
    if (strrchr(path2,'/')) {
      *(param=strrchr(path2,'/'))='\0';
      param++;

      if (checkpath(path2,path,context)) return 1;
      if (path[strlen(path)-1] != '/') strcat(path,"/");
      strcat(path,param);
      out_err(LEVEL_FLOOD,"Resolved: %s\n",path);
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

  if ((fd=file_open(path,O_WRONLY|O_CREAT,RIGHT_STOR,context))==-1) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(501,context,"nonexistant file or permission denied");
/*    socket_close(sock);*/
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
    sock = socket_connect(addr,context->dataport,mainConfig->port,context->controlfd);
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
  {
    const char *groupname=NULL;
    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }
    file_chown (path,user->username,groupname,context);
  }

  bytesnow = byteslast = 0;
  if (context->resume == (unsigned long)-1)
    lseek(fd,0,SEEK_END);
  else
    lseek(fd,context->resume,SEEK_SET);

  FORALL_HOOKS(EVENT_PREUPLOAD)
    typedef int (*login_hook)(unsigned long, const char*, const char *);
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_PREUPLOAD,user->username,path);
  END_FORALL_HOOKS

  out_err(LEVEL_FLOOD,"Download: User %s starts uploading %s\n",
    user->username,param);

  context->current_action.token = TOK_STOR;
  strncpy(context->current_action.arg,path,4096);
  context->current_action.current_file = fd;
  context->current_action.bytesnow = 0;
  context->idle_time_data_start = context->current_action.tm_start = time(NULL);

/*  if (user->max_ul_speed)
    context->current_limiter = limiter_new(user->max_ul_speed);
  else
    context->current_limiter = NULL;*/

/*  if (user->max_ul_speed)
  {*/
    context->current_ul_limiter.maxspeed = user->max_ul_speed;
    context->current_ul_limiter.bytes_transfered = 0;
    gettimeofday(&context->current_ul_limiter.current_time,NULL);
/*  }
  else
    context->current_ul_limiter.maxspeed = 0;*/

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

  out_err(LEVEL_FLOOD,"Removing file '%s'\n",path);

  return file_remove(path,context);
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
/*    user = GetUserByID(context->userid);*/
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
/** returns 0 if ok
 * 1 if user name is invalid or has been deleted
 * 2 if user has reached num_logins
 * 3 if site is closed and user is not a siteop
 */
int do_user(const char *username, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
/*    user = GetUserByID(context->userid);*/
    user = NULL;

  ret = backend_validate_login(username,user,&context->userid);
  if (ret) return 1;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
  user = GetUserByID(context->userid);

  /* check if user have been deleted */
  if (user->flags && strchr(user->flags,FLAG_DELETED))
    return 1;

  /* check if site is closed */
  if (mainConfig->site_closed &&
      !(user->flags && strchr(user->flags,FLAG_SITEOP)))
    return 3;

  /* count logins from user */
  if (user->num_logins)
  {
    int count=0;
    int i;
    for (i=0; i<HARD_USERLIMIT; i++)
    {
#if BACKEND_STORAGE
      /* strcmp user->username , ? */
#else
      if (context_list[i].magic == CONTEXT_MAGIC && context->userid == context_list[i].userid)
#endif
	count++;
    } /* for (i=0; i<HARD_USERLIMIT; i... */

    /* we substract 1, because the current login attempt is counted */
    count--;

    out_err(LEVEL_CRITICAL,"NUM_logins: %d\n",count);

    if (count >= user->num_logins) return 2;
    /* >= and not ==, because it two attempts are issued simultaneously, count > num_logins ! */
  }
  
  return 0;
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
    user = GetUserByID(context->userid);

  snprintf(ip,30,"%d.%d.%d.%d",userip[0],userip[1],userip[2],userip[3]);
  if (user_ip_inlist(user,ip)==1)
    return 0;
  
  /* user ip not found, try groups */
  for (i=0; i<user->group_num; i++) {
    group = GetGroupByID(user->groups[i]);
    if (group_ip_inlist(group,ip)==1)
      return 0;
  }

  return 1;
}

/*************** check_tls_forced ********************/
/** check if tls connection must be enforced for user
 * return 0 if user is in tls mode or is not forced to user
 *        1 if user should be in tls but is not
 */
int check_tls_forced(wzd_context_t * context)
{
  wzd_user_t * user;
/*  wzd_group_t *group;
  int i;*/

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (user->flags && strchr(user->flags,FLAG_TLS)) {
    if ( !(context->connection_flags & CONNECTION_TLS) ) {
      return 1;
    }
  }
  /* TODO XXX FIXME implement flags for groups */
#if 0
  /* try groups */
  for (i=0; i<user->group_num; i++) {
    group = GetGroupByID(user->groups[i]);
    if (group->flags && strchr(group->flags,FLAG_TLS)) {
      if ( !(context->connection_flags & CONNECTION_TLS) ) {
	return 1;
      }
  }
#endif

  return 0;
}

/*************** do_login_loop ***********************/

int do_login_loop(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * token;
  char username[HARD_USERNAME_LENGTH];
  int ret;
  int user_ok=0, pass_ok=0;
#ifdef SSL_SUPPORT
  int tls_ok=0;
#endif
  int command;

  *username = '\0';

  while (1) {
    /* wait response */
    ret = (context->read_fct)(context->controlfd,buffer,BUFFER_LEN,0,HARD_XFER_TIMEOUT,context);

    if (ret == 0) {
      out_err(LEVEL_FLOOD,"Connection closed or timeout\n");
      return 1;
    }
    if (ret==-1) {
      out_err(LEVEL_FLOOD,"Error reading client response\n");
      return 1;
    }

    /* this replace the memset (bzero ?) some lines before */
    buffer[ret] = '\0';

    if (buffer[0]=='\0') continue;

    {
      int length = strlen(buffer);
      while (length >= 0 && (buffer[length-1]=='\r' || buffer[length-1]=='\n'))
	buffer[length-- -1] = '\0';
      strncpy(context->last_command,buffer,HARD_LAST_COMMAND_LENGTH-1);
    }

#ifdef DEBUG
out_err(LEVEL_FLOOD,"RAW: '%s'\n",buffer);
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
      if (!token) {
	ret = send_message_with_args(421,context,"Give me a user name !");
	return 1;
      }
      ret = do_user(token,context);
      if (ret==1) { /* user was not accepted */
	ret = send_message_with_args(421,context,"User rejected");
	return 1;
      }
      if (ret==2) { /* too many logins */
	ret = send_message_with_args(421,context,"Too many connections with your login");
	return 1;
      }
      if (ret==3) { /* site closed */
	ret = send_message_with_args(421,context,"Site is closed, try again later");
	return 1;
      }
      /* validate ip for user */
      ret = do_user_ip(token,context);
      if (ret) { /* user was not accepted */
	ret = send_message_with_args(421,context,"IP not allowed");
	return 1;
      }
      strncpy(username,token,HARD_USERNAME_LENGTH-1);
      ret = send_message_with_args(331,context,username);
      user_ok = 1;
      break;
    case TOK_PASS:
      if (!user_ok || pass_ok) {
	ret = send_message_with_args(421,context,"Incorrect login sequence");
	return 1;
      }
      token = strtok_r(NULL," \t\r\n",&ptr);
      if (!token) {
	ret = send_message_with_args(421,context,"Give me a password !");
	return 1;
      }
      ret = do_pass(username,token,context);
      if (ret) { /* pass was not accepted */
	ret = send_message_with_args(421,context,"Password rejected");
	return 1;
      }
      /* IF SSL, we should check HERE if the connection has been switched to tls or not */
#ifdef SSL_SUPPORT
      if (mainConfig->tls_type == TLS_STRICT_EXPLICIT && !tls_ok) {
	ret = send_message_with_args(421,context,"TLS session MUST be engaged");
	return 1;
      }
#endif
      /* check if user must be connected in tls mode */
      if (check_tls_forced(context)) {
	  ret = send_message_with_args(421,context,"User MUST connect in tls/ssl mode");
	  return 1;
      }
      return 0; /* user + pass ok */
      break;
#ifdef SSL_SUPPORT
    case TOK_AUTH:
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token || token[0]==0) {
        ret = send_message_with_args(421,context,"Invalid token in AUTH command\n");
        return 1;
      }
      if (strcasecmp(token,"SSL")==0 || mainConfig->tls_type == TLS_IMPLICIT)
        context->ssl.data_mode = TLS_PRIV; /* SSL must have encrypted data connection */
      else
	context->ssl.data_mode = TLS_CLEAR;
      if (mainConfig->tls_type != TLS_IMPLICIT) {
        ret = send_message_with_args(234, context, token);
      }
      ret = tls_auth(token,context);
      if (ret) { /* couldn't switch to ssl */
	/* XXX should we send a message ? - with ssl aborted we can't be sure there won't be problems */
	ret = send_message_with_args(431,context,"Failed TLS negotiation");
	return 1;
      }
      tls_ok = 1;
      context->connection_flags |= CONNECTION_TLS;
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
#else /* SSL_SUPPORT */
    case TOK_AUTH:
    case TOK_PBSZ:
    case TOK_PROT:
      ret = send_message_with_args(530,context,"TLS commands disabled");
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
void * clientThreadProc(void *arg)
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
  int oldtype;

  context = arg;
  sockfd = context->controlfd;
	
  out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);
#ifdef WZD_MULTITHREAD
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);
  pthread_cleanup_push((void (*) (void *))client_die, (void *) context);
#endif /* WZD_MULTITHREAD */

  ret = do_login(context);

  if (ret) { /* USER not logged in */
    socket_close (sockfd);
    out_log(LEVEL_INFO,"LOGIN FAILURE Client dying (socket %d)\n",sockfd);
#ifdef WZD_MULTITHREAD
    client_die(context);
#endif /* WZD_MULTITHREAD */
    return NULL;
  }

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  {
    const char * groupname = NULL;
    const char * userip = context->hostip;
    const char * remote_host;
    struct hostent *h;
    h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),AF_INET);
    if (h==NULL)
      remote_host = inet_ntoa( *((struct in_addr*)context->hostip) );
    else
      remote_host = h->h_name;
    if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
    log_message("LOGIN","%s (%u.%u.%u.%u) \"%s\" \"%s\" \"%s\"",
	remote_host,
	userip[0],userip[1],userip[2],userip[3],
	user->username,
	(groupname)?groupname:"No Group",
	user->tagline
	);
  }

  /* user+pass ok */
  FORALL_HOOKS(EVENT_LOGIN)
    typedef int (*login_hook)(unsigned long, const char*);
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_LOGIN,user->username);
    if (hook->external_command)
      ret = hook_call_external(hook,user->username);
  END_FORALL_HOOKS
  ret = send_message(230,context);

  /* update last login time */
  time(&user->last_login);

  /* main loop */
  exitclient=0;
  context->idle_time_start = time(NULL);

  while (!exitclient) {
    save_errno = 666;
    /* trying to find if bzero is faster than memset */
/*    bzero(buffer,BUFFER_LEN);*/
/*    memset(buffer,0,BUFFER_LEN);*/
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

    /* this replace the memset (bzero ?) some lines before */
    buffer[ret] = '\0';

    if (buffer[0]=='\0') continue;

    {
      int length = strlen(buffer);
      while (length >= 0 && (buffer[length-1]=='\r' || buffer[length-1]=='\n'))
	buffer[length-- -1] = '\0';
      strncpy(context->last_command,buffer,HARD_LAST_COMMAND_LENGTH-1);
    }
/*    context->idle_time_start = time(NULL);*/
#ifdef DEBUG
out_err(LEVEL_FLOOD,"RAW: '%s'\n",buffer);
#endif

    /* 2. get next token */
    ptr = &buffer[0];
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    context->state = command;

	  switch (command) {
	  case TOK_QUIT:
	    ret = send_message(221,context);
	    {
	      const char * groupname = NULL;
	      const char * userip = context->hostip;
	      const char * remote_host;
	      struct hostent *h;
	      h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),AF_INET);
	      if (h==NULL)
		remote_host = inet_ntoa( *((struct in_addr*)context->hostip) );
	      else
		remote_host = h->h_name;
	      if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
	      log_message("LOGOUT","%s (%u.%u.%u.%u) \"%s\" \"%s\" \"%s\"",
		  remote_host,
		  userip[0],userip[1],userip[2],userip[3],
		  user->username,
		  (groupname)?groupname:"No Group",
		  user->tagline
		  );
	    }
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
	      socket_close(context->pasvsock);
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
	      /* TODO print message file */
/*	      print_file("/home/pollux/.message",250,context);*/
	      ret = send_message_with_args(250,context,context->currentpath,"now current directory.");
	      break;
	    }
	    if (do_chdir(param,context)) {
	      ret = send_message_with_args(550,context,param,"No such file or directory (no access ?).");
	      break;
	    }
	      /* TODO print message file */
            print_file("/home/pollux/.message",250,context);
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
	    context->idle_time_start = time(NULL);
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
	    context->idle_time_start = time(NULL);
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
/*	      snprintf(buffer2,BUFFER_LEN-1,"\"%s\" created",token);*/
              FORALL_HOOKS(EVENT_MKDIR)
                typedef int (*mkdir_hook)(unsigned long, const char*);
                if (hook->hook)
	          ret = (*(mkdir_hook)hook->hook)(EVENT_MKDIR,token);
		if (hook->external_command)
		  ret = hook_call_external(hook,token);
              END_FORALL_HOOKS

	      ret = send_message_with_args(257,context,token,"created");
	    }
	    context->idle_time_start = time(NULL);
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
              FORALL_HOOKS(EVENT_RMDIR)
                typedef int (*rmdir_hook)(unsigned long, const char*);
                if (hook->hook)
	          ret = (*(rmdir_hook)hook->hook)(EVENT_RMDIR,token);
		if (hook->external_command)
		  ret = hook_call_external(hook,token);
              END_FORALL_HOOKS
	      ret = send_message_with_args(258,context,buffer2,"");
	    }
	    context->idle_time_start = time(NULL);
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
	    context->idle_time_start = time(NULL);
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
	    context->idle_time_start = time(NULL);
	    break;
	  case TOK_APPE:
	    if (context->current_action.token != TOK_UNKNOWN) {
	      ret = send_message(491,context);
	      break;
	    }
	    token = strtok_r(NULL,"\r\n",&ptr);
	    context->resume = (unsigned long)-1;
	    ret = do_stor(token,context);

	    context->resume=0;
	    context->idle_time_start = time(NULL);
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
	    context->idle_time_start = time(NULL);
	    break;
	  case TOK_ABOR:
/*	    if (context->pid_child) kill(context->pid_child,SIGTERM);
	    context->pid_child = 0;*/
	    if (context->pasvsock) {
	      socket_close(context->pasvsock);
	      context->pasvsock=0;
	    }
	    if (context->current_action.current_file) {
	      out_xferlog(context, 0 /* incomplete */);
	      /* FIXME XXX TODO
	       * the two following sleep(5) are MANDATORY
	       * the reason is unknown, but seems to be link to network
	       * (not lock)
	       */
      sleep(5);
	      if (context->current_action.token == TOK_STOR) {
		file_unlock(context->current_action.current_file);
		file_close(context->current_action.current_file,context);
		/* send events here allow sfv checker to mark file as bad if
		 * partially uploaded
		 */
		FORALL_HOOKS(EVENT_POSTUPLOAD)
		  typedef int (*upload_hook)(unsigned long, const char*, const char *);
		  ret = (*(upload_hook)hook->hook)(EVENT_POSTUPLOAD,user->username,context->current_action.arg);
		END_FORALL_HOOKS
	      }
              context->current_action.current_file = 0;
              context->current_action.bytesnow = 0;
              context->current_action.token = TOK_UNKNOWN;
              data_close(context);
      sleep(5);
	    }
	    ret = send_message(226,context);
	    break;
#ifdef SSL_SUPPORT
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
#ifdef SSL_SUPPORT
	    ret = send_message_with_args(211,context,"AUTH TLS\n PBSZ\n PROT\n MDTM\n SIZE\n SITE\n REST");
#else
	    ret = send_message_with_args(211,context,"MDTM\n SIZE\n SITE\n REST");
#endif
	    context->idle_time_start = time(NULL);
	    break;
	  case TOK_RNFR:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    do_rnfr(token,context);
	    break;
	  case TOK_RNTO:
	    token = strtok_r(NULL,"\r\n",&ptr);
	    do_rnto(token,context);
	    context->idle_time_start = time(NULL);
	    break;
	  case TOK_NOTHING:
	    break;
	  default:
	    ret = send_message(202,context);
	    break;
	  }
	} /* while (!exitclient) */

/*	Sleep(2000);*/

#ifdef WZD_MULTITHREAD
      pthread_cleanup_pop(1); /* 1 means the cleanup fct is executed !*/
#else /* WZD_MULTITHREAD */
      client_die(context);
#endif /* WZD_MULTITHREAD */

#ifdef SSL_SUPPORT
      tls_free(context);
#endif
      return NULL;
}
