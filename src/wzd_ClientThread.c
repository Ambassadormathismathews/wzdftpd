/* vi:ai:et:ts=8 sw=2
 */
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

#ifdef WIN32
#define        INET_ADDRSTRLEN         16
#define        INET6_ADDRSTRLEN        46
#endif

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
#include <io.h>
#endif

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h> /* gethostbyaddr */

#endif /* __CYGWIN__ && WINSOCK_SUPPORT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#ifndef _MSC_VER
#include <unistd.h>
#include <pthread.h>
#endif

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_data.h"
#include "wzd_messages.h"
#include "wzd_vfs.h"
#include "wzd_crc32.h"
#include "wzd_file.h"
#include "wzd_md5.h"
#include "wzd_ratio.h"
#include "wzd_section.h"
#include "wzd_site.h"
#include "wzd_socket.h"
#include "wzd_tls.h"
#include "ls.h"
#include "wzd_ClientThread.h"

#include "wzd_debug.h"

#define BUFFER_LEN	4096

/*************** identify_token **********************/

int identify_token(char *token)
{
  unsigned int length;
  if (!token || (length=strlen(token))==0)
    return TOK_UNKNOWN;
  ascii_lower(token,length);
/* TODO order the following by probability order */
  if (strcmp("user",token)==0)
    return TOK_USER;
  if (strcmp("pass",token)==0)
    return TOK_PASS;
  if (strcmp("auth",token)==0)
    return TOK_AUTH;
  if (strcmp("quit",token)==0)
    return TOK_QUIT;
  if (strcmp("type",token)==0)
    return TOK_TYPE;
  if (strcmp("mode",token)==0)
    return TOK_MODE;
  if (strcmp("port",token)==0)
    return TOK_PORT;
  if (strcmp("pasv",token)==0)
    return TOK_PASV;
  if (strcmp("pwd",token)==0)
    return TOK_PWD;
  if (strcmp("noop",token)==0)
    return TOK_NOOP;
  if (strcmp("syst",token)==0)
    return TOK_SYST;
  if (strcmp("cwd",token)==0)
    return TOK_CWD;
  if (strcmp("cdup",token)==0)
    return TOK_CDUP;
  if (strcmp("list",token)==0)
    return TOK_LIST;
  if (strcmp("nlst",token)==0)
    return TOK_NLST;
  if (strcmp("mkd",token)==0)
    return TOK_MKD;
  if (strcmp("rmd",token)==0)
    return TOK_RMD;
  if (strcmp("retr",token)==0)
    return TOK_RETR;
  if (strcmp("stor",token)==0)
    return TOK_STOR;
  if (strcmp("appe",token)==0)
    return TOK_APPE;
  if (strcmp("rest",token)==0)
    return TOK_REST;
  if (strcmp("mdtm",token)==0)
    return TOK_MDTM;
  if (strcmp("size",token)==0)
    return TOK_SIZE;
  if (strcmp("dele",token)==0)
    return TOK_DELE;
  if (strcmp("abor",token)==0)
    return TOK_ABOR;
#ifdef HAVE_OPENSSL
  if (strcmp("pbsz",token)==0)
    return TOK_PBSZ;
  if (strcmp("prot",token)==0)
    return TOK_PROT;
#endif
  if (strcmp("site",token)==0)
    return TOK_SITE;
  if (strcmp("feat",token)==0)
    return TOK_FEAT;
  if (strcmp("allo",token)==0)
    return TOK_ALLO;
  if (strcmp("rnfr",token)==0)
    return TOK_RNFR;
  if (strcmp("rnto",token)==0)
    return TOK_RNTO;
  if (strcmp("abor",token)==0)
    return TOK_ABOR;
  if (strcmp("epsv",token)==0)
    return TOK_EPSV;
  if (strcmp("eprt",token)==0)
    return TOK_EPRT;
  if (strcmp("pret",token)==0)
    return TOK_PRET;
  if (strcmp("xcrc",token)==0)
    return TOK_XCRC;
  if (strcmp("xmd5",token)==0)
    return TOK_XMD5;
  /* XXX FIXME TODO the following sequence can be divided into parts, and MUST be followwed by either
   * STAT or ABOR or QUIT
   * we should return TOK_PREPARE_SPECIAL_CMD or smthing like this
   * and wait the next command
   */
  if (strcmp("\xff\xf2",token)==0)
    return TOK_NOTHING;
  if (strcmp("\xff\xf4\xff\xf2",token)==0)
    return TOK_NOTHING;
  if (strcmp("\xff\xf4",token)==0) /* telnet IP */
    return TOK_NOTHING;
  if (strcmp("\xff",token)==0) /* telnet SYNCH */
    return TOK_NOTHING;
  return TOK_UNKNOWN;
}

/*************** clear_read **************************/

int clear_read(unsigned int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext)
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

#if defined(_MSC_VER)
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

int clear_write(unsigned int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext)
{
/*  wzd_context_t * context = (wzd_context_t*)vcontext;*/
  int ret;
  int done;
  int save_errno;
  fd_set fds, efds;
  struct timeval tv;

  done=0;
  while (length>0) {
    if (timeout==0)
      ret = send(sock,msg+done,length,0);
    else {
      while (1) {
        FD_ZERO(&fds);
        FD_ZERO(&efds);
        FD_SET(sock,&fds);
        FD_SET(sock,&efds);
        tv.tv_sec = timeout; tv.tv_usec = 0;

#if defined(_MSC_VER)
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
      ret = send(sock,msg+done,length,0);
      if (ret==-1) return ret;
    } /* timeout */
    done += ret;
    length -= ret;
  }

  return done;
}

/*************** getmyip *****************************/

unsigned char * getmyip(int sock)
{
#if !defined(IPV6_SUPPORT)
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
#else /* IPV6_SUPPORT */
  static unsigned char myip[16];
  struct sockaddr_in6 sa6;
  unsigned int size;

  size = sizeof(struct sockaddr_in6);
  memset(myip,0,sizeof(myip));
  if (getsockname(sock,(struct sockaddr *)&sa6,&size)!=-1)
  {
    memcpy(myip,&sa6.sin6_addr,sizeof(myip));
  } else { /* failed, using localhost */
    exit (1);
  }

  return myip;
#endif /* IPV6_SUPPORT */
}

/***************** client_die ************************/

void client_die(wzd_context_t * context)
{
  int ret;

  FORALL_HOOKS(EVENT_LOGOUT)
    typedef int (*login_hook)(unsigned long, const char*);
#ifdef BACKEND_STORAGE
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_LOGOUT,GetUserByID(context->userid)->username);
#endif
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_LOGOUT,GetUserByID(context->userid)->username);
  END_FORALL_HOOKS

#if 0
#ifdef BACKEND_STORAGE
  if (context->userinfo.flags)
    free(context->userinfo.flags);
#endif
#endif

#ifdef DEBUG
/*  if (context->current_limiter) {
out_err(LEVEL_HIGH,"clientThread: limiter is NOT null at exit\n");
  }*/
#endif

/*  limiter_free(context->current_limiter);*/
  context->magic = 0;

  out_log(LEVEL_INFO,"Client dying (socket %d)\n",context->controlfd);
  /* close existing pasv connections */
  if (context->pasvsock >= 0) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = -1;
  }
  if (context->datafd >= 0) {
    socket_close(context->datafd);
    FD_UNREGISTER(context->datafd,"Client data fd");
  }
  context->datafd = -1;
  socket_close(context->controlfd);
  FD_UNREGISTER(context->controlfd,"Client socket");
  context->controlfd = -1;
}

/*************** check_timeout ***********************/

int check_timeout(wzd_context_t * context)
{
  time_t t, delay;
  wzd_group_t *gptr;
  unsigned int i;
  int ret;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0)
    user = GetUserByID(context->userid);
  else
#endif
    user = GetUserByID(context->userid);

  /* reset global ul/dl counters */
  mainConfig->global_ul_limiter.bytes_transfered = 0;
#ifndef _MSC_VER
  gettimeofday(&(mainConfig->global_ul_limiter.current_time),NULL);
  mainConfig->global_dl_limiter.bytes_transfered = 0;
  gettimeofday(&(mainConfig->global_dl_limiter.current_time),NULL);
#else
  _ftime(&(mainConfig->global_ul_limiter.current_time));
  mainConfig->global_dl_limiter.bytes_transfered = 0;
  _ftime(&(mainConfig->global_dl_limiter.current_time));
#endif

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
        if (hook->hook)
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
        char inet_str[256];
        inet_str[0] = '\0';
        inet_ntop(CURRENT_AF,context->hostip,inet_str,sizeof(inet_str));
        log_message("TIMEOUT","%s (%s) timed out after being idle %d seconds",
            user->username,
            inet_str,
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
          char inet_str[256];
          inet_str[0] = '\0';
          inet_ntop(CURRENT_AF,context->hostip,inet_str,sizeof(inet_str));
          log_message("TIMEOUT","%s (%s) timed out after being idle %d seconds",
              user->username,
              inet_str,
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
  char allowed[WZD_MAX_PATH],path[WZD_MAX_PATH];
  struct stat buf;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);


  if (!wanted_path) return E_WRONGPATH;
  if (checkpath(wanted_path,path,context)) return E_WRONGPATH;
  snprintf(allowed,WZD_MAX_PATH,"%s/",user->rootpath);

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    return E_FILE_FORBIDDEN;
  }

  {
    int ret;
    int length;
    char tmppath[WZD_MAX_PATH];

    strncpy(tmppath,path,WZD_MAX_PATH); /* FIXME slow, and length _MUST_ be tested */
    /* remove trailing / */
    length = strlen(tmppath);
    if (length>1 && tmppath[length-1]=='/')
#ifdef _MSC_VER
      if (length != 3) /* root of a logical dir */
#endif
      tmppath[length-1] = '\0';
    ret = _checkPerm(tmppath,RIGHT_CWD,user);
  
    if (ret) { /* no access */
      return E_NOPERM;
    }
  }


  if (!stat(path,&buf)) {
    if (S_ISDIR(buf.st_mode)) {
      char buffer[WZD_MAX_PATH], buffer2[WZD_MAX_PATH];
      if (wanted_path[0] == '/') { /* absolute path */
        strncpy(buffer,wanted_path,WZD_MAX_PATH);
      } else {
        strncpy(buffer,context->currentpath,WZD_MAX_PATH);
        if (buffer[strlen(buffer)-1] != '/')
          strlcat(buffer,"/",WZD_MAX_PATH);
        strlcat(buffer,wanted_path,WZD_MAX_PATH);
      }
      stripdir(buffer,buffer2,WZD_MAX_PATH-1);
/*out_err(LEVEL_INFO,"DIR: %s NEW DIR: %s\n",buffer,buffer2);*/
      strncpy(context->currentpath,buffer2,WZD_MAX_PATH-1);
    }
    else return E_NOTDIR;
  }
  else return E_FILE_NOEXIST;

#ifdef DEBUG
out_err(LEVEL_INFO,"current path: '%s'\n",context->currentpath);
#endif

  return E_OK;
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
  unsigned int sock;
  unsigned char remote_host[16];
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
/*      send_message_with_args(501,context,"PASV timeout");*/
      return -1;
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, remote_host, &remote_port);
  if (sock == -1) {
    out_err(LEVEL_FLOOD,"accept failed to client %s:%d.\n",__FILE__,__LINE__);
    out_err(LEVEL_FLOOD,"errno is %d:%s.\n",errno,strerror(errno));
    socket_close(sock);
/*    send_message_with_args(501,context,"PASV timeout");*/
      return -1;
  }

#ifdef HAVE_OPENSSL
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_init_datamode(sock, context);
#endif

  socket_close (context->pasvsock);
  FD_UNREGISTER(context->pasvsock,"Client PASV socket");
  context->pasvsock = sock;

  context->datafd = sock;
  context->datamode = DATA_PASV;

  return sock;
}

/*************** waitconnect *************************/

int waitconnect(wzd_context_t * context)
{
  int sock;
  int ret;

  if (context->datafamily == WZD_INET4)
  {

    /** \todo TODO XXX FIXME check ipv4 IP at this point ! */

    ret = send_message(150,context); /* about to open data connection */
    sock = socket_connect(context->dataip,context->datafamily,context->dataport,mainConfig->port-1,context->controlfd,HARD_XFER_TIMEOUT);
    if (sock == -1) {
      ret = send_message(425,context);
      return -1;
    }

#ifdef HAVE_OPENSSL
    if (context->ssl.data_mode == TLS_PRIV)
      ret = tls_init_datamode(sock, context);
#endif

  } /* context->datafamily == WZD_INET4 */
#if defined(IPV6_SUPPORT)
  else if (context->datafamily == WZD_INET6)
  {

    /** \todo TODO XXX FIXME check ipv6 IP at this point ! */

    ret = send_message(150,context); /* about to open data connection */
    sock = socket_connect(context->dataip,context->datafamily,context->dataport,mainConfig->port-1,context->controlfd,HARD_XFER_TIMEOUT);
    if (sock == -1) {
      out_log(LEVEL_FLOOD,"Error establishing PORT connection: %s (%d)\n",strerror(errno),errno);
      ret = send_message(425,context);
      return -1;
    }

#ifdef HAVE_OPENSSL
    if (context->ssl.data_mode == TLS_PRIV)
      ret = tls_init_datamode(sock, context);
#endif

  } /* context->datafamily == WZD_INET6 */
#endif /* IPV6_SUPPORT */
  else
  {
    out_err(LEVEL_CRITICAL,"Invalid protocol %s:%d\n",__FILE__,__LINE__);
    ret = send_message(425,context);
    return -1;
  }
 
  return sock;
}

/*************** list_callback ***********************/

int list_callback(unsigned int sock, wzd_context_t * context, char *line)
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

#ifdef HAVE_OPENSSL
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
  char mask[1024],cmd[WZD_MAX_PATH],path[WZD_MAX_PATH];
  int ret,sock,n;
  char nullch[8];
  char * cmask;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (param && (strlen(param) >= (WZD_MAX_PATH-10)))
  {
    ret = send_message_with_args(501,context,"Argument or parameter too big.");
    return E_PARAM_BIG;
  }

  if (context->pasvsock < 0 && context->dataport == 0)
  {
    ret = send_message_with_args(501,context,"No data connection available.");
    return E_NO_DATA_CTX;
  }

  strcpy(nullch,".");
  mask[0] = '\0';
  if (param) {

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

    strncpy(cmd,param,sizeof(cmd));
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
        strncpy(cmd,ptr+1,WZD_MAX_PATH);
        *ptr = '\0';
//	strncpy(cmd,strrchr(cmd,'/')+1,2048);
//	*strrchr(cmd,'/') = '\0';
      } else { /* simple wildcard */
        strncpy(mask,cmd,sizeof(mask));
        cmd[0] = '\0';
      }
    }
    if (strrchr(cmd,'*') || strrchr(cmd,'?')) { /* wildcards in path ? ough */
      ret = send_message_with_args(501,context,"You can't put wildcards in the middle of path, only in the last part.");
      return E_PARAM_INVALID;
    }
  } else { /* no param, assume list of current dir */
    cmd[0] = '\0';
    param = nullch;
  }

  if (param[0]=='/') param++;
  if (param[0]=='/') {
    ret = send_message_with_args(501,context,"Too many / in the path - is it a joke ?");
    return E_PARAM_INVALID;
  }

  cmask = strrchr(mask,'/');
  if (cmask) {	/* search file in path (with /), but without wildcards */
    *cmask='\0';
    strlcat(cmd,"/",WZD_MAX_PATH);
    strlcat(cmd,mask,WZD_MAX_PATH);
    strncpy(mask,cmask,sizeof(mask));
  }

/*#ifdef DEBUG
printf("path before: '%s'\n",cmd);
#endif*/

  if (checkpath(cmd,path,context) || !strncmp(mask,"..",2)) {
    ret = send_message_with_args(501,context,"invalid filter/path");
    return E_PARAM_INVALID;
  }

/*#ifdef DEBUG
printf("path: '%s'\n",path);
#endif*/

  /* CHECK PERM */
  ret = _checkPerm(path,RIGHT_LIST,user);

  if (ret) { /* no access */
    ret = send_message_with_args(550,context,"LIST","No access");
    return E_NOPERM;
  }

  if (context->pasvsock < 0) { /* PORT ! */

    /** \todo TODO check that ip is correct - no trying to fxp LIST ??!! */

    sock = waitconnect(context);
    if (sock < 0) {
      /* note: reply is done in waitconnect() */
      return E_CONNECTTIMEOUT;
    }

  } else { /* PASV ! */
    ret = send_message(150,context); /* about to open data connection */
    if ((sock=waitaccept(context)) <= 0) {
      ret = send_message_with_args(501,context,"PASV connection failed");
      return E_PASV_FAILED;
    }
    context->pasvsock = -1;
  }
  FD_REGISTER(sock,"Client LIST socket");


  if (strlen(mask)==0) strcpy(mask,"*");

  if (list(sock,context,listtype,path,mask,list_callback))
    ret = send_message(226,context);
  else
    ret = send_message_with_args(501,context,"Error processing list");

#ifdef HAVE_OPENSSL
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = socket_close(sock);
  FD_UNREGISTER(sock,"Client LIST socket");
  context->datafd = -1;

  return E_OK;
}

/*************** do_mkdir ****************************/

int do_mkdir(char *param, wzd_context_t * context)
{
  char cmd[WZD_MAX_PATH], path[WZD_MAX_PATH];
  char buffer[WZD_MAX_PATH];
  int ret;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (!param || !param[0]) return E_PARAM_NULL;
  if (strlen(param)>WZD_MAX_PATH-1) return E_PARAM_BIG;
  if (strcmp(param,"/")==0) return E_OK;

  if (param[0] != '/') {
    strcpy(cmd,".");
    if (checkpath(cmd,path,context)) return E_WRONGPATH;
    if (path[strlen(path)-1]!='/') strcat(path,"/");
    strlcat(path,param,WZD_MAX_PATH);
  } else {
    strcpy(cmd,param);
    if (checkpath(cmd,path,context)) return E_WRONGPATH;
    if (path[strlen(path)-1]!='/') strcat(path,"/");
/*    if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';*/
  }
  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  ret = checkpath(param,buffer,context);

#if DEBUG
  if (ret || errno)
    out_err(LEVEL_FLOOD,"Making directory '%s' (%d, %s %d %d)\n",buffer,ret,strerror(errno),errno,ENOENT);
  else
    out_err(LEVEL_FLOOD,"Making directory '%s' (%d)\n",buffer,ret);
#endif

  if (buffer[strlen(buffer)-1]=='/')
    buffer[strlen(buffer)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    return E_FILE_FORBIDDEN;
  }

  if (strcmp(path,buffer) != 0) {
    out_err(LEVEL_FLOOD,"strcmp(%s,%s) != 0\n",path,buffer);
    return E_MKDIR_PARSE;
  }

  /* check section path-filter */
  {
    char *ptr;
    wzd_section_t * section;
    strcpy(path,buffer);
    ptr = strrchr(path,'/');
    if (ptr && ptr!=&path[0]) {
      *ptr='\0';
      /* we can reuse cmd */
      if (param[0] != '/') {
        unsigned int length;
        strncpy(cmd,context->currentpath,WZD_MAX_PATH-1-strlen(param));
        length = strlen(cmd);
        if (cmd[length-1]!='/') {
          cmd[length++] = '/';
        }
        strncpy(cmd+length,param,WZD_MAX_PATH-1-length);
      } else {
        strncpy(cmd,param,WZD_MAX_PATH);
      }
      /* we need to give the ftp-relative path here */
      section = section_find(mainConfig->section_list,cmd);
      if (section && !section_check_filter(section,ptr+1))
      {
        out_err(LEVEL_FLOOD,"path %s does not match path-filter\n",path);
        return E_MKDIR_PATHFILTER;
      }
    }
  }

  context->current_action.token = TOK_MKD;
  strncpy(context->current_action.arg,buffer,HARD_LAST_COMMAND_LENGTH);
  context->current_action.current_file = 0;

  ret = file_mkdir(buffer,0755,context); /* TODO umask ? - should have a variable here */

  if (ret) {
    out_err(LEVEL_FLOOD,"mkdir returned %d (%s)\n",errno,strerror(errno));
  } else {
    const char *groupname=NULL;
    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }
    file_chown(buffer,user->username,groupname,context);

    FORALL_HOOKS(EVENT_MKDIR)
      typedef int (*mkdir_hook)(unsigned long, const char*);
      if (hook->hook)
        ret = (*(mkdir_hook)hook->hook)(EVENT_MKDIR,buffer);
      if (hook->external_command)
        ret = hook_call_external(hook,257);
    END_FORALL_HOOKS

  if (param[0] != '/') {
      strcpy(buffer,context->currentpath);
      strlcat(buffer,"/",WZD_MAX_PATH);
      strlcat(buffer,param,WZD_MAX_PATH);
    } else {
      strcpy(buffer,param);
    }
    stripdir(buffer,path,WZD_MAX_PATH-1);
    
    log_message("NEWDIR","\"%s\" \"%s\" \"%s\" \"%s\"",
        path, /* ftp-absolute path */
        user->username,
        (groupname)?groupname:"No Group",
        user->tagline
        );
  }

  return ret;
}

/*************** do_rmdir ****************************/

int do_rmdir(char * param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  struct stat s;
  int ret;

  if (!param || !param[0]) return E_PARAM_NULL;
  if (strlen(param)>WZD_MAX_PATH-1) return E_PARAM_BIG;

  if (checkpath(param,path,context)) return E_WRONGPATH;

  /* if path is / terminated, lstat will return the dir itself in case
   * of a symlink
   */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    return E_FILE_FORBIDDEN;
  }

  if (lstat(path,&s)) return E_FILE_NOEXIST;
  if (!S_ISDIR(s.st_mode)) return E_NOTDIR;

  /* check permissions */
  ret = file_rmdir(path,context);

  if (!ret) {
    const char *groupname=NULL;
    wzd_user_t * user;
    char buffer[WZD_MAX_PATH], path[WZD_MAX_PATH];

#ifdef BACKEND_STORAGE
    if (mainConfig->backend.backend_storage==1) {
      user = &context->userinfo;
    } else
#endif
      user = GetUserByID(context->userid);

    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }

    if (param[0] != '/') {
      strcpy(buffer,context->currentpath);
      strlcat(buffer,"/",WZD_MAX_PATH);
      strlcat(buffer,param,WZD_MAX_PATH);
    } else {
      strcpy(buffer,param);
    }
    stripdir(buffer,path,WZD_MAX_PATH-1);
    
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
  unsigned char pasv_bind_ip[16];
  int offset=0;

  size = sizeof(struct sockaddr_in);
  port = mainConfig->pasv_low_range; /* use pasv range min */

  /* close existing pasv connections */
  if (context->pasvsock >= 0) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = -1;
  }

  /* create socket */
  if ((context->pasvsock=socket(AF_INET,SOCK_STREAM,0)) < 0) {
    context->pasvsock = -1;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

  if (mainConfig->pasv_ip[0] == 0) {
#if defined(IPV6_SUPPORT)
      if (IN6_IS_ADDR_V4MAPPED(myip))
        memcpy(pasv_bind_ip,myip+12,4);
      else
#endif /* IPV6_SUPPORT */
        memcpy(pasv_bind_ip,myip,4);
  } else {
#if defined(IPV6_SUPPORT)
    if (IN6_IS_ADDR_V4MAPPED(context->hostip))
      offset = 12;
#endif
    /* do NOT send pasv_ip if used from private network */
    if (context->hostip[offset+0]==10 ||
      (context->hostip[offset+0] == 172 && context->hostip[offset+1] == 16) ||
      (context->hostip[offset+0] == 192 && context->hostip[offset+1] == 168 && context->hostip[offset+2] == 0) ||
      (context->hostip[offset+0] == 127 && context->hostip[offset+1] == 0 && context->hostip[offset+2] == 0 && context->hostip[offset+3] == 1))
    {
#if defined(IPV6_SUPPORT)
      if (IN6_IS_ADDR_V4MAPPED(myip))
        memcpy(pasv_bind_ip,myip+12,4);
      else
#endif /* IPV6_SUPPORT */
        memcpy(pasv_bind_ip,myip,4);
    }
    else
#if defined(IPV6_SUPPORT)
      if (IN6_IS_ADDR_V4MAPPED(mainConfig->pasv_ip))
        memcpy(pasv_bind_ip,mainConfig->pasv_ip+12,4);
      else
#endif /* IPV6_SUPPORT */
        memcpy(pasv_bind_ip,mainConfig->pasv_ip,4);
  }
/*  out_err(LEVEL_CRITICAL,"PASV_IP: %d.%d.%d.%d\n",
      pasv_bind_ip[0], pasv_bind_ip[1], pasv_bind_ip[2], pasv_bind_ip[3]);*/

  while (port < mainConfig->pasv_high_range) { /* use pasv range max */
    memset(&sai,0,size);

    sai.sin_family = AF_INET;
    sai.sin_port = htons((unsigned short)port);
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
    context->pasvsock = -1;
    ret = send_message(425,context);
    return;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    ret = send_message(425,context);
    return;
  }

  FD_REGISTER(context->pasvsock,"Client PASV socket");

  context->datafamily = WZD_INET4;
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

/*************** do_eprt *****************************/
void do_eprt(char *param, wzd_context_t * context)
{
#if defined(IPV6_SUPPORT)
  int ret;
  char sep;
  char net_prt;
  char * net_addr, * s_tcp_port;
  char * ptr;
  unsigned int tcp_port;
  struct hostent * host;
  struct in_addr addr4;
  struct in6_addr addr6;

  if (context->pasvsock) {
    socket_close(context->pasvsock);
    context->pasvsock = -1;
  }
  /* context->resume = 0; */
  if (!param || strlen(param) <= 7) {
    ret = send_message(502,context);
    ret = send_message_with_args(501,context,"Invalid argument");
    return;
  }

  sep = *param++;
  net_prt = *param++;
  if ( (*param++) != sep || (net_prt != '1' && net_prt != '2') ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    return;
  }

  net_addr = param;
  while (*param && (*param) != sep ) param++;
  if ( !*param ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    return;
  }

  *param = '\0';
  param++;

  s_tcp_port = param;
  while (*param && (*param) != sep ) param++;
  if ( !*param || *param != sep ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    return;
  }

  *param = '\0';

  tcp_port = strtoul(s_tcp_port,&ptr,0);
  if (*ptr) {
    ret = send_message_with_args(501,context,"Invalid port");
    return;
  }

  /* resolve net_addr to context->dataip */
  switch (net_prt - '0') {
  case WZD_INET4:
    if ( (ret=inet_pton(AF_INET,net_addr,&addr4)) <= 0 )
    {
      ret = send_message_with_args(501,context,"Invalid host");
      return;
    }
    memcpy(context->dataip,(const char *)addr4.s_addr,4);
    break;
  case WZD_INET6:
    if ( (ret=inet_pton(AF_INET6,net_addr,&addr6)) <= 0 )
    {
      ret = send_message_with_args(501,context,"Invalid host");
      return;
    }
    memcpy(context->dataip,addr6.s6_addr,16);
    break;
  default:
    ret = send_message_with_args(501,context,"Invalid protocol");
    return;
  }
  

  context->dataport = tcp_port;
  context->datafamily = net_prt - '0';

  ret = send_message_with_args(200,context,"Command okay");
#else /* defined(IPV6_SUPPORT) */
  send_message(202,context);
#endif
}

/*************** do_epsv *****************************/
void do_epsv(wzd_context_t * context)
{
  int ret;
  unsigned long addr;
  unsigned int size,port;
  struct sockaddr_in sai;
#if defined(IPV6_SUPPORT)
  struct sockaddr_in6 sai6;
#endif
  unsigned char *myip;
  unsigned char pasv_bind_ip[16];

#if !defined(IPV6_SUPPORT)
  size = sizeof(struct sockaddr_in);
#else
  size = sizeof(struct sockaddr_in6);
#endif
  port = mainConfig->pasv_low_range; /* use pasv range min */

  /* close existing pasv connections */
  if (context->pasvsock >= 0) {
    socket_close(context->pasvsock);
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = -1;
  }

  /* create socket */
#if !defined(IPV6_SUPPORT)
  if ((context->pasvsock = socket(PF_INET,SOCK_STREAM,0)) < 0)
#else
  if ((context->pasvsock = socket(PF_INET6,SOCK_STREAM,0)) < 0)
#endif
  {
    context->pasvsock = -1;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

  if (mainConfig->pasv_ip[0] == 0) {
    memcpy(pasv_bind_ip,myip,sizeof(pasv_bind_ip));
  } else {
    /* do NOT send pasv_ip if used from private network */
    /** \todo TODO XXX FIXME private networks are not the same in ipv6 */
    if (context->hostip[0]==10 ||
      (context->hostip[0] == 172 && context->hostip[1] == 16) ||
      (context->hostip[0] == 192 && context->hostip[1] == 168 && context->hostip[2] == 0) ||
      (context->hostip[0] == 127 && context->hostip[1] == 0 && context->hostip[2] == 0 && context->hostip[3] == 1))
      memcpy(pasv_bind_ip,myip,sizeof(pasv_bind_ip));
    else
      memcpy(pasv_bind_ip,mainConfig->pasv_ip,sizeof(pasv_bind_ip));
  }
/*  out_err(LEVEL_CRITICAL,"PASV_IP: %d.%d.%d.%d\n",
      pasv_bind_ip[0], pasv_bind_ip[1], pasv_bind_ip[2], pasv_bind_ip[3]);*/

  while (port < mainConfig->pasv_high_range) { /* use pasv range max */
#if !defined(IPV6_SUPPORT)
    memset(&sai,0,size);

    sai.sin_family = AF_INET;
    sai.sin_port = htons((unsigned short)port);
    /* XXX TODO FIXME bind to specific address works, but not for NAT */
    /* XXX TODO FIXME always bind to 'myip' ?! */
    addr = INADDR_ANY;
/*    memcpy( (void*)&addr, pasv_bind_ip, sizeof(unsigned long));*/
    
    memcpy(&sai.sin_addr.s_addr,&addr,sizeof(unsigned long));

    if (bind(context->pasvsock,(struct sockaddr *)&sai,size)==0) break;
#else /* IPV6_SUPPORT */
    memset(&sai6,0,size);

    sai6.sin6_family = AF_INET6;
    sai6.sin6_port = htons(port);
    sai6.sin6_flowinfo = 0;
/*     sai6.sin6_addr = in6addr_any;*/ /* FIXME VISUAL */
    memset(&sai6.sin6_addr,0,16);
    /* XXX TODO FIXME bind to specific address works, but not for NAT */
    /* XXX TODO FIXME always bind to 'myip' ?! */
/*    addr = INADDR_ANY;*/
    
/*    memcpy(&sai.sin_addr.s_addr,&addr,sizeof(unsigned long));*/

    if (bind(context->pasvsock,(struct sockaddr *)&sai6,size)==0) break;

#endif /* IPV6_SUPPORT */
    port++; /* retry with next port */
  }


  if (port >= 65536) {
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    ret = send_message(425,context);
    return;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    ret = send_message(425,context);
    return;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

#if !defined(IPV6_SUPPORT)
  context->datafamily = WZD_INET4;
  ret = send_message_with_args(227,context,pasv_bind_ip[0], pasv_bind_ip[1], pasv_bind_ip[2], pasv_bind_ip[3],(port>>8)&0xff, port&0xff);
#else
  context->datafamily = WZD_INET6;
  {
    char buf[256];
    snprintf(buf,256,"227 Entering Passive Mode (|||%d|)\r\n",port);
    ret = send_message_raw(buf,context);
  }
#endif
  
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
  char path[WZD_MAX_PATH];
  int fd;
  unsigned long bytestot, bytesnow, byteslast;
  int sock;
  int ret;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock < 0) && (context->dataport == 0)) {
    ret = send_message_with_args(501,context,"No data connection available - issue PORT or PASV first");
    return E_NO_DATA_CTX;
  }

  if (!param || strlen(param)==0) {
    ret = send_message_with_args(501,context,"Incorrect filename");
    return E_PARAM_INVALID;
  }

  if (strlen(param)>WZD_MAX_PATH-1) {
    ret = send_message_with_args(501,context,"Filename too long");
    return E_PARAM_BIG;
  }

  if (checkpath(param,path,context)) {
    ret = send_message_with_args(501,context,"Invalid file name");
    return E_PARAM_INVALID;
  }

  /* trailing / ? */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1] = '\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
  }

  /* check user ratio */
  if (ratio_check_download(path,context)) {
    ret = send_message_with_args(501,context,"Insufficient credits - Upload first");
    return E_CREDS_INSUFF;
  }

  if ((fd=file_open(path,O_RDONLY,RIGHT_RETR,context))==-1) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(550,context,param,"nonexistant file or permission denied");
/*    socket_close(sock);*/
    return E_FILE_NOEXIST;
  }
  FD_REGISTER(fd,"Client file (RETR)");

  /* get length */
  bytestot = lseek(fd,0,SEEK_END);
  if (bytestot == -1) /* happens with 0-length files */
    bytestot = 0;
  bytesnow = byteslast=context->resume;

  if (context->pasvsock < 0) { /* PORT ! */

    /* \todo TODO IP-check needed (FXP ?!) */
    sock = waitconnect(context);
    if (sock < 0) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (RETR)");
      /* note: reply is done in waitconnect() */
      return E_CONNECTTIMEOUT;
    }

  } else { /* PASV ! */
    /* FIXME */
/*    sprintf(cmd, "150 Opening BINARY data connection for '%s' (%ld bytes).\r\n",
      param, bytestot);*/
    ret = send_message(150,context);
    if ((sock=waitaccept(context)) < 0) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (RETR)");
      ret = send_message_with_args(501,context,"PASV connection failed");
      return E_PASV_FAILED;
    }
  }
  FD_REGISTER(sock,"Client data socket (RETR)");

  context->datafd = sock;

  lseek(fd,context->resume,SEEK_SET);

  out_log(LEVEL_FLOOD,"Download: User %s starts downloading %s (%ld bytes)\n",
    user->username,param,bytestot);

  context->current_action.token = TOK_RETR;
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);
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
#ifndef _MSC_VER
    gettimeofday(&context->current_dl_limiter.current_time,NULL);
#else
    _ftime(&context->current_dl_limiter.current_time);
#endif
/*  }
  else
    context->current_dl_limiter.maxspeed = 0;*/

  /* we increment the counter of downloaded files at the beggining
   * of the download
   */
  user->stats.files_dl_total++;
  return E_OK;
}

/*************** do_stor *****************************/
int do_stor(char *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH],path2[WZD_MAX_PATH],cmd[WZD_MAX_PATH];
  int fd;
  unsigned long bytesnow, byteslast;
  int sock;
  int ret;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock < 0) && (context->dataport == 0)) {
    ret = send_message_with_args(503,context,"Issue PORT or PASV First");
    return E_NO_DATA_CTX;
  }

  if (!param || strlen(param)==0) {
    ret = send_message_with_args(501,context,"Incorrect filename");
    return E_PARAM_INVALID;
  }

  if (strlen(param)>WZD_MAX_PATH-1) {
    ret = send_message_with_args(501,context,"Filename too long");
    return E_PARAM_BIG;
  }

  if (param[0]=='/') { /* absolute path */
    strcpy(path,user->rootpath);
  } else { /* absolute path */
    /* FIXME these 2 lines forbids STOR dir/filename style - normal ? */
/*   XXX if (strrchr(param,'/'))
      param = strrchr(param,'/')+1; XXX */

    strcpy(cmd,".");
    if (checkpath(cmd,path,context)) {
      ret = send_message_with_args(501,context,"Incorrect filename");
      return E_PARAM_INVALID;
    }
    if (path[strlen(path)-1] != '/') strcat(path,"/");
  } /* absolute path */
  strlcat(path,param,WZD_MAX_PATH);

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
      strlcat(path,param,WZD_MAX_PATH);
      out_err(LEVEL_FLOOD,"Resolved: %s\n",path);
    }
  }
  /* END OF BUGFIX */

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
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
    return E_FILE_NOEXIST;
  }
  FD_REGISTER(fd,"Client file (STOR)");

  if (context->pasvsock < 0) { /* PORT ! */

    /* \todo TODO IP-check needed (FXP ?!) */
    sock = waitconnect(context);
    if (sock < 0) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (STOR)");
      /* note: reply is done in waitconnect() */
      return E_CONNECTTIMEOUT;
    }

  } else { /* PASV ! */
    /* FIXME */
/*    sprintf(cmd, "150 Opening BINARY data connection for '%s'.\r\n",
      param);*/
    ret = send_message(150,context);
    if ((sock=waitaccept(context)) < 0) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (STOR)");
      ret = send_message_with_args(501,context,"PASV connection failed");
      return E_PASV_FAILED;
    }
  }
  FD_REGISTER(sock,"Client data socket (STOR)");

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
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);
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
#ifndef WIN32 /* FIXME VISUAL */
    gettimeofday(&context->current_ul_limiter.current_time,NULL);
#else
    _ftime(&context->current_ul_limiter.current_time);
#endif
/*  }
  else
    context->current_ul_limiter.maxspeed = 0;*/

  return E_OK;
}

/*************** do_mdtm *****************************/
void do_mdtm(char *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH], tm[32];
  struct stat s;
  int ret;

  if (!param || strlen(param)>=WZD_MAX_PATH) {
    ret = send_message_with_args(501,context,"Incorrect argument");
    return;
  }

  if (!checkpath(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

    /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
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
  char path[WZD_MAX_PATH];
  char buffer[1024];
  struct stat s;
  int ret;

  if (!param || strlen(param)>=WZD_MAX_PATH) {
    ret = send_message_with_args(501,context,"Incorrect argument");
    return;
  }
  if (!checkpath(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
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
  char path[WZD_MAX_PATH];
  int ret;
  struct stat s;
  u64_t file_size;
  wzd_user_t * user, * owner;

  if (!param || strlen(param)==0 || strlen(param)>=WZD_MAX_PATH || checkpath(param,path,context)) {
    ret = send_message_with_args(501,context,"Syntax error");
    return E_PARAM_INVALID;
  }

  user = GetUserByID(context->userid);
  if (!user) {
    ret = send_message_with_args(501,context,"Mama says I don't exist !");
    return E_USER_IDONTEXIST;
  }

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
  }

  if (lstat(path,&s)) {
    /* non-existent file ? */
    ret = send_message_with_args(501,context,"File does not exist");
    return E_FILE_NOEXIST;
  }
  if (S_ISDIR(s.st_mode)) {
    ret = send_message_with_args(501,context,"This is a directory !");
    return E_ISDIR;
  }
  if (S_ISREG(s.st_mode))
    file_size = s.st_size;
  else
    file_size = 0;
  owner = file_getowner(path,context);

  out_err(LEVEL_FLOOD,"Removing file '%s'\n",path);

  ret = file_remove(path,context);

  /* decrement user credits and upload stats */
  /* we should adjust stats for REAL OWNER of file */
  if (!ret && file_size)
  {
    if (owner) {
      if (strcmp(owner->username,"nobody"))
      {
        if (owner->ratio) {
          if (owner->credits > owner->ratio*file_size)
            owner->credits -= (owner->ratio * file_size);
          else
            owner->credits = 0;
        }
        if (owner->stats.bytes_ul_total > file_size)
          owner->stats.bytes_ul_total -= file_size;
        else
          owner->stats.bytes_ul_total = 0;
        if (owner->stats.files_ul_total)
          owner->stats.files_ul_total--;
      }
    }
  }

  if (!ret)
    ret = send_message_with_args(250,context,"DELE"," command successfull");
  else
    ret = send_message_with_args(501,context,"DELE failed");
  return ret;
}

/*************** do_rnfr *****************************/
void do_rnfr(const char *filename, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  int ret;

  if (!filename || strlen(filename)==0 || strlen(filename)>=WZD_MAX_PATH || checkpath(filename,path,context)) {
    ret = send_message_with_args(550,context,"RNFR","file does not exist");
    return;
  }

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return;
  }

  context->current_action.token = TOK_RNFR;
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);
  context->current_action.current_file = 0;
  context->current_action.bytesnow = 0;
  context->current_action.tm_start = time(NULL);

  ret = send_message_with_args(350,context,"OK, send RNTO");
}

/*************** do_rnto *****************************/
void do_rnto(const char *filename, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  int ret;

  if (!filename || strlen(filename)==0 || strlen(filename)>=WZD_MAX_PATH) {
    ret = send_message_with_args(553,context,"RNTO","wrong file name ?");
    return;
  }

  checkpath(filename,path,context);
  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
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
    ret = send_message_with_args(250,context,"RNTO"," command OK");
  }
}

/*************** do_pret *****************************/
void do_pret(char *param, wzd_context_t * context)
{
  int ret;

  /* TODO XXX FIXME PRET *MUST* be sent before the PASV command */

  /* TODO check next token (RETR STOR STOU LIST NLST APPE) and
   * run specific commands ...
   */
  /* e.g: if RETR, open file to have it in cache ? */

  ret = send_message_with_args(200,context,"Command OK");
}

/*************** do_xcrc *****************************/
void do_xcrc(char *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  char * ptr;
  char * ptest;
  struct stat s;
  int ret;
  unsigned long crc = 0;
  unsigned long startpos = 0;
  unsigned long length = (unsigned long)-1;

  if (!param || strlen(param)==0 || strlen(param)>=WZD_MAX_PATH) {
    ret = send_message_with_args(501,context,"Syntax error");
    return;
  }

  /* get filename and args:
   * "filename" must be quoted
   * startpos and length are optional
   */
  ptr = param;
  if (*ptr == '"') {
    ptr++;
    while (*ptr && *ptr != '"') ptr++;
    if (!*ptr) {
      ret = send_message_with_args(501,context,"Syntax error");
      return;
    }
    memcpy(buffer,param+1,ptr-param-1);
    buffer[ptr-param-1] = '\0';
    ptr++;
    /* optional: read startpos AND length */
    startpos = strtoul(ptr,&ptest,0);
    if (ptest && ptest != ptr)
    {
      ptr = ptest;
      length = strtoul(ptr,&ptest,0);
      if (!ptest || ptest == ptr) {
        ret = send_message_with_args(501,context,"Syntax error");
        return;
      } else { /* optional: read start checksum */
        ptr = ptest;
        crc = strtoul(ptr,&ptest,16);
        if (!ptest || ptest == ptr)
          crc = 0;
      }
    } else
      startpos = 0;
    param = buffer;
  }

  if (!checkpath(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return;
    }


    if (stat(path,&s)==0) {
      ret = calc_crc32(path,&crc,startpos,length);
      snprintf(buffer,1024,"%lX\r\n",crc);
/*      snprintf(buffer,1024,"%d %lX\r\n",250,crc);*/
/*      ret = send_message_raw(buffer,context);*/
      ret = send_message_with_args(250,context,buffer,"");
      return;
    }
  }
  ret = send_message_with_args(550,context,"XCRC","File inexistant or no access ?");
}

/*************** do_xmd5 *****************************/
void do_xmd5(char *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  char * ptr;
  char * ptest;
  struct stat s;
  int ret;
  unsigned char crc[16];
  unsigned char md5str[33];
  unsigned long startpos = 0;
  unsigned long length = (unsigned long)-1;
  unsigned int i;

  if (!param || strlen(param)==0 || strlen(param)>=WZD_MAX_PATH) {
    ret = send_message_with_args(501,context,"Syntax error");
    return;
  }

  for (i=0; i<16; i++)
    crc[i] = 0;

  /* get filename and args:
   * "filename" must be quoted
   * startpos and length are optional
   */
  ptr = param;
  if (*ptr == '"') {
    ptr++;
    while (*ptr && *ptr != '"') ptr++;
    if (!*ptr) {
      ret = send_message_with_args(501,context,"Syntax error");
      return;
    }
    memcpy(buffer,param+1,ptr-param-1);
    buffer[ptr-param-1] = '\0';
    ptr++;
    /* optional: read startpos AND length */
    startpos = strtoul(ptr,&ptest,0);
    if (ptest && ptest != ptr)
    {
      ptr = ptest;
      length = strtoul(ptr,&ptest,0);
      if (!ptest || ptest == ptr) {
        ret = send_message_with_args(501,context,"Syntax error");
        return;
      } else { /* optional: read start checksum */
        ptr = ptest;
        strtomd5(ptr,&ptest,crc);
        if (!ptest || ptest == ptr)
          memset(crc,0,16);
      }
    } else
      startpos = 0;
    param = buffer;
  }

  if (!checkpath(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return;
    }


    if (stat(path,&s)==0) {
      ret = calc_md5(path,crc,startpos,length);
      for (i=0; i<16; i++)
        snprintf(md5str+i*2,3,"%02x",crc[i]);
      ret = send_message_with_args(250,context,md5str,"");
      return;
    }
  }
  ret = send_message_with_args(550,context,"XMD5","File inexistant or no access ?");
}

/*************** do_pass *****************************/

/* return E_OK if ok, E_PASS_REJECTED if wrong pass, E_LOGIN_NO_HOME if ok but homedir does not exist */
int do_pass(const char *username, const char * pass, wzd_context_t * context)
{
/*  char buffer[4096];*/
  int ret;
  wzd_user_t * user;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
/*    user = GetUserByID(context->userid);*/
    user = NULL;

  ret = backend_validate_pass(username,pass,user,&context->userid);
  if (ret) {
    /* pass was not accepted */
    return E_PASS_REJECTED;
  }

  if ( ! mainConfig->backend.backend_storage )
    user = GetUserByID(context->userid);

  /* normalize rootpath */

/*  if (!realpath(context->userinfo.rootpath,buffer)) return 1;
  strncpy(context->userinfo.rootpath,buffer,1024);*/

  /* initial dir */
  strcpy(context->currentpath,"/");
  if (do_chdir(context->currentpath,context))
  {
    /* could not chdir to home !!!! */
    out_log(LEVEL_CRITICAL,"Could not chdir to home '%s' (root: '%s'), user '%s'\n",context->currentpath,user->rootpath,user->username);
    return E_USER_NO_HOME;
  }

  /* XXX - now we can wait (or not) the ACCT */

  return E_OK;
}

/*************** do_user *****************************/
/** returns E_OK if ok
 * E_USER_REJECTED if user name is rejected by backend
 * E_USER_DELETED if user has been deleted
 * E_USER_NUMLOGINS if user has reached num_logins
 * E_USER_CLOSED if site is closed and user is not a siteop
 * E_GROUP_NUMLOGINS if user has reached group num_logins
 */
int do_user(const char *username, wzd_context_t * context)
{
  int ret;
  wzd_user_t * me;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    me = &context->userinfo;
  } else
#endif
/*    me = GetUserByID(context->userid);*/
    me = NULL;

  ret = backend_validate_login(username,me,&context->userid);
  if (ret) return E_USER_REJECTED;

  if ( ! mainConfig->backend.backend_storage )
    me = GetUserByID(context->userid);

  /* check if user have been deleted */
  if (me->flags && strchr(me->flags,FLAG_DELETED))
    return E_USER_DELETED;

  /* check if site is closed */
  if (mainConfig->site_closed &&
      !(me->flags && strchr(me->flags,FLAG_SITEOP)))
    return E_USER_CLOSED;

  /* count logins from user */
  if (me->num_logins)
  {
    int count=0;
    int i;
    for (i=0; i<HARD_USERLIMIT; i++)
    {
#ifdef BACKEND_STORAGE
      /* strcmp user->username , ? */
      if (context_list[i].magic == CONTEXT_MAGIC && !strcmp(context->userinfo.username,context_list[i].userinfo.username))
#else
      if (context_list[i].magic == CONTEXT_MAGIC && context->userid == context_list[i].userid)
#endif
        count++;
    } /* for (i=0; i<HARD_USERLIMIT; i... */

    /* we substract 1, because the current login attempt is counted */
    count--;

/*    out_err(LEVEL_CRITICAL,"NUM_logins: %d\n",count);*/

    if (count >= me->num_logins) return E_USER_NUMLOGINS;
    /* >= and not ==, because it two attempts are issued simultaneously, count > num_logins ! */
  }

  /* foreach group of user, check num_logins */
  {
    unsigned int i,j;
      wzd_group_t * group;
    wzd_user_t * user;
    unsigned int num_logins[HARD_DEF_GROUP_MAX];
    memset(num_logins,0,HARD_DEF_GROUP_MAX*sizeof(int));
    /* try to do it in one pass only */
    for (i=0; i<HARD_USERLIMIT; i++)
    {
      if (context_list[i].magic == CONTEXT_MAGIC) {
        user = GetUserByID(context_list[i].userid);
        for (j=0; j<user->group_num; j++)
          num_logins[ user->groups[j] ]++;
      }
    }
    /* checks num_logins for all groups */
    for (i=0; i<me->group_num; i++)
    {
      group = GetGroupByID( me->groups[i] );
      if (group && group->num_logins
          && (num_logins[me->groups[i]]>group->num_logins))
        /* > and not >= because current login attempt is counted ! */
        return E_GROUP_NUMLOGINS; /* user has reached group max num_logins */
    }
  }
  
  return E_OK;
}

/*************** do_user_ip **************************/

int do_user_ip(const char *username, wzd_context_t * context)
{
  char ip[INET6_ADDRSTRLEN];
  const unsigned char *userip = context->hostip;
  wzd_user_t * user;
  wzd_group_t *group;
  unsigned int i;

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

#if !defined(IPV6_SUPPORT)
  inet_ntop(AF_INET,userip,ip,INET_ADDRSTRLEN);
#else
  inet_ntop(AF_INET6,userip,ip,INET6_ADDRSTRLEN);
#endif
  if (user_ip_inlist(user,ip,context->ident)==1)
    return E_OK;
  
  /* user ip not found, try groups */
  for (i=0; i<user->group_num; i++) {
    group = GetGroupByID(user->groups[i]);
    if (group_ip_inlist(group,ip,context->ident)==1)
      return E_OK;
  }

  return E_USER_NOIP;
}

/*************** check_tls_forced ********************/
/** check if tls connection must be enforced for user
 * return E_OK if user is in tls mode or is not forced to user
 *        E_USER_TLSFORCED if user should be in tls but is not
 */
int check_tls_forced(wzd_context_t * context)
{
  wzd_user_t * user;
/*  wzd_group_t *group;
  int i;*/

#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (user->flags && strchr(user->flags,FLAG_TLS)) {
    if ( !(context->connection_flags & CONNECTION_TLS) ) {
      return E_USER_TLSFORCED;
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

  return E_OK;
}

/*************** do_login_loop ***********************/

static int do_login_loop(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * token;
  char username[HARD_USERNAME_LENGTH];
  int ret;
  int user_ok=0, pass_ok=0;
#ifdef HAVE_OPENSSL
  int tls_ok=0;
#endif
  int command;

  *username = '\0';

  context->state = STATE_LOGGING;

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
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,buffer);
#endif

    /* strtok_r: to be reentrant ! */
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    switch (command) {
    case TOK_USER:
      if (user_ok) { /* USER command issued 2 times */
        ret = send_message_with_args(421,context,"USER command issued twice");
        return 1;
      }
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token) {
        ret = send_message_with_args(421,context,"Give me a user name !");
        return 1;
      }
      ret = do_user(token,context);
      switch (ret) {
      case E_USER_REJECTED: /* user was not accepted */
        ret = send_message_with_args(421,context,"User rejected");
        return 1;
      case E_USER_NUMLOGINS: /* too many logins */
        ret = send_message_with_args(421,context,"Too many connections with your login");
        return 1;
      case E_USER_CLOSED: /* site closed */
        ret = send_message_with_args(421,context,"Site is closed, try again later");
        return 1;
      case E_GROUP_NUMLOGINS: /* too many logins for group */
        ret = send_message_with_args(421,context,"Too many connections for your group");
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
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token) {
        ret = send_message_with_args(421,context,"Give me a password !");
        return 1;
      }
      ret = do_pass(username,token,context);
      if (ret==E_PASS_REJECTED) { /* pass was not accepted */
        ret = send_message_with_args(421,context,"Password rejected");
        return E_PASS_REJECTED;
      }
      if (ret==E_USER_NO_HOME) { /* pass is ok, could not chdir */
        ret = send_message_with_args(421,context,"Could not go to my home directory !");
        return E_USER_NO_HOME;
      }
      /* IF SSL, we should check HERE if the connection has been switched to tls or not */
#ifdef HAVE_OPENSSL
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
#ifdef HAVE_OPENSSL
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
      /** \todo PBSZ: convert token to int, set the PBSZ size */
      ret = send_message_with_args(200,context,"Command okay");
      break;
    case TOK_PROT:
      /** \todo PROT: if user is NOT in TLS mode, insult him */
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
#else /* HAVE_OPENSSL */
    case TOK_AUTH:
    case TOK_PBSZ:
    case TOK_PROT:
      ret = send_message_with_args(530,context,"TLS commands disabled");
      break;
#endif
    case TOK_FEAT:
      ret = send_message_with_args(211,context,SUPPORTED_FEATURES);
      break;
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
  char *buffer = NULL;
  char * param;
  int save_errno;
  unsigned int sockfd;
  int ret;
  int exitclient;
  char *token;
  char *ptr;
  int command;
  wzd_user_t * user;
#ifndef _MSC_VER
  int oldtype;
#endif

  context = arg;
  sockfd = context->controlfd;

  out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);
#ifndef _MSC_VER
#ifdef WZD_MULTITHREAD
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);
  pthread_cleanup_push((void (*) (void *))client_die, (void *) context);
#endif /* WZD_MULTITHREAD */
#endif

  ret = do_login(context);

/** \todo XXX FIXME what is the utility of these lines ?! */
#ifdef BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==1) {
    user = GetUserByID(context->userid);
  } else
#endif
    user = GetUserByID(context->userid);

  if (ret) { /* USER not logged in */
    const char * groupname = NULL;
    const unsigned char * userip = context->hostip;
    const char * remote_host;
    struct hostent *h;
    char inet_str[256];

    socket_close (sockfd);

    if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
    inet_str[0] = '\0';
    inet_ntop(CURRENT_AF,context->hostip,inet_str,sizeof(inet_str));
    h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),CURRENT_AF);
    if (h==NULL)
      remote_host = inet_str;
    else
      remote_host = h->h_name;
    out_log(LEVEL_INFO,"LOGIN FAILURE Client dying (socket %d)\n",sockfd);
    log_message("LOGIN_FAILED","%s (%s) \"%s\" \"%s\" \"%s\"",
        (remote_host)?remote_host:"no host !",
        inet_str,
        user->username,
        (groupname)?groupname:"No Group",
        user->tagline
        );
#ifdef WZD_MULTITHREAD
    client_die(context);
#endif /* WZD_MULTITHREAD */
    return NULL;
  }

  context->state = STATE_COMMAND;

  {
    const char * groupname = NULL;
    const unsigned char * userip = context->hostip;
    const char * remote_host;
    struct hostent *h;
    char inet_str[256];
    if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
    inet_str[0] = '\0';
    inet_ntop(CURRENT_AF,context->hostip,inet_str,sizeof(inet_str));
    h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),CURRENT_AF);
    if (h==NULL)
      remote_host = inet_str;
    else
      remote_host = h->h_name;
    log_message("LOGIN","%s (%s) \"%s\" \"%s\" \"%s\"",
        (remote_host)?remote_host:"no host !",
        inet_str,
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
      ret = hook_call_external(hook,230);
  END_FORALL_HOOKS
  ret = send_message(230,context);

  /* update last login time */
  time(&user->last_login);

  buffer = malloc(WZD_BUFFER_LEN);

  /* main loop */
  exitclient=0;
  context->idle_time_start = time(NULL);

  while (!exitclient) {
#ifdef DEBUG
    if (!context->magic == CONTEXT_MAGIC || sockfd != (unsigned int)context->controlfd)
    {
      out_err(LEVEL_CRITICAL,"Omar m'a tuer !\n");
      out_err(LEVEL_CRITICAL,"sock %d\n",sockfd);
    }
#endif /* DEBUG */
    save_errno = 666;
    param=NULL;
    /* 1. read */
    FD_ZERO(&fds_r);
    FD_ZERO(&fds_w);
    FD_ZERO(&efds);
    /* set control fd */
#ifdef DEBUG
    if (sockfd<0 || !fd_is_valid(sockfd)) {
      fprintf(stderr,"Trying to set invalid sockfd (%d) %s:%d\n",
          sockfd,__FILE__,__LINE__);
      exitclient=1;
      break;
    }
#endif
    FD_SET(sockfd,&fds_r);
    FD_SET(sockfd,&efds);
    /* set data fd */
    ret = data_set_fd(context,&fds_r,&fds_w,&efds);
    if ((signed)sockfd > ret) ret = sockfd;

    tv.tv_sec=HARD_REACTION_TIME; tv.tv_usec=0L;
    ret = select(ret+1,&fds_r,&fds_w,&efds,&tv);
    save_errno = errno;

    if (ret==-1) {
     if (errno == EINTR) continue;
      else {
        out_log(LEVEL_CRITICAL,"Major error during recv: control fd %d errno %d error %s\n",sockfd,save_errno,strerror(save_errno));
        exitclient = 1;
      }
    }
    /* TODO XXX FIXME is this empty if() intentional ?? */
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
    ret = (context->read_fct)(sockfd,buffer,WZD_BUFFER_LEN-1,0,0,context); /* timeout = 0, we know there's something to read */

    /* remote host has closed session */
    if (ret==0 || ret==-1) {
      out_log(LEVEL_FLOOD,"Host disconnected improperly!\n");
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
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,buffer);
#endif

    /* 2. get next token */
    ptr = &buffer[0];
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    switch (command) {
    case TOK_QUIT:
      ret = send_message(221,context);
      {
        const char * groupname = NULL;
        const unsigned char * userip = context->hostip;
        const char * remote_host;
        struct hostent *h;
        char inet_str[256];
        if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
        inet_str[0] = '\0';
        inet_ntop(CURRENT_AF,context->hostip,inet_str,sizeof(inet_str));
        h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),CURRENT_AF);
        if (h==NULL)
          remote_host = inet_str;
        else
          remote_host = h->h_name;
        log_message("LOGOUT","%s (%s) \"%s\" \"%s\" \"%s\"",
            remote_host,
            inet_str,
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
      if (!token) {
        ret = send_message_with_args(501,context,"Invalid TYPE marker");
        break;
      }
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
        context->pasvsock = -1;
      }
      /* context->resume = 0; */
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token) {
        ret = send_message_with_args(501,context,"Invalid parameters");
        break;
      }
      if ((sscanf(token,"%d,%d,%d,%d,%d,%d",
              &context->dataip[0],&context->dataip[1],&context->dataip[2],&context->dataip[3],
              &p1,&p2))<6) {
        ret = send_message(502,context);
        break;
      }

      context->dataport = ((p1&0xff)<<8) | (p2&0xff);
      context->datafamily = WZD_INET4;
      ret = send_message_with_args(200,context,"Command okay");

      break;
    case TOK_PASV:
      do_pasv(context);
      break;
    case TOK_EPRT:
      param = strtok_r(NULL,"\r\n",&ptr);
      do_eprt(param,context);
      break;
    case TOK_EPSV:
      do_epsv(context);
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
        ret = send_message_with_args(250,context,context->currentpath," now current directory.");
        break;
      }
      if (do_chdir(param,context)) {
        ret = send_message_with_args(550,context,param?param:"(null)","No such file or directory (no access ?).");
        break;
      }
      ret = send_message_with_args(250,context,context->currentpath," now current directory.");
      break;
    case TOK_LIST:
      context->resume = 0;
      context->state = STATE_XFER;
/*      if (context->pid_child) {
        ret = send_message(491,context);
        break;
      }*/
      token = strtok_r(NULL,"\r\n",&ptr);
      do_list(token,LIST_TYPE_LONG,context);
      context->idle_time_start = time(NULL);
      break;
    case TOK_NLST:
      context->resume = 0;
      context->state = STATE_XFER;
/*      if (context->pid_child) {
        ret = send_message(491,context);
        break;
      }*/
      token = strtok_r(NULL,"\r\n",&ptr);	    
      do_list(token,LIST_TYPE_SHORT,context);
      context->idle_time_start = time(NULL);
      break;
    case TOK_MKD:
      {
        char buffer2[BUFFER_LEN];
        token = strtok_r(NULL,"\r\n",&ptr);
        /* TODO check perms !! */
        switch (do_mkdir(token,context)) { 
        case E_OK: /* success */
          ret = send_message_with_args(257,context,token,"created");
          break;
        case E_FILE_FORBIDDEN:
          ret = send_message_with_args(553,context,"forbidden !");
          break;
        case E_MKDIR_PATHFILTER:
          ret = send_message_with_args(553,context,"dirname does not match pathfilter");
          break;
        default:
          /* could not create dir */
          snprintf(buffer2,BUFFER_LEN-1,"could not create dir '%s'",(token)?token:"(NULL)");
          ret = send_message_with_args(553,context,buffer2);
          break;
        }
        context->idle_time_start = time(NULL);
        break;
      }
    case TOK_RMD:
      {
        char buffer2[BUFFER_LEN];
        token = strtok_r(NULL,"\r\n",&ptr);
        /* TODO check perms !! */
        switch (do_rmdir(token,context)) {
          case E_OK: /* success */
            snprintf(buffer2,BUFFER_LEN-1,"\"%s\" deleted",token);
            FORALL_HOOKS(EVENT_RMDIR)
              typedef int (*rmdir_hook)(unsigned long, const char*);
            if (hook->hook)
              ret = (*(rmdir_hook)hook->hook)(EVENT_RMDIR,token);
            if (hook->external_command)
              ret = hook_call_external(hook,258);
            END_FORALL_HOOKS
            ret = send_message_with_args(258,context,buffer2,"");
            break;
          case E_NOTDIR:
            ret = send_message_with_args(553,context,"not a directory");
            break;
          case E_FILE_FORBIDDEN:
            ret = send_message_with_args(553,context,"forbidden !");
            break;
          default:
            snprintf(buffer2,BUFFER_LEN-1,"could not delete dir '%s'",(token)?token:"(NULL)");
            ret = send_message_with_args(553,context,buffer2);
        }
        context->idle_time_start = time(NULL);
        break;
      }
    case TOK_RETR:
      if (context->current_action.token != TOK_UNKNOWN) {
        ret = send_message(491,context);
        break;
      }
      context->state = STATE_XFER;
      token = strtok_r(NULL,"\r\n",&ptr);
      do_retr(token,context);
      context->resume=0;
      context->idle_time_start = time(NULL);
      break;
    case TOK_STOR:
      if (context->current_action.token != TOK_UNKNOWN) {
        ret = send_message(491,context);
        break;
      }
      context->state = STATE_XFER;
      token = strtok_r(NULL,"\r\n",&ptr);
      ret = do_stor(token,context);
      context->resume=0;
      context->idle_time_start = time(NULL);
      break;
    case TOK_APPE:
      if (context->current_action.token != TOK_UNKNOWN) {
        ret = send_message(491,context);
        break;
      }
      context->state = STATE_XFER;
      token = strtok_r(NULL,"\r\n",&ptr);
      context->resume = (unsigned long)-1;
      ret = do_stor(token,context);

      context->resume=0;
      context->idle_time_start = time(NULL);
      break;
    case TOK_REST:
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token) {
        ret = send_message_with_args(501,context,"Invalid REST marker");
        break;
      }
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
      do_dele(token,context);
      context->idle_time_start = time(NULL);
      break;
    case TOK_ABOR:
/*      if (context->pid_child) kill(context->pid_child,SIGTERM);
      context->pid_child = 0;*/
      if (context->pasvsock) {
        socket_close(context->pasvsock);
        FD_UNREGISTER(context->pasvsock,"Client PASV socket");
        context->pasvsock=-1;
      }
      if (context->current_action.current_file) {
        out_xferlog(context, 0 /* incomplete */);
        /** \bug FIXME XXX TODO
         * the two following sleep(5) are MANDATORY
         * the reason is unknown, but seems to be link to network
         * (not lock)
         */
#ifndef _MSC_VER
        sleep(5);
#else
        Sleep(5000);
#endif
        if (context->current_action.token == TOK_STOR) {
          file_unlock(context->current_action.current_file);
          file_close(context->current_action.current_file,context);
          /* send events here allow sfv checker to mark file as bad if
           * partially uploaded
           */
          FORALL_HOOKS(EVENT_POSTUPLOAD)
            typedef int (*upload_hook)(unsigned long, const char*, const char *);
          if (hook->hook)
            ret = (*(upload_hook)hook->hook)(EVENT_POSTUPLOAD,user->username,context->current_action.arg);
          END_FORALL_HOOKS
        }
        context->current_action.current_file = 0;
        context->current_action.bytesnow = 0;
        context->current_action.token = TOK_UNKNOWN;
        context->state = STATE_COMMAND;
        data_close(context);
#ifndef _MSC_VER
        sleep(5);
#else
        Sleep(5000);
#endif
      }
      ret = send_message(226,context);
      break;
#ifdef HAVE_OPENSSL
    case TOK_PROT:
      /** \todo TOK_PROT: if user is NOT in TLS mode, insult him */
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
      ret = send_message_with_args(211,context,SUPPORTED_FEATURES);
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
    case TOK_PRET:
      token = strtok_r(NULL,"\r\n",&ptr);
      do_pret(token,context);
      break;
    case TOK_XCRC:
      token = strtok_r(NULL,"\r\n",&ptr);
      do_xcrc(token,context);
      break;
    case TOK_XMD5:
      token = strtok_r(NULL,"\r\n",&ptr);
      do_xmd5(token,context);
      break;
    case TOK_NOTHING:
      break;
    default:
      ret = send_message(202,context);
      break;
    }
  } /* while (!exitclient) */

/*	Sleep(2000);*/

  free(buffer);

#ifdef WZD_MULTITHREAD
#ifndef _MSC_VER
  pthread_cleanup_pop(1); /* 1 means the cleanup fct is executed !*/
#else
  client_die(context);
#endif /* _MSC_VER */
#else /* WZD_MULTITHREAD */
  client_die(context);
#endif /* WZD_MULTITHREAD */

#ifdef HAVE_OPENSSL
  tls_free(context);
#endif
  return NULL;
}
