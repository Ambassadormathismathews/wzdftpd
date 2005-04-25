/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
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
/** \file wzd_ClientThread.h
 * \brief Main loop of wzdftpd client.
 *
 * This file contains the code which is executed by threads, and
 * most of the core FTP functions (see RFC 959).
 */

#include "wzd_all.h"

#ifdef WIN32

#define        INET_ADDRSTRLEN         16
#define        INET6_ADDRSTRLEN        46

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h> /* gethostbyaddr */

#endif /* WIN32 */

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

#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_data.h"
#include "wzd_messages.h"
#include "wzd_vfs.h"
#include "wzd_crc32.h"
#include "wzd_file.h"
#include "wzd_libmain.h"
#include "wzd_perm.h"
#include "wzd_ratio.h"
#include "wzd_section.h"
#include "wzd_site.h"
#include "wzd_string.h"
#include "wzd_socket.h"
#include "wzd_tls.h"
#include "wzd_utf8.h"
#include "ls.h"
#include "wzd_ClientThread.h"
#include "wzd_ServerThread.h"

#include <libwzd-auth/wzd_md5.h>

#include "wzd_debug.h"

#define BUFFER_LEN	4096

/*************** identify_token **********************/

#define STRTOINT(a,b,c,d) (((a)<<24) + ((b)<<16) + ((c)<<8) + (d))

/** \brief Fast token identification function.
 *
 * Converts the string into an integer and return the corresponding
 * identifier. Luckily, all FTP commands are no more than 4 characters.
 */
int identify_token(char *token)
{
  unsigned int length;
  if (!token || (length=strlen(token))==0)
    return TOK_UNKNOWN;
  ascii_lower(token,length);

  /* TODO order the following by probability order */
  if (length <= 4) {
    switch ( STRTOINT(token[0],token[1],token[2],token[3]) ) {
      case STRTOINT('h','e','l','p'): return TOK_HELP;
      case STRTOINT('u','s','e','r'): return TOK_USER;
      case STRTOINT('p','a','s','s'): return TOK_PASS;
      case STRTOINT('a','u','t','h'): return TOK_AUTH;
      case STRTOINT('q','u','i','t'): return TOK_QUIT;
      case STRTOINT('t','y','p','e'): return TOK_TYPE;
      case STRTOINT('m','o','d','e'): return TOK_MODE;
      case STRTOINT('p','o','r','t'): return TOK_PORT;
      case STRTOINT('p','a','s','v'): return TOK_PASV;
      case STRTOINT('p','w','d','\0'): return TOK_PWD;
      case STRTOINT('n','o','o','p'): return TOK_NOOP;
      case STRTOINT('s','y','s','t'): return TOK_SYST;
      case STRTOINT('c','w','d','\0'): return TOK_CWD;
      case STRTOINT('c','d','u','p'): return TOK_CDUP;
      case STRTOINT('l','i','s','t'): return TOK_LIST;
      case STRTOINT('n','l','s','t'): return TOK_NLST;
      case STRTOINT('m','l','s','t'): return TOK_MLST;
      case STRTOINT('m','l','s','d'): return TOK_MLSD;
      case STRTOINT('m','k','d','\0'): return TOK_MKD;
      case STRTOINT('r','m','d','\0'): return TOK_RMD;
      case STRTOINT('r','e','t','r'): return TOK_RETR;
      case STRTOINT('s','t','o','r'): return TOK_STOR;
      case STRTOINT('a','p','p','e'): return TOK_APPE;
      case STRTOINT('r','e','s','t'): return TOK_REST;
      case STRTOINT('m','d','t','m'): return TOK_MDTM;
      case STRTOINT('s','i','z','e'): return TOK_SIZE;
      case STRTOINT('d','e','l','e'): return TOK_DELE;
      case STRTOINT('a','b','o','r'): return TOK_ABOR;
      case STRTOINT('p','b','s','z'): return TOK_PBSZ;
      case STRTOINT('p','r','o','t'): return TOK_PROT;
      case STRTOINT('c','p','s','v'): return TOK_CPSV;
      case STRTOINT('s','s','c','n'): return TOK_SSCN;
      case STRTOINT('s','i','t','e'): return TOK_SITE;
      case STRTOINT('f','e','a','t'): return TOK_FEAT;
      case STRTOINT('a','l','l','o'): return TOK_ALLO;
      case STRTOINT('r','n','f','r'): return TOK_RNFR;
      case STRTOINT('r','n','t','o'): return TOK_RNTO;
      /* IPv6 */
      case STRTOINT('e','p','s','v'): return TOK_EPSV;
      case STRTOINT('e','p','r','t'): return TOK_EPRT;
      /* extensions */
      case STRTOINT('p','r','e','t'): return TOK_PRET;
      case STRTOINT('x','c','r','c'): return TOK_XCRC;
      case STRTOINT('x','m','d','5'): return TOK_XMD5;
      case STRTOINT('o','p','t','s'): return TOK_OPTS;
/*      default:
        return TOK_UNKNOWN;*/
    }
  }

  /* XXX FIXME TODO the following sequence can be divided into parts, and MUST be followed by either
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

/** \brief Non-blocking read function
 *
 * Try to read length bytes in non-blocking mode for timeout seconds
 * max. If timeout is null, performs a blocking read.
 */
int clear_read(fd_t sock, char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
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

      if (FD_ISSET(sock,&fds)) /* ok */
        break;
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

/** \brief Non-blocking write function
 *
 * Try to write length bytes in non-blocking mode for timeout seconds
 * max. If timeout is null, performs a blocking write.
 */
int clear_write(fd_t sock, const char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
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

        if (FD_ISSET(sock,&fds)) /* break */
          break;
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
/** \brief Cleanup code
 *
 * Called whenever a connection with a client is closed (for any reason).
 * Closes all files/sockets.
 */
void client_die(wzd_context_t * context)
{
  int ret;

  if (context->magic != CONTEXT_MAGIC) {
#ifdef DEBUG
out_err(LEVEL_HIGH,"clientThread: context->magic is invalid at exit\n");
#endif
    return;
  }

  /* close opened files */
  if (context->current_action.current_file != (fd_t)-1) {
    file_unlock(context->current_action.current_file);
    file_close(context->current_action.current_file,context);
    FD_UNREGISTER(context->current_action.current_file,"Client file (RETR or STOR)");
    /** \todo XXX call POST_UPLOAD hooks ?!! */
    context->current_action.current_file = -1;
  }

  FORALL_HOOKS(EVENT_LOGOUT)
    typedef int (*login_hook)(unsigned long, wzd_context_t*, const char*);
    if (hook->hook)
      ret = (*(login_hook)hook->hook)(EVENT_LOGOUT, context, GetUserByID(context->userid)->username);
  END_FORALL_HOOKS

#ifdef DEBUG
/*  if (context->current_limiter) {
out_err(LEVEL_HIGH,"clientThread: limiter is NOT null at exit\n");
  }*/
#endif

/*  limiter_free(context->current_limiter);*/

    if (context->data_buffer) {
      wzd_free(context->data_buffer);
      context->data_buffer = NULL;
    }

  out_log(LEVEL_INFO,"Client dying (socket %d)\n",context->controlfd);
  /* close existing pasv connections */
  if (context->pasvsock != (fd_t)-1) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = -1;
  }
  if (context->datafd != (fd_t)-1) {
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    /* if TLS, shutdown TLS before closing data connection */
    tls_close_data(context);
#endif
    socket_close(context->datafd);
    FD_UNREGISTER(context->datafd,"Client data fd");
  }
  context->datafd = -1;
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  /* if TLS, shutdown TLS before closing control connection */
  tls_free(context);
#endif
  socket_close(context->controlfd);
  FD_UNREGISTER(context->controlfd,"Client socket");
  context->controlfd = -1;

  context_remove(context_list,context);
}

/*************** check_timeout ***********************/

int check_timeout(wzd_context_t * context)
{
  time_t t, delay;
  wzd_group_t *gptr;
  unsigned int i;
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if (!user) return 0; /* Hmm humm XXX FIXME */

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
      file_close(context->current_action.current_file,context);
      context->current_action.current_file = -1;
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
    if (delay > (time_t)user->max_idle_time) {
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
      kill_child_new(context->pid_child,context);
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
      if (delay > (time_t)gptr->max_idle_time) {
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
        context->exitclient = 1;
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
  int ret;
  char allowed[WZD_MAX_PATH],path[WZD_MAX_PATH];
  struct statbuf buf;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_CWD) ) return E_NOPERM;

  if (!wanted_path) return E_WRONGPATH;
  ret = checkpath_new(wanted_path,path,context);
  if (ret) return ret;
  snprintf(allowed,WZD_MAX_PATH,"%s/",user->rootpath);

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    return E_FILE_FORBIDDEN;
  }

  REMOVE_TRAILING_SLASH(path);

  {
    char tmppath[WZD_MAX_PATH];

    strncpy(tmppath,path,WZD_MAX_PATH); /* FIXME slow, and length _MUST_ be tested */
    /* remove trailing / */
#if 0
    ret = _checkPerm(tmppath,RIGHT_CWD,user); /** \bug checkpath_new already checks for RIGHT_CWD */
  
    if (ret) { /* no access */
      return E_NOPERM;
    }
#endif
  }


  if (!fs_stat(path,&buf)) {
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
  fd_t sock;
  unsigned char remote_host[16];
  unsigned int remote_port;

  {
    wzd_user_t * user;
    user = GetUserByID(context->userid);
    if (user && strchr(user->flags,FLAG_TLS_DATA) && context->ssl.data_mode != TLS_PRIV) {
      send_message_with_args(501,context,"Your class must use encrypted data connections");
      return -1;
    }
  }

  sock = context->pasvsock;
  do {
    FD_ZERO(&fds);
    FD_SET(sock,&fds);
    tv.tv_sec=HARD_XFER_TIMEOUT; tv.tv_usec=0L; /* FIXME - HARD_XFER_TIMEOUT should be a variable */

    if (select(sock+1,&fds,NULL,NULL,&tv) <= 0) {
      out_err(LEVEL_FLOOD,"accept timeout to client %s:%d.\n",__FILE__,__LINE__);
      FD_UNREGISTER(sock,"Client PASV socket");
      socket_close(sock);
      send_message_with_args(501,context,"PASV timeout");
      return -1;
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, remote_host, &remote_port);
  if (sock == (fd_t)-1) {
    out_err(LEVEL_FLOOD,"accept failed to client %s:%d.\n",__FILE__,__LINE__);
    out_err(LEVEL_FLOOD,"errno is %d:%s.\n",errno,strerror(errno));
    FD_UNREGISTER(sock,"Client PASV socket");
    socket_close(sock);
    send_message_with_args(501,context,"PASV timeout");
    return -1;
  }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->ssl.data_mode == TLS_PRIV) {
    int ret;
    ret = tls_init_datamode(sock, context);
    if (ret) {
      FD_UNREGISTER(context->pasvsock,"Client PASV socket");
      socket_close(context->pasvsock);
      context->pasvsock = -1;
      socket_close(sock);
      sock = -1;
      send_message_with_args(421,context,"Data connection closed (SSL/TLS negotiation failed).");
      return -1;
    }
  }
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

  {
    wzd_user_t * user;
    user = GetUserByID(context->userid);
    if (user && strchr(user->flags,FLAG_TLS_DATA) && context->ssl.data_mode != TLS_PRIV) {
      send_message_with_args(501,context,"Your class must use encrypted data connections");
      return -1;
    }
  }

  if (context->datafamily == WZD_INET4)
  {

    /** \todo TODO XXX FIXME check ipv4 IP at this point ! */

    ret = send_message(150,context); /* about to open data connection */
    sock = socket_connect(context->dataip,context->datafamily,context->dataport,mainConfig->port-1,context->controlfd,HARD_XFER_TIMEOUT);
    if (sock == -1) {
      ret = send_message(425,context);
      return -1;
    }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    if (context->ssl.data_mode == TLS_PRIV) {
      ret = tls_init_datamode(sock, context);
      if (ret) {
        send_message_with_args(421,context,"Data connection closed (SSL/TLS negotiation failed).");
        return -1;
      }
    }
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

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    if (context->ssl.data_mode == TLS_PRIV) {
      ret = tls_init_datamode(sock, context);
      if (ret) {
        send_message_with_args(421,context,"Data connection closed (SSL/TLS negotiation failed).");
        return -1;
      }
    }
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

int list_callback(fd_t sock, wzd_context_t * context, char *line)
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

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->ssl.data_mode == TLS_CLEAR)
    clear_write(sock,line,strlen(line),0,HARD_XFER_TIMEOUT,context);
  else
#endif
    (context->write_fct)(sock,line,strlen(line),0,HARD_XFER_TIMEOUT,context);

  return 1;
}

/*************** do_list *****************************/

int do_list(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char mask[1024],cmd[WZD_MAX_PATH], *path;
  int ret,n;
  fd_t sock;
  char nullch[8];
  char * cmask;
  const char * param;
  wzd_user_t * user;
  list_type_t listtype;

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_LIST) ) return E_NOPERM;

  if (!str_checklength(arg, 0, WZD_MAX_PATH-10))
  {
    ret = send_message_with_args(501,context,"Argument or parameter too big.");
    return E_PARAM_BIG;
  }
  param = str_tochar(arg);

  if (context->pasvsock == (fd_t)-1 && context->dataport == 0)
  {
    ret = send_message_with_args(501,context,"No data connection available.");
    return E_NO_DATA_CTX;
  }
  if (context->state == STATE_XFER) {
    ret = send_message(491,context);
    return E_XFER_PROGRESS;
  }

  if (strcasecmp(str_tochar(name),"nlst")==0)
    listtype = LIST_TYPE_SHORT;
  else
    listtype = LIST_TYPE_LONG;

  context->resume = 0;

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
    if (cmd[0] != '\0' && cmd[strlen(cmd)-1]=='/') cmd[strlen(cmd)-1]='\0';

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

  path = wzd_malloc(WZD_MAX_PATH+1);
  if (checkpath_new(cmd,path,context) || !strncmp(mask,"..",2)) {
    ret = send_message_with_args(501,context,"invalid filter/path");
    wzd_free(path);
    return E_PARAM_INVALID;
  }

  REMOVE_TRAILING_SLASH(path);

/*#ifdef DEBUG
printf("path: '%s'\n",path);
#endif*/

  /* CHECK PERM */
  ret = _checkPerm(path,RIGHT_LIST,user);

  if (ret) { /* no access */
    ret = send_message_with_args(550,context,"LIST","No access");
    wzd_free(path);
    return E_NOPERM;
  }

  if (context->pasvsock == (fd_t)-1) { /* PORT ! */

    /** \todo TODO check that ip is correct - no trying to fxp LIST ??!! */

    sock = waitconnect(context);
    if (sock == (fd_t)-1) {
      /* note: reply is done in waitconnect() */
      wzd_free(path);
      return E_CONNECTTIMEOUT;
    }

  } else { /* PASV ! */
    ret = send_message(150,context); /* about to open data connection */
    if ((sock=waitaccept(context)) == (fd_t)-1) {
      /* note: reply is done in waitaccept() */
      wzd_free(path);
      return E_PASV_FAILED;
    }
    context->pasvsock = -1;
  }
  FD_REGISTER(sock,"Client LIST socket");

  context->state = STATE_XFER;

  if (strlen(mask)==0) strcpy(mask,"*");

  if (list(sock,context,listtype,path,mask,list_callback))
    ret = send_message(226,context);
  else
    ret = send_message_with_args(501,context,"Error processing list");

  wzd_free(path);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = socket_close(sock);
  FD_UNREGISTER(sock,"Client LIST socket");
  context->datafd = -1;
  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;

  return E_OK;
}


/* filename must be an ABSOLUTE path */
int mlst_single_file(const char *filename, wzd_string_t * buffer, wzd_context_t * context)
{
  struct wzd_file_t * file_info;
  char *ptr;
  struct statbuf s;
  wzd_string_t *temp;
  const char *type;

  if (!filename  || !buffer) return -1;

  ptr = strrchr(filename,'/');
  if (!ptr) return -1;
  if (ptr+1 != '\0') ptr++;

  if (fs_stat(filename,&s)) return -1;

  temp = str_allocate();

  str_sprintf(buffer," ");

  /* XXX build info */
  file_info = file_stat(filename,context);

  /* Type=... */
  if (file_info) {
    switch (file_info->kind) {
      case FILE_REG:
        type = "file"; break;
      case FILE_DIR:
        type = "dir"; break;
      case FILE_LNK:
        type = "OS.unix=slink"; break;
      case FILE_VFS:
        type = "OS.wzdftpd=vfs"; break;
      default:
        type = "unknown"; break;
    }
  } else {
    switch (s.st_mode & S_IFMT) {
      case S_IFREG:
        type = "file"; break;
      case S_IFDIR:
        type = "dir"; break;
      default:
        type = "unknown"; break;
    }
  }
  str_sprintf(temp," Type=%s;",type);
  str_append(buffer,str_tochar(temp));

  /* Size=... */
  {
    str_sprintf(temp," Size=%" PRIu64 ";",(u64_t)s.st_size);
    str_append(buffer,str_tochar(temp));
  }

  /* Modify=... */
  {
    char tm[32];
    strftime(tm,sizeof(tm),"%Y%m%d%H%M%S",gmtime(&s.st_mtime));

    str_sprintf(temp," Modify=%s;",tm);
    str_append(buffer,str_tochar(temp));
  }

#if 0
  /* Perm=... */
  {
    str_sprintf(temp," Perm=");
    /* "a" / "c" / "d" / "e" / "f" /
     * "l" / "m" / "p" / "r" / "w"
     */
    str_append(buffer,str_tochar(temp));
  }
#endif

  /* Unique=... */
  {
    str_sprintf(temp," Unique=%llu;",(u64_t)s.st_ino);
    str_append(buffer,str_tochar(temp));
  }

  /* End, append name */
  str_append(buffer," ");
  str_append(buffer,ptr);

  free_file_recursive(file_info);
  str_deallocate(temp);

  return 0;
}

/*************** do_mlsd *****************************/

int do_mlsd(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_LIST) ) return E_NOPERM;

  ret = send_message_with_args(501,context,"Not yet implemented.");

  return E_OK;
}

/*************** do_mlst *****************************/

int do_mlst(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  char * path;
  wzd_string_t * str;

  user = GetUserByID(context->userid);

  /* stat has the same behaviour as LIST */
  if ( !(user->userperms & RIGHT_LIST) ) return E_NOPERM;

  if (!str_checklength(param, 1, WZD_MAX_PATH-10))
  {
    ret = send_message_with_args(501,context,"Argument or parameter too big.");
    return E_PARAM_BIG;
  }

  context->state = STATE_COMMAND;

  path = wzd_malloc(WZD_MAX_PATH+1);
  if (checkpath_new(str_tochar(param),path,context)) {
    ret = send_message_with_args(550,context,"incorrect file name");
    wzd_free(path);
    return E_PARAM_INVALID;
  }

  str = str_allocate();
  if (mlst_single_file(path, str, context)) {
    ret = send_message_with_args(501,context,"Error occured");
    wzd_free(path);
    str_deallocate(str);
    return E_PARAM_INVALID;
  }

  str_append(str,"\r\n");


  send_message_raw("250- Listing %s\r\n",context); /* XXX %s <- param */
  send_message_raw(str_tochar(str),context);

  ret = send_message_raw("250 End\r\n",context);

  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;

  wzd_free(path);

  return E_OK;
}

/*************** do_opts *****************************/
int do_opts(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  const char *ptr;
  int ret;

  ptr = str_tochar(param);

  if (strncasecmp(ptr,"UTF8",4)==0)
  {
    ptr += 4;
    if (*ptr++ != ' ') goto label_opts_error;

#ifdef HAVE_UTF8
    if (strncasecmp(ptr,"ON",2)==0)
    {
      context->connection_flags |= CONNECTION_UTF8;
      ret = send_message_with_args(200, context, "UTF8 OPTS ON");
      return 0;
    }
    else if (strncasecmp(ptr,"OFF",2)==0)
    {
      context->connection_flags &= ~(CONNECTION_UTF8);
      ret = send_message_with_args(200, context, "UTF8 OPTS OFF");
      return 0;
    }
#endif
    /* let it go to error return */
  } /* UTF8 */

label_opts_error:
  ret = send_message_with_args(501,context,"OPTS option not recognized");

  return 0;
}

/*************** do_stat *****************************/

int do_stat(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char mask[1024],cmd[WZD_MAX_PATH], *path;
  int ret,n;
  fd_t sock;
  char nullch[8];
  char * cmask;
  const char *param;
  wzd_user_t * user;
  list_type_t listtype;
  ssl_data_t old_data_mode;

  user = GetUserByID(context->userid);

  /* stat has the same behaviour as LIST */
  if ( !(user->userperms & RIGHT_LIST) ) return E_NOPERM;

  if (!str_checklength(arg, 1, WZD_MAX_PATH-10))
  {
    ret = send_message_with_args(501,context,"Argument or parameter too big.");
    return E_PARAM_BIG;
  }
  param = str_tochar(arg);

  listtype = LIST_TYPE_LONG;

  context->resume = 0;
  context->state = STATE_COMMAND;

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

  path = wzd_malloc(WZD_MAX_PATH + 1);
  if (checkpath_new(cmd,path,context) || !strncmp(mask,"..",2)) {
    ret = send_message_with_args(501,context,"invalid filter/path");
    wzd_free(path);
    return E_PARAM_INVALID;
  }

/*#ifdef DEBUG
printf("path: '%s'\n",path);
#endif*/

  /* CHECK PERM */
  ret = _checkPerm(path,RIGHT_LIST,user);

  if (ret) { /* no access */
    ret = send_message_with_args(550,context,"STAT","No access");
    wzd_free(path);
    return E_NOPERM;
  }

  sock = context->controlfd;

  if (strlen(mask)==0) strcpy(mask,"*");

  /* \todo XXX FIXME horrible workaround to avoid sending clear data inside ssl stream */
  old_data_mode = context->ssl.data_mode;
  context->ssl.data_mode = (context->connection_flags & CONNECTION_TLS) ? TLS_PRIV : TLS_CLEAR;

  send_message_raw("213-Status of .:\r\n",context);
  send_message_raw("total 0\r\n",context);
  if (list(sock,context,listtype,path,mask,list_callback))
    ret = send_message_raw("213 End of Status\r\n",context);
  else
    ret = send_message_raw("213 Error processing list\r\n",context);

  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;
  context->ssl.data_mode = old_data_mode;

  wzd_free(path);

  return E_OK;
}

/*************** do_mkdir ****************************/

int do_mkdir(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char  * cmd = NULL, * path = NULL;
  char * buffer = NULL;
  int ret;
  wzd_user_t * user;
  const char *param;

  if (!str_checklength(arg,1,WZD_MAX_PATH-1))
  {
    ret = send_message_with_args(501,context,"invalid path");
    return E_PARAM_INVALID;
  }
  param = str_tochar(arg);

  cmd = wzd_malloc(WZD_MAX_PATH+1);
  path = wzd_malloc(WZD_MAX_PATH+1);
  buffer = wzd_malloc(WZD_MAX_PATH+1);

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_MKDIR) ) { ret = E_NOPERM; goto label_error_mkdir; }

  if (strcmp(param,"/")==0) { ret = E_WRONGPATH; goto label_error_mkdir; }

  if (param[0] != '/') {
    strcpy(cmd,".");
    if (checkpath(cmd,path,context)) { ret = E_WRONGPATH; goto label_error_mkdir; }
    if (path[strlen(path)-1]!='/') strcat(path,"/");
    strlcat(path,param,WZD_MAX_PATH);
  } else {
    wzd_strncpy(cmd,param,WZD_MAX_PATH);
    if (checkpath(cmd,path,context)) { ret = E_WRONGPATH; goto label_error_mkdir; }
    if (path[strlen(path)-1]!='/') strcat(path,"/");
/*    if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';*/
  }
  REMOVE_TRAILING_SLASH(path);

  ret = checkpath_new(param,buffer,context);
  if (ret != E_FILE_NOEXIST) goto label_error_mkdir;

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
    wzd_free(buffer);
    wzd_free(path);
    wzd_free(cmd);
    ret = send_message_with_args(553,context,"forbidden !");
    return E_FILE_FORBIDDEN;
  }

  /** \bug why this test ? it breaks mkdir inside symlinks ! */
/*  if (strcmp(path,buffer) != 0) { ret = E_MKDIR_PARSE; goto label_error_mkdir; }*/

  /* check section path-filter */
  {
    char *ptr;
    wzd_section_t * section;
    wzd_strncpy(path,buffer,WZD_MAX_PATH);
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
        ret = send_message_with_args(553,context,"dirname does not match pathfilter");
        wzd_free(buffer);
        wzd_free(path);
        wzd_free(cmd);
        return E_MKDIR_PATHFILTER;
      }
    }
  }

  context->current_action.token = TOK_MKD;
  strncpy(context->current_action.arg,buffer,HARD_LAST_COMMAND_LENGTH);
  context->current_action.current_file = -1;

  ret = file_mkdir(buffer,0755,context); /* TODO umask ? - should have a variable here */

  if (ret) {
    out_err(LEVEL_FLOOD,"mkdir returned %d (%s)\n",errno,strerror(errno));
    ret = E_PARAM_INVALID; goto label_error_mkdir;
  } else {
    const char *groupname=NULL;
    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }
    file_chown(buffer,user->username,groupname,context);

    /* send message header */
    send_message_raw("257- command ok\r\n",context);
    FORALL_HOOKS(EVENT_MKDIR)
      typedef int (*mkdir_hook)(unsigned long, const char*);
      if (hook->hook)
        ret = (*(mkdir_hook)hook->hook)(EVENT_MKDIR,buffer);
      if (hook->external_command)
        ret = hook_call_external(hook,257);
    END_FORALL_HOOKS
    ret = send_message_with_args(257,context,param,"created");

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
  context->idle_time_start = time(NULL);
  wzd_free(buffer);
  wzd_free(path);
  wzd_free(cmd);

  return E_OK;

label_error_mkdir:
  snprintf(buffer,WZD_MAX_PATH-1,"could not create dir '%s'",(param)?param:"(NULL)");
  send_message_with_args(553,context,buffer);
  wzd_free(buffer);
  wzd_free(path);
  wzd_free(cmd);
  return ret;
}

/*************** do_rmdir ****************************/

int do_rmdir(wzd_string_t *name, wzd_string_t * arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH], buffer[WZD_MAX_PATH];
  struct statbuf s;
  int ret;
  wzd_user_t * user;
  const char *param;

  if (!str_checklength(arg,1,WZD_MAX_PATH-1))
  {
    ret = send_message_with_args(501,context,"invalid path");
    return E_PARAM_INVALID;
  }
  param = str_tochar(arg);

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_RMDIR) ) { ret = E_NOPERM;; goto label_error_rmdir; }


  if (checkpath_new(param,path,context)) { ret = E_WRONGPATH; goto label_error_rmdir; }

  /* if path is / terminated, lstat will return the dir itself in case
   * of a symlink
   */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(553,context,"forbidden !");
    return E_FILE_FORBIDDEN;
  }

  if (fs_lstat(path,&s)) { ret = E_FILE_NOEXIST; goto label_error_rmdir; }
  if (!S_ISDIR(s.st_mode)) {
    ret = send_message_with_args(553,context,"not a directory");
    return E_NOTDIR;
  }

  /* check permissions */
  ret = file_rmdir(path,context);

  if (ret) {
    out_err(LEVEL_FLOOD,"rmdir returned %d (%s)\n",errno,strerror(errno));
    ret = E_PARAM_INVALID; goto label_error_rmdir;
  } else {
    const char *groupname=NULL;
    wzd_user_t * user;
    char buffer[WZD_MAX_PATH], path[WZD_MAX_PATH];

    user = GetUserByID(context->userid);

    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }

    /* send message header */
    send_message_raw("258- command ok\r\n",context);
    FORALL_HOOKS(EVENT_RMDIR)
      typedef int (*rmdir_hook)(unsigned long, const char*);
      if (hook->hook)
        ret = (*(rmdir_hook)hook->hook)(EVENT_RMDIR,buffer);
      if (hook->external_command)
        ret = hook_call_external(hook,258);
    END_FORALL_HOOKS
    ret = send_message_with_args(258,context,param,"removed");

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

  context->idle_time_start = time(NULL);

  return E_OK;

label_error_rmdir:
  snprintf(buffer,WZD_MAX_PATH-1,"could not delete dir '%s'",(param)?param:"(NULL)");
  send_message_with_args(553,context,buffer);
  return ret;
}

/*************** do_port *****************************/
int do_port(wzd_string_t *name, wzd_string_t *args, wzd_context_t * context)
{
  int a0,a1,a2,a3;
  unsigned int p1, p2;
  int ret;

  if (context->pasvsock != (fd_t)-1) {
    socket_close(context->pasvsock);
    context->pasvsock = -1;
  }
  if (!args) {
    ret = send_message_with_args(501,context,"Invalid parameters");
    return E_PARAM_NULL;
  }
  if ((sscanf(str_tochar(args),"%d,%d,%d,%d,%d,%d",
          &a0,&a1,&a2,&a3,
          &p1,&p2))<6) {
    ret = send_message(502,context);
    return E_PARAM_INVALID;
  }

  context->dataip[0] = (unsigned char)a0;
  context->dataip[1] = (unsigned char)a1;
  context->dataip[2] = (unsigned char)a2;
  context->dataip[3] = (unsigned char)a3;

  context->dataport = ((p1&0xff)<<8) | (p2&0xff);
  context->datafamily = WZD_INET4;
  ret = send_message_with_args(200,context,"Command okay");
  return E_OK;
}

/*************** do_pasv *****************************/
int do_pasv(wzd_string_t *name, wzd_string_t *args, wzd_context_t * context)
{
  int ret;
  unsigned long addr;
  unsigned int size,port;
  struct sockaddr_in sai;
  unsigned char *myip;
  unsigned char pasv_bind_ip[16];
  int offset=0;
  int count=0;

  size = sizeof(struct sockaddr_in);
  port = mainConfig->pasv_low_range; /* use pasv range min */

  /* close existing pasv connections */
  if (context->pasvsock != (fd_t)-1) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = -1;
  }

  /* create socket */
  if ((context->pasvsock=socket(AF_INET,SOCK_STREAM,0)) == (fd_t)-1) {
    context->pasvsock = -1;
    ret = send_message(425,context);
    return E_NO_DATA_CTX;
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

  port = mainConfig->pasv_low_range; /* use pasv range min */
  count = mainConfig->pasv_high_range - mainConfig->pasv_low_range;
#ifndef WIN32
  port = port + (random()) % count; /* we try to change starting port for random */
#else
  port = port + (rand()) % count; /* we try to change starting port for random */
#endif
  while (count > 0) { /* use pasv range max */
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
    if (port >= mainConfig->pasv_high_range)
      port = mainConfig->pasv_low_range;
    /** \bug this could create an infinite loop */
  }
  if (port < mainConfig->pasv_low_range || port > mainConfig->pasv_high_range)
  {
    out_log(LEVEL_HIGH, "PASV: found port out of range !! (%d not in [%d , %d])\n",
        mainConfig->pasv_low_range, mainConfig->pasv_high_range);
  }


  if (port >= 65536) {
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    ret = send_message(425,context);
    return E_NO_DATA_CTX;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    ret = send_message(425,context);
    return E_NO_DATA_CTX;
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

  if (strcasecmp("cpsv",str_tochar(name))==0)
    context->tls_role = TLS_CLIENT_MODE;

  return E_OK;
}

/*************** do_eprt *****************************/
int do_eprt(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
#if defined(IPV6_SUPPORT)
  int ret;
  char sep;
  char net_prt;
  char * net_addr, * s_tcp_port;
  char * ptr;
  unsigned int tcp_port;
  struct in_addr addr4;
  struct in6_addr addr6;
  char * param;

  if (context->pasvsock != (fd_t)-1) {
    socket_close(context->pasvsock);
    context->pasvsock = -1;
  }
  /* context->resume = 0; */
  if (!arg || strlen(str_tochar(arg)) <= 7) {
    ret = send_message(502,context);
    ret = send_message_with_args(501,context,"Invalid argument");
    return E_PARAM_INVALID;
  }

  param = strdup(str_tochar(arg));

  sep = *param++;
  net_prt = *param++;
  if ( (*param++) != sep || (net_prt != '1' && net_prt != '2') ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    free(param);
    return E_PARAM_INVALID;
  }

  net_addr = param;
  while (*param && (*param) != sep ) param++;
  if ( !*param ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    free(param);
    return E_PARAM_INVALID;
  }

  *param = '\0';
  param++;

  s_tcp_port = param;
  while (*param && (*param) != sep ) param++;
  if ( !*param || *param != sep ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    free(param);
    return E_PARAM_INVALID;
  }

  *param = '\0';

  tcp_port = strtoul(s_tcp_port,&ptr,0);
  if (*ptr) {
    ret = send_message_with_args(501,context,"Invalid port");
    free(param);
    return E_PARAM_INVALID;
  }

  /* resolve net_addr to context->dataip */
  switch (net_prt - '0') {
  case WZD_INET4:
    if ( (ret=inet_pton(AF_INET,net_addr,&addr4)) <= 0 )
    {
      ret = send_message_with_args(501,context,"Invalid host");
      free(param);
      return E_PARAM_INVALID;
    }
    memcpy(context->dataip,(const char *)addr4.s_addr,4);
    break;
  case WZD_INET6:
    if ( (ret=inet_pton(AF_INET6,net_addr,&addr6)) <= 0 )
    {
      ret = send_message_with_args(501,context,"Invalid host");
      free(param);
      return E_PARAM_INVALID;
    }
    memcpy(context->dataip,addr6.s6_addr,16);
    break;
  default:
    ret = send_message_with_args(501,context,"Invalid protocol");
    free(param);
    return E_PARAM_INVALID;
  }


  context->dataport = tcp_port;
  context->datafamily = net_prt - '0';

  free(param);
  ret = send_message_with_args(200,context,"Command okay");
#else /* defined(IPV6_SUPPORT) */
  send_message(202,context);
#endif
  return E_OK;
}

/*************** do_epsv *****************************/
int do_epsv(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  int ret;
  unsigned int size,port;
#if defined(IPV6_SUPPORT)
  struct sockaddr_in6 sai6;
#else
  struct sockaddr_in sai;
  unsigned long addr;
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
  if (context->pasvsock != (fd_t)-1) {
    socket_close(context->pasvsock);
/*    port = context->pasvsock+1; *//* FIXME force change of socket */
    context->pasvsock = -1;
  }

  /* create socket */
#if !defined(IPV6_SUPPORT)
  if ((context->pasvsock = socket(PF_INET,SOCK_STREAM,0)) == (fd_t)-1)
#else
  if ((context->pasvsock = socket(PF_INET6,SOCK_STREAM,0)) == (fd_t)-1)
#endif
  {
    context->pasvsock = -1;
    ret = send_message(425,context);
    return E_NO_DATA_CTX;
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
    return E_NO_DATA_CTX;
  }

  if (listen(context->pasvsock,1)<0) {
    out_log(LEVEL_CRITICAL,"Major error during listen: errno %d error %s\n",errno,strerror(errno));
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    ret = send_message(425,context);
    return E_NO_DATA_CTX;
  }

  myip = getmyip(context->controlfd); /* FIXME use a variable to get pasv ip ? */

#if !defined(IPV6_SUPPORT)
  context->datafamily = WZD_INET4;
  ret = send_message_with_args(227,context,pasv_bind_ip[0], pasv_bind_ip[1], pasv_bind_ip[2], pasv_bind_ip[3],(port>>8)&0xff, port&0xff);
#else
  context->datafamily = WZD_INET6;
  {
    char buf[256];
    snprintf(buf,256,"229 Entering Passive Mode (|||%d|)\r\n",port);
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
  return E_OK;
}

/*************** do_retr *****************************/
/** \brief Prepares a data retrieval transfer.
 *
 * Ensures that a data connection is available, checks user permissions,
 * sends EVENT_PREDOWNLOAD, and opens file.
 * The real transfer is handled by data_execute().
 */
int do_retr(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  int fd;
  u64_t bytestot, bytesnow, byteslast;
  fd_t sock;
  int ret;
  wzd_user_t * user;
  const char *param;

  param = str_tochar(arg);
  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_RETR) ) return E_NOPERM;

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock == (fd_t)-1) && (context->dataport == 0)) {
    ret = send_message_with_args(501,context,"No data connection available - issue PORT or PASV first");
    return E_NO_DATA_CTX;
  }
  if (context->state == STATE_XFER) {
    ret = send_message(491,context);
    return E_XFER_PROGRESS;
  }

  if (!param || strlen(param)==0) {
    ret = send_message_with_args(501,context,"Incorrect filename");
    return E_PARAM_INVALID;
  }

  if (strlen(param)>WZD_MAX_PATH-1) {
    ret = send_message_with_args(501,context,"Filename too long");
    return E_PARAM_BIG;
  }

  if (checkpath_new(param,path,context)) {
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

  FORALL_HOOKS(EVENT_PREDOWNLOAD)
    typedef int (*xfer_hook)(unsigned long, const char*, const char *);
    ret = 0;
    if (hook->hook)
      ret = (*(xfer_hook)hook->hook)(EVENT_PREDOWNLOAD,user->username,path);
    if (hook->external_command)
      ret = hook_call_external(hook,0);
    if (ret) {
      out_log(LEVEL_NORMAL, "Download denied by hook (returned %d)\n", ret);
      ret = send_message_with_args(501,context,"Download denied");
      return E_XFER_REJECTED;
    }
  END_FORALL_HOOKS

  if ((fd=file_open(path,O_RDONLY,RIGHT_RETR,context))==-1) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(550,context,param,"nonexistant file or permission denied");
/*    socket_close(sock);*/
    return E_FILE_NOEXIST;
  }
  FD_REGISTER(fd,"Client file (RETR)");

  /* get length */
  bytestot = file_seek(fd,0,SEEK_END);
  if ((off_t)bytestot == (off_t)-1) /* happens with 0-length files */
    bytestot = 0;
  bytesnow = byteslast=context->resume;

  if (context->pasvsock == (fd_t)-1) { /* PORT ! */

    /* \todo TODO IP-check needed (FXP ?!) */
    sock = waitconnect(context);
    if (sock == (fd_t)-1) {
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
    if ((sock=waitaccept(context)) == (fd_t)-1) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (RETR)");
      /* note: reply is done in waitaccept() */
      return E_PASV_FAILED;
    }
  }
  FD_REGISTER(sock,"Client data socket (RETR)");

  context->datafd = sock;

  file_seek(fd,(fs_off_t)context->resume,SEEK_SET);

  out_log(LEVEL_FLOOD,"Download: User %s starts downloading %s (%" PRIu64 " bytes)\n", user->username,param,bytestot);

  context->state = STATE_XFER;
  context->current_action.token = TOK_RETR;
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);
  context->current_action.current_file = fd;
  context->current_action.bytesnow = 0;
  context->idle_time_data_start = context->current_action.tm_start = time(NULL);
  gettimeofday(&context->current_action.tv_start,NULL);

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

  context->resume=0;
  context->idle_time_start = time(NULL);

  return E_OK;
}

/*************** do_stor *****************************/
int do_stor(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH],path2[WZD_MAX_PATH];
  int fd;
  u64_t bytesnow, byteslast;
  fd_t sock;
  int ret;
  wzd_user_t * user;
  const char *param;

  param = str_tochar(arg);

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_STOR) ) return E_NOPERM;

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connetion */
  if ((context->pasvsock == (fd_t)-1) && (context->dataport == 0)) {
    ret = send_message_with_args(503,context,"Issue PORT or PASV First");
    return E_NO_DATA_CTX;
  }
  if (context->state == STATE_XFER) {
    ret = send_message(491,context);
    return E_XFER_PROGRESS;
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

    strcpy(path2,".");
    if (checkpath_new(path2,path,context)) {
      ret = send_message_with_args(501,context,"Incorrect filename");
      return E_PARAM_INVALID;
    }
    if (path[strlen(path)-1] != '/') strcat(path,"/");
  } /* absolute path */
  strlcat(path,param,WZD_MAX_PATH);

  /* TODO call checkpath again ? see do_mkdir */

#if 0
  /* TODO understand !!! */
  /* BUGFIX */
  if ((ret=readlink(path,path2,sizeof(path2)-1)) >= 0) {
    path2[ret] = '\0';
    out_err(LEVEL_FLOOD,"Link is:  %s %d ... checking\n",path2,ret);
    strcpy(path,path2);
    if (strrchr(path2,'/')) {
      *(param=strrchr(path2,'/'))='\0';
      param++;

      if (checkpath_new(path2,path,context)) return 1;
      if (path[strlen(path)-1] != '/') strcat(path,"/");
      strlcat(path,param,WZD_MAX_PATH);
      out_err(LEVEL_FLOOD,"Resolved: %s\n",path);
    }
  }
  /* END OF BUGFIX */
#endif /* 0 */

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
  }

  FORALL_HOOKS(EVENT_PREUPLOAD)
    typedef int (*xfer_hook)(unsigned long, const char*, const char *);
    ret = 0;
    if (hook->hook)
      ret = (*(xfer_hook)hook->hook)(EVENT_PREUPLOAD,user->username,path);
    if (hook->external_command)
      ret = hook_call_external(hook,0);
    if (ret) {
      out_log(LEVEL_NORMAL, "Upload denied by hook (returned %d)\n", ret);
      ret = send_message_with_args(501,context,"Upload denied");
      return E_XFER_REJECTED;
    }
  END_FORALL_HOOKS


  /* overwrite protection */
  /* TODO make permissions per-dir + per-group + per-user ? */
/*  if (context->userinfo.perms & PERM_OVERWRITE) {
    fp=file_open(path,"r",RIGHT_STOR,context),
    if (!fp) {
      fclose(fp);
      return 2;
    }
  }*/
  if (strcasecmp(str_tochar(name),"appe")==0)
    context->resume = (unsigned long)-1;

  if ((fd=file_open(path,O_WRONLY|O_CREAT,RIGHT_STOR,context))==-1) { /* XXX allow access to files being uploaded ? */
    ret = send_message_with_args(501,context,"nonexistant file or permission denied");
/*    socket_close(sock);*/
    return E_FILE_NOEXIST;
  }
  FD_REGISTER(fd,"Client file (STOR)");

  if (context->pasvsock == (fd_t)-1) { /* PORT ! */

    /* \todo TODO IP-check needed (FXP ?!) */
    sock = waitconnect(context);
    if (sock == (fd_t)-1) {
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
    if ((sock=waitaccept(context)) == (fd_t)-1) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (STOR)");
      /* note: reply is done in waitaccept() */
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
    file_seek(fd,0,SEEK_END);
  else
    file_seek(fd,(fs_off_t)context->resume,SEEK_SET);

  out_err(LEVEL_FLOOD,"Download: User %s starts uploading %s\n",
    user->username,param);

  context->state = STATE_XFER;
  context->current_action.token = TOK_STOR;
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);
  context->current_action.current_file = fd;
  context->current_action.bytesnow = 0;
  context->idle_time_data_start = context->current_action.tm_start = time(NULL);
  gettimeofday(&context->current_action.tv_start,NULL);

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

  context->resume=0;
  context->idle_time_start = time(NULL);

  return E_OK;
}

/*************** do_mdtm *****************************/
int do_mdtm(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH], tm[32];
  struct statbuf s;
  int ret;

  if (!str_checklength(param,1,WZD_MAX_PATH-1)) {
    ret = send_message_with_args(501,context,"Incorrect argument");
    return E_PARAM_INVALID;
  }

  if (!checkpath_new(str_tochar(param),path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

    /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return E_FILE_FORBIDDEN;
    }

    if (fs_stat(path,&s)==0) {
      context->resume = 0L;
      strftime(tm,sizeof(tm),"%Y%m%d%H%M%S",gmtime(&s.st_mtime));
      ret = send_message_with_args(213,context,tm);
      return E_OK;
    }
  }
  ret = send_message_with_args(501,context,"File inexistant or no access ?");
  return E_FILE_NOEXIST;
}

/*************** do_size *****************************/
int do_size(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  struct statbuf s;
  int ret;

  if (!str_checklength(param,1,WZD_MAX_PATH-1)) {
    ret = send_message_with_args(501,context,"Incorrect argument");
    return E_PARAM_INVALID;
  }
  if (!checkpath_new(str_tochar(param),path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return E_FILE_FORBIDDEN;
    }


    if (fs_stat(path,&s)==0) {
      snprintf(buffer,1024,"%" PRIu64,(u64_t)s.st_size);
      ret = send_message_with_args(213,context,buffer);
      return E_OK;
    }
  }
  ret = send_message_with_args(501,context,"File inexistant or no access ?");
  return E_FILE_NOEXIST;
}

/*************** do_abor *****************************/
int do_abor(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

/*      if (context->pid_child) kill(context->pid_child,SIGTERM);
      context->pid_child = 0;*/
  if (context->pasvsock != (fd_t)-1 && context->datafd != context->pasvsock) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
    context->pasvsock=-1;
  }
  if (context->current_action.current_file != (fd_t)-1) {
    /* transfer aborted, we should send a 426 */
    ret = send_message(426,context);
    out_xferlog(context, 0 /* incomplete */);
    /** \bug FIXME XXX TODO
     * the two following sleep(5) are MANDATORY
     * the reason is unknown, but seems to be link to network
     * (not lock)
     * Perhaps it was due to the missing 426 reply ?
     */
#ifndef _MSC_VER
    sleep(1);
#else
    Sleep(1000);
#endif
    if (context->current_action.token == TOK_STOR || context->current_action.token == TOK_RETR) {
      file_unlock(context->current_action.current_file);
      file_close(context->current_action.current_file,context);
      FD_UNREGISTER(context->current_action.current_file,"Client file (RETR or STOR)");
      if (context->current_action.token == TOK_STOR) {
        /* send events here allow sfv checker to mark file as bad if
         * partially uploaded
         */
        FORALL_HOOKS(EVENT_POSTUPLOAD)
          typedef int (*upload_hook)(unsigned long, const char*, const char *);
          if (hook->hook)
            ret = (*(upload_hook)hook->hook)(EVENT_POSTUPLOAD,user->username,context->current_action.arg);
        END_FORALL_HOOKS
      }
    }
    context->current_action.current_file = -1;
    context->current_action.bytesnow = 0;
    context->current_action.token = TOK_UNKNOWN;
    context->state = STATE_COMMAND;
    data_close(context);
    if (context->pasvsock != (fd_t)-1)
      context->pasvsock = -1;
#ifndef _MSC_VER
    sleep(1);
#else
    Sleep(1000);
#endif
  }
  ret = send_message(226,context);
  return E_OK;
}

/*************** do_cwd ******************************/
int do_cwd(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  int ret;
  const char *param;

  param = str_tochar(arg);
  context->resume = 0;
  if (strcmp(str_tochar(name),"cdup")==0) param="..";

  if (!param) {
    param = "/";
  }
  /* avoir error if current is "/" and action is ".." */
  if (param && !strcmp("/",context->currentpath) && !strcmp("..",param)) {
    ret = send_message_with_args(250,context,context->currentpath," now current directory.");
    return E_OK;
  }
  if ( (ret=do_chdir(param,context)) ) {
    switch (ret) {
    case E_NOTDIR:
      ret = send_message_with_args(550,context,param?param:"(null)","Not a directory");
      break;
    case E_WRONGPATH:
      ret = send_message_with_args(550,context,param?param:"(null)","Invalid path");
      break;
    case E_FILE_NOEXIST:
      ret = send_message_with_args(550,context,param?param:"(null)","No such file or directory (no access ?)");
      break;
    case E_FILE_FORBIDDEN:
    case E_NOPERM:
      ret = send_message_with_args(550,context,param?param:"(null)","Negative on that, Houston (access denied)");
      break;
    default:
      ret = send_message_with_args(550,context,param?param:"(null)","chdir FAILED");
      break;
    }
    return E_OK;
  }
  /** \bug we have to ensure that the reply is RFC compliant */
  ret = send_message_with_args(250,context,context->currentpath," now current directory.");
  return E_OK;
}

/*************** do_dele *****************************/
int do_dele(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  int ret;
  struct statbuf s;
  u64_t file_size;
  wzd_user_t * user, * owner;

  if (!str_checklength(param,1,WZD_MAX_PATH-1) || checkpath_new(str_tochar(param),path,context)) {
    ret = send_message_with_args(501,context,"Syntax error");
    return E_PARAM_INVALID;
  }

  user = GetUserByID(context->userid);
  if (!user) {
    ret = send_message_with_args(501,context,"Mama says I don't exist !");
    return E_USER_IDONTEXIST;
  }

  if ( !(user->userperms & RIGHT_DELE) ) {
    ret = send_message_with_args(501,context,"Permission denied");
    return E_NOPERM;
  }

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
  }

  if (fs_lstat(path,&s)) {
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

  context->current_action.token = TOK_DELE;
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

  if (!ret) {
    send_message_raw("250- command ok\r\n",context);
    FORALL_HOOKS(EVENT_DELE)
      typedef int (*dele_hook)(unsigned long, const char*);
      if (hook->hook)
        ret = (*(dele_hook)hook->hook)(EVENT_DELE,path);
      if (hook->external_command)
        ret = hook_call_external(hook,250);
    END_FORALL_HOOKS
    ret = send_message_with_args(250,context,"DELE"," command successfull");

    context->idle_time_start = time(NULL);
  } else
    ret = send_message_with_args(501,context,"DELE failed");

  context->current_action.token = TOK_UNKNOWN;
  return ret;
}

/*************** do_pret *****************************/
int do_pret(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;

  /* TODO XXX FIXME PRET *MUST* be sent before the PASV command */

  /* TODO check next token (RETR STOR STOU LIST NLST APPE) and
   * run specific commands ...
   */
  /* e.g: if RETR, open file to have it in cache ? */

  ret = send_message_with_args(200,context,"Command OK");
  return E_OK;
}

/*************** do_print_message ********************/
int do_print_message(wzd_string_t *name, wzd_string_t *filename, wzd_context_t * context)
{
  int cmd;
  int ret;
  char buffer[WZD_BUFFER_LEN];
  wzd_string_t * str;

  cmd = identify_token((char*)str_tochar(name));
  switch (cmd) {
    case TOK_PWD:
      context->resume = 0;
      /** \todo allow msg 257 customization */
      /*ret = send_message(257,context);*/
	  str = str_allocate();
	  str_sprintf(str,"257 \"%s\" is current directory.\r\n",context->currentpath);
#ifdef HAVE_UTF8
      if (context->connection_flags & CONNECTION_UTF8)
	  {
            if (!str_is_valid_utf8(str))
              str_local_to_utf8(str,local_charset());
	  }
#endif
      ret = send_message_raw(str_tochar(str),context);
	  str_deallocate(str);
      break;
    case TOK_ALLO:
    case TOK_NOOP:
      ret = send_message_with_args(200,context,"Command okay");
      break;
    case TOK_FEAT:
      snprintf(buffer,sizeof(buffer),"Extensions supported:\n%s",SUPPORTED_FEATURES);
      ret = send_message_with_args(211,context,buffer);
      break;
    case TOK_SYST:
      context->resume = 0;
      ret = send_message(215,context);
      break;
  }
  return E_OK;
}

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
/*************** do_prot *****************************/
int do_prot(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  const char *arg;

  arg = str_tochar(param);
  /** \todo TOK_PROT: if user is NOT in TLS mode, insult him */
  if (strcasecmp("P",arg)==0)
    context->ssl.data_mode = TLS_PRIV;
  else if (strcasecmp("C",arg)==0)
    context->ssl.data_mode = TLS_CLEAR;
  else {
    ret = send_message_with_args(550,context,"PROT","must be C or P");
    return E_PARAM_INVALID;
  }
  ret = send_message_with_args(200,context,"PROT command OK");
  return E_OK;
}
#else
int do_prot(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  return E_PARAM_INVALID;
}
#endif

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
/*************** do_sscn *****************************/
int do_sscn(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  const char *arg;

  arg = str_tochar(param);
  if (!arg || strlen(arg)==0 || strcasecmp(arg,"off")==0) {
    context->tls_role = TLS_SERVER_MODE;
    ret = send_message_with_args(200,context,"SSCN:SERVER METHOD");
    return E_OK;
  }
  if (strcasecmp(arg,"on")==0) {
    context->tls_role = TLS_CLIENT_MODE;
    ret = send_message_with_args(200,context,"SSCN:CLIENT METHOD");
    return E_OK;
  }

  ret = send_message_with_args(550,context,"SSCN","Invalid argument");
  return E_PARAM_INVALID;
}
#else
int do_sscn(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  return E_PARAM_INVALID;
}
#endif

/*************** do_quit *****************************/
int do_quit(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  int ret;

  ret = send_message(221,context);
  {
    const char * groupname = NULL;
    wzd_user_t * user;
    const char * remote_host;
    struct hostent *h;
    char inet_str[256];

    user = GetUserByID(context->userid);

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
  context->exitclient=1;
  /* check if pending xfers */

  return E_OK;
}

/*************** do_rest *****************************/
int do_rest(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  int ret;
  u64_t ull;
  char *ptr;

  if (!arg) {
    ret = send_message_with_args(501,context,"Invalid REST marker");
    return E_PARAM_INVALID;
  }
  ull = strtoull(str_tochar(arg), &ptr, 0);
  if (ptr==str_tochar(arg) || *ptr!='\0')
  {
    ret = send_message_with_args(501,context,"Invalid REST marker");
    return E_PARAM_INVALID;
  } else {
    char buf[256];
    snprintf(buf,256,"Restarting at %" PRIu64 ". Send STORE or RETRIEVE.",ull);
    ret = send_message_with_args(350,context,buf);
    context->resume = ull;
  }
  return E_OK;
}

/*************** do_rnfr *****************************/
int do_rnfr(wzd_string_t *name, wzd_string_t *filename, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if (!user || !(user->userperms & RIGHT_RNFR)) {
    ret = send_message_with_args(550,context,"RNFR","permission denied");
    return E_FILE_NOEXIST;
  }


  if (!filename || strlen(str_tochar(filename))==0 || strlen(str_tochar(filename))>=WZD_MAX_PATH || checkpath_new(str_tochar(filename),path,context)) {
    ret = send_message_with_args(550,context,"RNFR","file does not exist");
    return E_FILE_NOEXIST;
  }

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
  }

  context->current_action.token = TOK_RNFR;
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);
  context->current_action.current_file = -1;
  context->current_action.bytesnow = 0;
  context->current_action.tm_start = time(NULL);

  ret = send_message_with_args(350,context,"OK, send RNTO");
  return E_OK;
}

/*************** do_rnto *****************************/
int do_rnto(wzd_string_t *name, wzd_string_t *filename, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if (!user || !(user->userperms & RIGHT_RNFR)) {
    ret = send_message_with_args(550,context,"RNTO","permission denied");
    return E_FILE_NOEXIST;
  }


  if (!filename || strlen(str_tochar(filename))==0 || strlen(str_tochar(filename))>=WZD_MAX_PATH) {
    ret = send_message_with_args(553,context,"RNTO","wrong file name ?");
    return E_PARAM_INVALID;
  }
  if (context->current_action.token != TOK_RNFR) {
    ret = send_message_with_args(553,context,"RNTO","send RNFR before !");
    return E_PARAM_INVALID;
  }

  checkpath_new(str_tochar(filename),path,context);
  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Go away bastard");
    return E_FILE_FORBIDDEN;
  }
  context->current_action.token = TOK_UNKNOWN;
  context->current_action.current_file = -1;
  context->current_action.bytesnow = 0;

  ret = file_rename(context->current_action.arg,path,context);
  if (ret) {
    ret = send_message_with_args(550,context,"RNTO","command failed");
  } else {
    ret = send_message_with_args(250,context,"RNTO"," command OK");
    context->idle_time_start = time(NULL);
  }
  return E_OK;
}

/*************** do_type *****************************/
int do_type(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;

  context->resume = 0;
  if (!param) {
    ret = send_message_with_args(501,context,"Invalid TYPE marker");
    return E_PARAM_INVALID;
  }
  if (strcasecmp(str_tochar(param),"I")==0)
    context->current_xfer_type = BINARY;
  else if (strcasecmp(str_tochar(param),"A")==0)
    context->current_xfer_type = ASCII;
  else {
    ret = send_message(502,context);
    return E_PARAM_INVALID;
  }
  ret = send_message_with_args(200,context,"Command okay");
  return E_OK;
}

/*************** do_xcrc *****************************/
int do_xcrc(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  const char * ptr;
  char * ptest;
  struct statbuf s;
  int ret;
  unsigned long crc = 0;
  unsigned long startpos = 0;
  unsigned long length = (unsigned long)-1;
  const char *param;

  if (!str_checklength(arg,1,WZD_MAX_PATH-1)) {
    ret = send_message_with_args(501,context,"Syntax error");
    return E_PARAM_INVALID;
  }
  param = str_tochar(arg);

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
      return E_PARAM_INVALID;
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
        return E_PARAM_INVALID;
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

  if (!checkpath_new(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return E_FILE_FORBIDDEN;
    }


    if (fs_stat(path,&s)==0) {
      ret = calc_crc32(path,&crc,startpos,length);
      snprintf(buffer,1024,"%lX",crc);
/*      snprintf(buffer,1024,"%d %lX\r\n",250,crc);*/
/*      ret = send_message_raw(buffer,context);*/
      ret = send_message_with_args(250,context,buffer,"");
      return E_OK;
    }
  }
  ret = send_message_with_args(550,context,"XCRC","File inexistant or no access ?");
  return E_FILE_NOEXIST;
}

/*************** do_xmd5 *****************************/
int do_xmd5(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  const char * ptr;
  char * ptest;
  struct statbuf s;
  int ret;
  unsigned char crc[16];
  unsigned char md5str[33];
  unsigned long startpos = 0;
  unsigned long length = (unsigned long)-1;
  unsigned int i;
  const char *param;

  if (!str_checklength(arg,1,WZD_MAX_PATH-1)) {
    ret = send_message_with_args(501,context,"Syntax error");
    return E_PARAM_INVALID;
  }
  param = str_tochar(arg);

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
      return E_PARAM_INVALID;
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
        return E_PARAM_INVALID;
      } else { /* optional: read start checksum */
        ptr = ptest;
        strtomd5((char*)ptr,&ptest,crc);
        if (!ptest || ptest == ptr)
          memset(crc,0,16);
      }
    } else
      startpos = 0;
    param = buffer;
  }

  if (!checkpath_new(param,path,context)) {
    if (path[strlen(path)-1]=='/')
      path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
    if (is_hidden_file(path)) {
      ret = send_message_with_args(501,context,"Go away bastard");
      return E_FILE_FORBIDDEN;
    }


    if (fs_stat(path,&s)==0) {
      ret = calc_md5(path,crc,startpos,length);
      for (i=0; i<16; i++)
        snprintf(md5str+i*2,3,"%02x",crc[i]);
      ret = send_message_with_args(250,context,md5str,"");
      return E_OK;
    }
  }
  ret = send_message_with_args(550,context,"XMD5","File inexistant or no access ?");
  return E_FILE_NOEXIST;
}

/*************** do_pass *****************************/

/* return E_OK if ok, E_PASS_REJECTED if wrong pass, E_LOGIN_NO_HOME if ok but homedir does not exist */
int do_pass(const char *username, const char * pass, wzd_context_t * context)
{
/*  char buffer[4096];*/
  int ret;
  wzd_user_t * user;

  user = NULL;

  ret = backend_validate_pass(username,pass,user,&context->userid);
  if (ret) {
    /* pass was not accepted */
    return E_PASS_REJECTED;
  }

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

  me = NULL;

  ret = backend_validate_login(username,me,&context->userid);
  if (ret) return E_USER_REJECTED;

  me = GetUserByID(context->userid);
  if (!me) return E_USER_IDONTEXIST;

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
    ListElmt * elmnt;
    wzd_context_t * loop_context;
    int count=0;
    for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
    {
      loop_context = list_data(elmnt);
      if (loop_context && loop_context->magic == CONTEXT_MAGIC && context->userid == loop_context->userid)
        count++;
    } /* for all contexts */

    /* we substract 1, because the current login attempt is counted */
    count--;

/*    out_err(LEVEL_CRITICAL,"NUM_logins: %d\n",count);*/

    if (count >= me->num_logins) return E_USER_NUMLOGINS;
    /* >= and not ==, because it two attempts are issued simultaneously, count > num_logins ! */
  }

  /* foreach group of user, check num_logins */
  {
    ListElmt * elmnt;
    wzd_context_t * loop_context;
    unsigned int i,j,k;
    wzd_group_t * group;
    wzd_user_t * user;
    unsigned int * num_logins;

    num_logins = malloc(me->group_num * sizeof(unsigned int));
    memset(num_logins,0,me->group_num*sizeof(int));
    /* try to do it in one pass only */
    /* we build the same tab as me->groups, containing the counters */
    for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
    {
      loop_context = list_data(elmnt);
      if (loop_context && loop_context->magic == CONTEXT_MAGIC) {
        user = GetUserByID(loop_context->userid);
        if (!user) {
          /* this can happen if a user disconnects while iterating list */
          continue;
        }
        for (j=0; j<user->group_num; j++)
          for (k=0; k<me->group_num; k++)
            if (user->groups[j] == me->groups[k])
              num_logins[ k ]++;
      }
    }
    /* checks num_logins for all groups */
    for (i=0; i<me->group_num; i++)
    {
      group = GetGroupByID( me->groups[i] );
      if (group && group->num_logins
          && (num_logins[i]>group->num_logins))
        /* > and not >= because current login attempt is counted ! */
      {
        free(num_logins);
        return E_GROUP_NUMLOGINS; /* user has reached group max num_logins */
      }
    }
    free(num_logins);
  }

  return E_OK;
}

/*************** do_help *****************************/
int do_help(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  /* TODO maybe add HELP SITE? */
  send_message_with_args(214,context);

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

  user = GetUserByID(context->userid);

  if (!user) return E_USER_IDONTEXIST;

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
  int reject_nonexistant=1;
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  int tls_ok=0;
#endif
  int command;

  if (chtbl_lookup((CHTBL*)mainConfig->htab, "reject_unknown_users", (void**)&ptr) == 0)
  {
    if (ptr && strcmp(ptr,"0")==0)
      reject_nonexistant = 0;
  }

  *username = '\0';

  context->state = STATE_LOGGING;

  while (1) {
    /* wait response */
    ret = (context->read_fct)(context->controlfd,buffer,BUFFER_LEN,0,HARD_XFER_TIMEOUT,context);

    if (ret == 0) {
      out_err(LEVEL_FLOOD,"Connection closed or timeout (socket %d)\n",context->controlfd);
      return 1;
    }
    if (ret==-1) {
      out_err(LEVEL_FLOOD,"Error reading client response (socket %d)\n",context->controlfd);
      return 1;
    }

    /* this replace the memset (bzero ?) some lines before */
    buffer[ret] = '\0';

    if (buffer[0]=='\0') continue;

    {
      size_t length = strlen(buffer);
      while (length > 0 && (buffer[length-1]=='\r' || buffer[length-1]=='\n'))
        buffer[length-- -1] = '\0';
      strncpy(context->last_command,buffer,HARD_LAST_COMMAND_LENGTH-1);
    }

#ifdef DEBUG
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,buffer);
#endif

    /* strtok_r: to be reentrant ! */
    ptr = buffer;
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    switch (command) {
    case TOK_HELP:
        send_message_with_args(530,context,"Login with USER and PASS");
        break;
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
        if (!reject_nonexistant)
          break;
        ret = send_message_with_args(421,context,"User rejected");
        return 1;
      case E_USER_NUMLOGINS: /* too many logins */
        ret = send_message_with_args(421,context,"Too many connections with your login");
        return 1;
      case E_USER_CLOSED: /* site closed */
        ret = send_message_with_args(421,context,"Site is closed, try again later");
        return 1;
      case E_USER_IDONTEXIST: /* i don't exist, probably a problem with backend */
        ret = send_message_with_args(501,context,"Mama says I don't exist ! (problem with backend ?)");
        return 1;
      case E_GROUP_NUMLOGINS: /* too many logins for group */
        ret = send_message_with_args(421,context,"Too many connections for your group");
        return 1;
      }
      /* validate ip for user */
      ret = do_user_ip(token,context);
      if (reject_nonexistant && ret) { /* user was not accepted */
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
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
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
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
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
      {
        wzd_string_t * str = STR("feat");
        ret = do_print_message(str,NULL,context);
        str_deallocate(str);
      }
      break;
    case TOK_OPTS:
      {
        wzd_string_t *s1, *s2;
        token = strtok_r(NULL,"\r\n",&ptr);
        s1 = STR("opts");
        s2 = STR(token);
        ret = do_opts(s1,s2,context);
        str_deallocate(s1);
        str_deallocate(s2);
      }
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
static int do_login(wzd_context_t * context)
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
/** @brief Client main loop
 *
 * Calls do_login(context) to handle the login, and then enters the main
 * loop.
 *
 * Each loop consist of checking if the control connection is ready for
 * reading, and if data connection is ready for reading/writing. If both
 * are ready, the control connection is always handled first.
 * Data are handled in the separate function data_execute().
 *
 * Control data are first translated to current charset if needed, then the
 * first token is parsed and sent to commands_find() to identify the command.
 *
 * The exit is done using client_die().
 */
void * clientThreadProc(void *arg)
{
  struct timeval tv;
  fd_set fds_r,fds_w,efds;
  wzd_context_t * context;
  char *buffer = NULL;
  int save_errno;
  fd_t sockfd;
  int ret;
  wzd_user_t * user;
  wzd_command_t * command;
  wzd_string_t * command_buffer;
  wzd_string_t * token;
#ifndef _MSC_VER
  int oldtype;
#endif

  context = arg;
  sockfd = context->controlfd;
  context->last_file.name[0] = '\0';
  context->last_file.token = TOK_UNKNOWN;
  context->data_buffer = wzd_malloc(mainConfig->data_buffer_length);

#ifdef _MSC_VER
  context->thread_id = GetCurrentThreadId();
#else
  context->thread_id = pthread_self();
#endif

  out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);
#ifndef _MSC_VER
#ifdef WZD_MULTITHREAD
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);
  pthread_cleanup_push((void (*) (void *))client_die, (void *) context);
#endif /* WZD_MULTITHREAD */
#endif

  ret = do_login(context);

  user = GetUserByID(context->userid);

  if (ret) { /* USER not logged in */
    const char * groupname = NULL;
    const char * remote_host;
    struct hostent *h;
    char inet_str[256];

    if (user && user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
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
        user ? user->username : "unknown",
        (groupname)?groupname:"No Group",
        user ? user->tagline : "unknown"
        );
#ifdef WZD_MULTITHREAD
    client_die(context);
#endif /* WZD_MULTITHREAD */
    return NULL;
  }

  context->state = STATE_COMMAND;

  {
    const char * groupname = NULL;
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
  send_message_raw("230-command ok\r\n",context);
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
  context->exitclient=0;
  context->idle_time_start = time(NULL);

  while (!context->exitclient) {
#ifdef DEBUG
    if (GetMyContext() != context)
    {
      out_err(LEVEL_CRITICAL,"GetMyContext does not match context !\n");
      out_err(LEVEL_CRITICAL,"GetMyContext %p\n",GetMyContext());
      out_err(LEVEL_CRITICAL,"context      %p\n",context);
    }
    if (!context->magic == CONTEXT_MAGIC || sockfd != context->controlfd)
    {
      out_err(LEVEL_CRITICAL,"Omar m'a tuer !\n");
      out_err(LEVEL_CRITICAL,"sock %d\n",sockfd);
    }
#endif /* DEBUG */
    save_errno = 666;
    /* 1. read */
    FD_ZERO(&fds_r);
    FD_ZERO(&fds_w);
    FD_ZERO(&efds);
    /* set control fd */
#ifdef DEBUG
    if (sockfd == (fd_t)-1 || !fd_is_valid(sockfd)) {
      fprintf(stderr,"Trying to set invalid sockfd (%d) %s:%d\n",
          sockfd,__FILE__,__LINE__);
      context->exitclient=1;
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
        context->exitclient = 1;
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
      /** \todo should be remove data descriptors and so ? */
    }

    if (!FD_ISSET(sockfd,&fds_r)) {
      /* we check for data iff control is not set - control is prior */
      if (ret==1) {
        if (context->current_action.token == TOK_UNKNOWN) {
          /* we are receiving / sending data without RETR/STOR */
          continue;
        }
        /* we have data ready */
        ret = data_execute(context,user,&fds_r,&fds_w);
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
      context->exitclient=1;
      break;
    }

    /* this replace the memset (bzero ?) some lines before */
    buffer[ret] = '\0';

    if (buffer[0]=='\0') continue;

    command_buffer = STR(buffer);

    str_trim_right(command_buffer);
    wzd_strncpy(context->last_command,str_tochar(command_buffer),HARD_LAST_COMMAND_LENGTH-1);

/*    context->idle_time_start = time(NULL);*/
#ifdef DEBUG
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,str_tochar(command_buffer));
#endif

    /* 2. get next token */
    token = str_tok(command_buffer, " \t\r\n");

    if (!token)
      command = NULL;
    else
    {
      command = commands_find(mainConfig->commands_list,token);
    }

    if (command) {
      /* if command is SITE,
       * get next command, and strcat it with a _
       */
      if (command->id == TOK_SITE) {
        wzd_string_t * site_command;
        wzd_command_t * command_real;

        site_command = str_tok(command_buffer," \t");
        if (site_command) {
          str_append(str_append(token,"_"),str_tochar(site_command));
          str_tolower(token);
          str_deallocate(site_command);
        }

        command_real = commands_find(mainConfig->commands_list,token);
        if (command_real) command = command_real;

        /** For SITE commands, the default permission (if not specified)
         * is to ALLOW users to use command, unless restricted !
         */
        if (command_real && commands_check_permission(command_real,context)) {
          ret = send_message_with_args(501,context,"Permission Denied");
          str_deallocate(token);
          str_deallocate(command_buffer);
          continue;
        }
      }
      /** For base FTP commands, the default permission (if not specified)
       * is to ALLOW users to use command, unless restricted !
       */
      if (command->perms && commands_check_permission(command,context)) {
        ret = send_message_with_args(501,context,"Permission Denied");
        str_deallocate(token);
        str_deallocate(command_buffer);
        continue;
      }
      ret = (*(command->command))(token,command_buffer,context);
      str_deallocate(token);
      str_deallocate(command_buffer);
      continue;
    } else {
      ret = send_message(202,context);
    }

    str_deallocate(token);
    str_deallocate(command_buffer);

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

  return NULL;
}


