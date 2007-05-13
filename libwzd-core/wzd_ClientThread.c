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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <sys/utime.h>

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h> /* gethostbyaddr */

#endif /* WIN32 */

/** \todo XXX FIXME remove this line and use correct types !!!!
 * this is used to convert char* to struct in6_addr
 */
#define PORCUS_CAST(x) ( ((struct in6_addr*)(x)) )

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_UTIME_H
# include <utime.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <pthread.h>
#endif

#ifndef HAVE_STRTOK_R
# include "libwzd-base/wzd_strtok_r.h"
#endif

#include "wzd_structs.h"

#include "wzd_fs.h"
#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_mod.h"
#include "wzd_data.h"
#include "wzd_messages.h"
#include "wzd_vfs.h"
#include "wzd_configfile.h"
#include "wzd_crc32.h"
#include "wzd_events.h"
#include "wzd_file.h"
#include "wzd_group.h"
#include "wzd_libmain.h"
#include "wzd_list.h"
#include "wzd_login.h"
#include "wzd_perm.h"
#include "wzd_protocol.h"
#include "wzd_ratio.h"
#include "wzd_section.h"
#include "wzd_site.h"
#include "wzd_string.h"
#include "wzd_socket.h"
#include "wzd_threads.h"
#include "wzd_tls.h"
#include "wzd_user.h"
#include "wzd_utf8.h"
#include "wzd_ClientThread.h"

#include <libwzd-auth/wzd_base64.h>
#include <libwzd-auth/wzd_md5.h>

#include "wzd_debug.h"

#define TELNET_SYNCH    242
#define TELNET_IP       244

#define BUFFER_LEN	4096


static int test_fxp(const char * remote_ip, net_family_t family, wzd_context_t * context);

static int fxp_is_denied(wzd_user_t * user);

static struct thread_key_t * _key_context = NULL;


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

/***************** client_die ************************/
/** \brief Cleanup code
 *
 * Called whenever a connection with a client is closed (for any reason).
 * Closes all files/sockets.
 */
void client_die(wzd_context_t * context)
{
#ifdef DEBUG
  out_log(LEVEL_FLOOD,"client_die(context = %p)\n",context);
#endif

  if (context == NULL) return;

  if (context->magic != CONTEXT_MAGIC) {
#ifdef DEBUG
out_err(LEVEL_HIGH,"clientThread: context->magic is invalid at exit\n");
#endif
    return;
  }

  /* close opened files */
  if (context->current_action.current_file != (fd_t)-1) {
    data_end_transfer( (context->current_action.token == TOK_STOR) /* is_upload */, 0 /* end_ok */, context);
  }

  {
    wzd_user_t * user = GetUserByID(context->userid);
    wzd_string_t * event_args = NULL;

    if (user) {
      event_args = STR(user->username);
      event_send(mainConfig->event_mgr, EVENT_LOGOUT, 0, event_args, context);
      str_deallocate(event_args);
    }
  }


  out_log(LEVEL_INFO,"Client dying (socket %d)\n",context->controlfd);
  /* close existing pasv connections */
  if (context->pasvsock != (fd_t)-1) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
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

  wzd_tls_free(_key_context);
  _key_context = NULL;

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

  WZD_ASSERT( user != NULL);
  if (user == NULL) return 0;

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
      {
        wzd_string_t * event_args = str_allocate();
        str_sprintf(event_args,"%s %s",user->username,context->current_action.arg);
        event_send(mainConfig->event_mgr, EVENT_POSTUPLOAD, 0, event_args, context);
        str_deallocate(event_args);
      }
      file_close(context->current_action.current_file,context);
      FD_UNREGISTER(context->current_action.current_file,"Client file (RETR or STOR)");
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
        int af = (context->family == WZD_INET6) ? AF_INET6 : AF_INET;
        inet_str[0] = '\0';
        inet_ntop(af,context->hostip,inet_str,sizeof(inet_str));
        log_message("TIMEOUT","%s (%s) timed out after being idle %d seconds",
            user->username,
            inet_str,
            (int)delay
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
    if (gptr && gptr->max_idle_time > 0) {
      if (delay > (time_t)gptr->max_idle_time) {
        /* TIMEOUT ! */
        send_message_with_args(421,context,"Timeout, closing connection");
        {
          char inet_str[256];
          int af = (context->family == WZD_INET6) ? AF_INET6 : AF_INET;
          inet_str[0] = '\0';
          inet_ntop(af,context->hostip,inet_str,sizeof(inet_str));
          log_message("TIMEOUT","%s (%s) timed out after being idle %d seconds",
              user->username,
              inet_str,
              (int)delay
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
  char allowed[WZD_MAX_PATH],path[WZD_MAX_PATH], * ptr;
  fs_filestat_t buf;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_CWD) ) return E_NOPERM;

  if (!wanted_path) return E_WRONGPATH;
  ret = checkpath_new(wanted_path,path,context);
  if (ret) return ret;
  snprintf(allowed,WZD_MAX_PATH,"%s/",user->rootpath);

  /* deny retrieve to permissions file */
  if (is_hidden_file(path))
    return E_FILE_FORBIDDEN;

  REMOVE_TRAILING_SLASH(path);

  if (!fs_file_stat(path,&buf)) {
    if (S_ISDIR(buf.mode)) {
      char buffer[WZD_MAX_PATH], buffer2[WZD_MAX_PATH];
      if (wanted_path[0] == '/') { /* absolute path */
        wzd_strncpy(buffer,wanted_path,WZD_MAX_PATH);
      } else {
        wzd_strncpy(buffer,context->currentpath,WZD_MAX_PATH);
        if (buffer[strlen(buffer)-1] != '/')
          strlcat(buffer,"/",WZD_MAX_PATH);
        strlcat(buffer,wanted_path,WZD_MAX_PATH);
      }
      stripdir(buffer,buffer2,WZD_MAX_PATH-1);
/*out_err(LEVEL_INFO,"DIR: %s NEW DIR: %s\n",buffer,buffer2);*/
      wzd_strncpy(context->currentpath,buffer2,WZD_MAX_PATH-1);
    }
    else return E_NOTDIR;
  }
  else return E_FILE_NOEXIST;

  ptr = stripdir(context->currentpath,path,sizeof(path));
  if (ptr) {
    wzd_strncpy(context->currentpath,path,WZD_MAX_PATH-1);
  }

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
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  {
    if (user && strchr(user->flags,FLAG_TLS_DATA) && context->tls_data_mode != TLS_PRIV) {
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
      FD_UNREGISTER(context->pasvsock,"Client PASV socket");
      socket_close(context->pasvsock);
      context->pasvsock = -1;
      send_message_with_args(501,context,"PASV timeout");
      return -1;
    }
  } while (!FD_ISSET(sock,&fds));

  sock = socket_accept(context->pasvsock, remote_host, &remote_port, &context->datafamily);
  if (sock == (fd_t)-1) {
    out_err(LEVEL_FLOOD,"accept failed to client %s:%d.\n",__FILE__,__LINE__);
    out_err(LEVEL_FLOOD,"errno is %d:%s.\n",errno,strerror(errno));
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    send_message_with_args(501,context,"PASV timeout");
    return -1;
  }

  if (fxp_is_denied(user) && test_fxp((const char*)remote_host,context->datafamily,context) != 0) {
    memset(context->dataip,0,16);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
    socket_close(context->pasvsock);
    context->pasvsock = -1;
    socket_close(sock);
    sock = -1;
    send_message_with_args(501,context,"FXP not allowed");
    return -1;
  }

  /** \todo check destination port for security: >= 1024 */


#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->tls_data_mode == TLS_PRIV) {
    int ret;
    ret = tls_init_datamode(sock, context);
    if (ret) {
      out_err(LEVEL_INFO,"WARNING TLS data negotiation failed with client %s:%d.\n",__FILE__,__LINE__);
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
    if (user && strchr(user->flags,FLAG_TLS_DATA) && context->tls_data_mode != TLS_PRIV) {
      send_message_with_args(501,context,"Your class must use encrypted data connections");
      return -1;
    }
  }

  if (context->datafamily == WZD_INET4)
  {

    /** \todo TODO XXX FIXME check ipv4 IP at this point ! */

    ret = send_message(150,context); /* about to open data connection */
    sock = socket_connect(context->dataip,context->datafamily,context->dataport,context->localport-1,context->controlfd,HARD_XFER_TIMEOUT);
    if (sock == -1) {
      ret = send_message(425,context);
      return -1;
    }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    if (context->tls_data_mode == TLS_PRIV) {
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
    sock = socket_connect(context->dataip,context->datafamily,context->dataport,context->localport-1,context->controlfd,HARD_XFER_TIMEOUT);
    if (sock == -1) {
      out_log(LEVEL_FLOOD,"Error establishing PORT connection: %s (%d)\n",strerror(errno),errno);
      ret = send_message(425,context);
      return -1;
    }

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    if (context->tls_data_mode == TLS_PRIV) {
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
  if (context->tls_data_mode == TLS_CLEAR)
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
  enum list_type_t listtype;

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_LIST) ) {
    ret = send_message_with_args(550,context,"LIST","No access");
    return E_NOPERM;
  }

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

    wzd_strncpy(cmd,param,sizeof(cmd));
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
    ret = send_message_with_args(501,context,"Too many / in the path - is it a joke?");
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
  if ((ret = checkpath_new(cmd,path,context)) || !strncmp(mask,"..",2)) {
    switch (ret) {
    case E_NOTDIR:
      /* return 501 for syntax error, see rfc3659 at section 7.2.1 */
      ret = send_message_with_args(501,context,"Not a directory");
      break;
    case E_WRONGPATH:
      ret = send_message_with_args(550,context,"LIST","Invalid path");
      break;
    case E_FILE_NOEXIST:
      ret = send_message_with_args(550,context,"LIST","No such file or directory (no access?)");
      break;
    case E_FILE_FORBIDDEN:
    case E_NOPERM:
      ret = send_message_with_args(550,context,"LIST","Negative on that, Houston (access denied)");
      break;
    default:
      ret = send_message_with_args(501,context,"LIST failed (syntax error?)");
      break;
    }
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
  if (context->tls_data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = socket_close(sock);
  FD_UNREGISTER(sock,"Client LIST socket");
  context->datafd = -1;
  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;

  return E_OK;
}


/*************** do_mlsd *****************************/

int do_mlsd(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  fd_t sock;
  char * path;

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_LIST) ) {
    ret = send_message_with_args(550,context,"MLSD","No access");
    return E_NOPERM;
  }

  if (context->pasvsock == (fd_t)-1 && context->dataport == 0)
  {
    ret = send_message_with_args(501,context,"No data connection available.");
    return E_NO_DATA_CTX;
  }
  if (context->state == STATE_XFER) {
    ret = send_message(491,context);
    return E_XFER_PROGRESS;
  }

  path = wzd_malloc(WZD_MAX_PATH+1);
  if (ret = checkpath_new(str_tochar(param),path,context)) {
    switch (ret) {
    case E_NOTDIR:
      /* return 501 for syntax error, see rfc3659 at section 7.2.1 */
      ret = send_message_with_args(501,context,"Not a directory");
      break;
    case E_WRONGPATH:
      ret = send_message_with_args(550,context,"MLSD","Invalid path");
      break;
    case E_FILE_NOEXIST:
      ret = send_message_with_args(550,context,"MLSD","No such file or directory (no access?)");
      break;
    case E_FILE_FORBIDDEN:
    case E_NOPERM:
      ret = send_message_with_args(550,context,"MLSD","Negative on that, Houston (access denied)");
      break;
    default:
      ret = send_message_with_args(501,context,"MLSD failed (syntax error?)");
      break;
    }
    wzd_free(path);
    return E_PARAM_INVALID;
  }

  REMOVE_TRAILING_SLASH(path);

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
  FD_REGISTER(sock,"Client MLSD socket");

  context->state = STATE_XFER;



  if (!mlsd_directory(path,sock,list_callback,context))
    ret = send_message(226,context);
  else
    ret = send_message_with_args(501,context,"Error processing list");


  wzd_free(path);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->tls_data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = socket_close(sock);
  FD_UNREGISTER(sock,"Client MLSD socket");
  context->datafd = -1;
  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;

  return E_OK;
}

/*************** do_mlst *****************************/

int do_mlst(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  char * path;
  char * str;

  user = GetUserByID(context->userid);

  /* stat has the same behaviour as LIST */
  if ( !(user->userperms & RIGHT_LIST) ) {
    ret = send_message_with_args(550,context,"MLST","No access");
    return E_NOPERM;
  }

  if (!param || strlen(str_tochar(param))==0)
  {
    ret = send_message_with_args(501,context,"Usage: MLST filename");
    return E_PARAM_BIG;
  }

  if (!str_checklength(param, 1, WZD_MAX_PATH-10))
  {
    ret = send_message_with_args(501,context,"Argument or parameter too big.");
    return E_PARAM_BIG;
  }

  context->state = STATE_COMMAND;

  path = wzd_malloc(WZD_MAX_PATH+1);
  if (ret = checkpath_new(str_tochar(param),path,context)) {
    switch (ret) {
      /* \todo enable MLST command to work on files and not just directories */
    case E_NOTDIR:
      /* return 501 for syntax error, see rfc3659 at section 7.2.1 */
      ret = send_message_with_args(501,context,"Not a directory");
      break;
    case E_WRONGPATH:
      ret = send_message_with_args(550,context,"MLST","Invalid path");
      break;
    case E_FILE_NOEXIST:
      ret = send_message_with_args(550,context,"MLST","No such file or directory (no access?)");
      break;
    case E_FILE_FORBIDDEN:
    case E_NOPERM:
      ret = send_message_with_args(550,context,"MLST","Negative on that, Houston (access denied)");
      break;
    default:
      ret = send_message_with_args(501,context,"MLST failed (syntax error?)");
      break;
    }
    wzd_free(path);
    return E_PARAM_INVALID;
  }

  REMOVE_TRAILING_SLASH(path);

  if ( (str = mlst_single_file(path, context)) == NULL) {
    ret = send_message_with_args(501,context,"Error occurred");
    wzd_free(path);
    return E_PARAM_INVALID;
  }

  strcat(str,"\r\n"); /* TODO check size */


  {
    wzd_string_t * buffer = str_allocate();
    str_sprintf(buffer,"250- Listing %s\r\n",str_tochar(param));
    send_message_raw(str_tochar(buffer),context);
    str_deallocate(buffer);
  }

  send_message_raw(str,context);

  ret = send_message_raw("250 End\r\n",context);

  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;

  wzd_free(path);
  wzd_free(str);

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
  if (strncasecmp(ptr,"MLST",4)==0)
  {
    /** \todo XXX FIXME implement options support for MLST */
    ret = send_message_with_args(200, context, "MLST OPTS Type;Size;Modify;Perm;UNIX.mode;");
    return 0;
  } /* MLST */

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
  enum list_type_t listtype;
  tls_data_mode_t old_data_mode;

  user = GetUserByID(context->userid);

  /* stat has the same behaviour as LIST */
  if ( !(user->userperms & RIGHT_LIST) ) {
    ret = send_message_with_args(550,context,"LIST","No access");
    return E_NOPERM;
  }


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

    wzd_strncpy(cmd,param,sizeof(cmd));
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
    ret = send_message_with_args(501,context,"Too many / in the path - is it a joke?");
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
    ret = send_message_with_args(501,context,"Invalid filter/path");
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
    ret = send_message_with_args(550,context,"STAT","No access");
    wzd_free(path);
    return E_NOPERM;
  }

  sock = context->controlfd;

  if (strlen(mask)==0) strcpy(mask,"*");

  /* \todo XXX FIXME horrible workaround to avoid sending clear data inside ssl stream */
  old_data_mode = context->tls_data_mode;
  context->tls_data_mode = (context->connection_flags & CONNECTION_TLS) ? TLS_PRIV : TLS_CLEAR;

  send_message_raw("213-Status of .:\r\n",context);
  send_message_raw("total 0\r\n",context);
  if (list(sock,context,listtype,path,mask,list_callback))
    ret = send_message_raw("213 End of Status\r\n",context);
  else
    ret = send_message_raw("213 Error processing list\r\n",context);

  context->idle_time_start = time(NULL);
  context->state = STATE_UNKNOWN;
  context->tls_data_mode = old_data_mode;

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
    ret = send_message_with_args(501,context,"Invalid path");
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
    if (checkpath_new(cmd,path,context)) { ret = E_WRONGPATH; goto label_error_mkdir; }
    if (path[strlen(path)-1]!='/') strcat(path,"/");
    strlcat(path,param,WZD_MAX_PATH);
  } else {
    wzd_strncpy(cmd,param,WZD_MAX_PATH);
    ret = checkpath_new(cmd,path,context);
    if (ret != E_FILE_NOEXIST) { ret = E_WRONGPATH; goto label_error_mkdir; }
    if (path[strlen(path)-1]!='/') strcat(path,"/");
/*    if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';*/
  }
  REMOVE_TRAILING_SLASH(path);

  ret = checkpath_new(param,buffer,context);
  if (ret != E_FILE_NOEXIST) goto label_error_mkdir;

#if DEBUG
  if (ret || errno) {
    if (ret != E_FILE_NOEXIST)
      out_err(LEVEL_FLOOD,"Making directory '%s' (%d, %s %d %d)\n",buffer,ret,strerror(errno),errno,ENOENT);
    switch (ret) {
    case E_USER_IDONTEXIST: out_log(LEVEL_HIGH,"mkdir: user does not exist !\n"); break;
    case E_PARAM_NULL: out_log(LEVEL_HIGH,"mkdir: no input parameter\n"); break;
    case E_PARAM_BIG: out_log(LEVEL_HIGH,"mkdir: parameter too long\n"); break;
    case E_WRONGPATH: out_log(LEVEL_HIGH,"mkdir: wrong path\n"); break;
    case E_FILE_NOEXIST: break; /* not an error ! */
    case E_NOPERM: out_log(LEVEL_HIGH,"mkdir: no permission\n"); break;
    default:
      break;
    }
  }
  else
    out_err(LEVEL_FLOOD,"Making directory '%s' (%d)\n",buffer,ret);
#endif

  {
    wzd_string_t * event_args = str_allocate();
    str_sprintf(event_args,"%s %s",user->username,buffer);
    ret = event_send(mainConfig->event_mgr, EVENT_PREMKDIR, 0, event_args, context);
    str_deallocate(event_args);
  }

  if (ret != EVENT_OK && ret != EVENT_BREAK) {
    out_log(LEVEL_NORMAL, "MKDIR denied by hook (returned %d)\n", ret);
    ret = send_message_with_args(501,context,"MKDIR denied");
    return E_XFER_REJECTED;
  }


  if (buffer[strlen(buffer)-1]=='/')
    buffer[strlen(buffer)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    wzd_free(buffer);
    wzd_free(path);
    wzd_free(cmd);
    ret = send_message_with_args(553,context,"Forbidden!");
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
        out_err(LEVEL_FLOOD,"path [%s] does not match path-filter\n",ptr+1);
        ret = send_message_with_args(553,context,"Dirname does not match pathfilter");
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
    if (ret != E_NOPERM)
      out_err(LEVEL_FLOOD,"MKDIR returned %d (%s)\n",errno,strerror(errno));
    goto label_error_mkdir; /* keep current ret value for later use */
  } else {
    const char *groupname=NULL;
    if (user->group_num > 0) {
      groupname = GetGroupByID(user->groups[0])->groupname;
    }
    file_chown(buffer,user->username,groupname,context);

    /* send message header */
    send_message_raw("257- Command okay\r\n",context);
    {
      wzd_string_t * event_args = STR(buffer);
      event_send(mainConfig->event_mgr, EVENT_MKDIR, 257, event_args, context);
      str_deallocate(event_args);
    }
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
  if (ret == E_NOPERM)
    snprintf(buffer,WZD_MAX_PATH-1,"Could not create dir: permission denied");
  else
    snprintf(buffer,WZD_MAX_PATH-1,"Could not create dir '%s' (%d)",(param)?param:"(NULL)",ret);
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
  fs_filestat_t s;
  int ret;
  wzd_user_t * user;
  const char *param;

  if (!str_checklength(arg,1,WZD_MAX_PATH-1))
  {
    ret = send_message_with_args(501,context,"Invalid path");
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
    ret = send_message_with_args(553,context,"Forbidden!");
    return E_FILE_FORBIDDEN;
  }

  if (fs_file_lstat(path,&s)) { ret = E_FILE_NOEXIST; goto label_error_rmdir; }
  if (!S_ISDIR(s.mode)) {
    ret = send_message_with_args(553,context,"Not a directory");
    return E_NOTDIR;
  }

  /* check permissions */
  ret = file_rmdir(path,context);

  if (ret) {
    out_err(LEVEL_FLOOD,"RMDIR returned %d (%s)\n",errno,strerror(errno));
    ret = E_PARAM_INVALID; goto label_error_rmdir;
  } else {
    /* send message header */
    send_message_raw("258- Command okay\r\n",context);
    {
      wzd_string_t * event_args = str_allocate();
      str_sprintf(event_args,"%s %s",user->username,path);
      event_send(mainConfig->event_mgr, EVENT_RMDIR, 258, event_args, context);
      str_deallocate(event_args);
    }
    ret = send_message_with_args(258,context,param,"Removed");

    {
      const char *groupname=NULL;
      char tbuf[WZD_MAX_PATH], path[WZD_MAX_PATH];

      if (user->group_num > 0) {
        groupname = GetGroupByID(user->groups[0])->groupname;
      }

      if (param[0] != '/') {
        strcpy(tbuf,context->currentpath);
        strlcat(tbuf,"/",WZD_MAX_PATH);
        strlcat(tbuf,param,WZD_MAX_PATH);
      } else {
        strcpy(tbuf,param);
      }
      stripdir(tbuf,path,WZD_MAX_PATH-1);

      log_message("DELDIR","\"%s\" \"%s\" \"%s\" \"%s\"",
          path, /* ftp-absolute path */
          user->username,
          (groupname)?groupname:"No Group",
          user->tagline
          );
    }

  }

  context->idle_time_start = time(NULL);

  return E_OK;

label_error_rmdir:
  snprintf(buffer,WZD_MAX_PATH-1,"Could not delete dir '%s'",(param)?param:"(NULL)");
  send_message_with_args(553,context,buffer);
  return ret;
}

/*************** do_port *****************************/
int do_port(wzd_string_t *name, wzd_string_t *args, wzd_context_t * context)
{
  int a0,a1,a2,a3;
  unsigned int p1, p2;
  int ret;
  wzd_user_t * user;

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

  user = GetUserByID(context->userid);

  if (fxp_is_denied(user) && test_fxp((const char*)context->dataip,WZD_INET4,context) != 0) {
    memset(context->dataip,0,16);
    ret = send_message_with_args(501,context,"FXP not allowed");
    return E_NOPERM;
  }

  /** \todo check destination port for security: >= 1024 */

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
  unsigned char buffer[16];
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

  myip = getmyip(context->controlfd, context->family, buffer); /* FIXME use a variable to get pasv ip ? */

  if (mainConfig->pasv_ip[0] == 0) {
#if defined(IPV6_SUPPORT)
      if (IN6_IS_ADDR_V4MAPPED(PORCUS_CAST(myip)) )
        memcpy(pasv_bind_ip,myip+12,4);
      else
#endif /* IPV6_SUPPORT */
        memcpy(pasv_bind_ip,myip,4);
  } else {
#if defined(IPV6_SUPPORT)
    if (IN6_IS_ADDR_V4MAPPED(PORCUS_CAST(context->hostip)))
      offset = 12;
#endif
    /* do NOT send pasv_ip if used from private network */
    if (context->hostip[offset+0]==10 ||
      (context->hostip[offset+0] == 172 && context->hostip[offset+1] == 16) ||
      (context->hostip[offset+0] == 192 && context->hostip[offset+1] == 168 && context->hostip[offset+2] == 0) ||
      (context->hostip[offset+0] == 127 && context->hostip[offset+1] == 0 && context->hostip[offset+2] == 0 && context->hostip[offset+3] == 1))
    {
#if defined(IPV6_SUPPORT)
      if (IN6_IS_ADDR_V4MAPPED(PORCUS_CAST(myip)))
        memcpy(pasv_bind_ip,myip+12,4);
      else
#endif /* IPV6_SUPPORT */
        memcpy(pasv_bind_ip,myip,4);
    }
    else
#if defined(IPV6_SUPPORT)
      if (IN6_IS_ADDR_V4MAPPED(PORCUS_CAST(mainConfig->pasv_ip)))
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
    {
      /* Rather than loop again, bail out.  This avoids an infinite loop,
         which happens if pasvsock is bad for some reason.  pasvsock
         shouldn't be bad (that would be a bug), but there's no reason
         to make things worse and go into an infinite loop. */
      return E_NO_DATA_CTX;
    }
  }
  if (port < mainConfig->pasv_low_range || port > mainConfig->pasv_high_range)
  {
    out_log(LEVEL_HIGH, "PASV: found port out of range !! (%d not in [%d , %d])\n",
        port, mainConfig->pasv_low_range, mainConfig->pasv_high_range);
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
  myip = getmyip(context->controlfd, context->family, buffer); /* FIXME use a variable to get pasv ip ? */

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
  char * param, * orig_param;
  wzd_user_t * user;

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

  orig_param = param = strdup(str_tochar(arg));

  sep = *param++;
  net_prt = *param++;
  if ( (*param++) != sep || (net_prt != '1' && net_prt != '2') ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    free(orig_param);
    return E_PARAM_INVALID;
  }

  net_addr = param;
  while (*param && (*param) != sep ) param++;
  if ( !*param ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    free(orig_param);
    return E_PARAM_INVALID;
  }

  *param = '\0';
  param++;

  s_tcp_port = param;
  while (*param && (*param) != sep ) param++;
  if ( !*param || *param != sep ) {
    ret = send_message_with_args(501,context,"Invalid argument");
    free(orig_param);
    return E_PARAM_INVALID;
  }

  *param = '\0';

  tcp_port = strtoul(s_tcp_port,&ptr,0);
  if (*ptr) {
    ret = send_message_with_args(501,context,"Invalid port");
    free(orig_param);
    return E_PARAM_INVALID;
  }

  /* resolve net_addr to context->dataip */
  switch (net_prt) {
  case '1':
    if ( (ret=inet_pton(AF_INET,net_addr,&addr4)) <= 0 )
    {
      ret = send_message_with_args(501,context,"Invalid host");
      free(orig_param);
      return E_PARAM_INVALID;
    }
    memcpy(context->dataip,(const char *)&addr4.s_addr,4);
    context->datafamily = WZD_INET4;
    break;
  case '2':
    if ( (ret=inet_pton(AF_INET6,net_addr,&addr6)) <= 0 )
    {
      ret = send_message_with_args(501,context,"Invalid host");
      free(orig_param);
      return E_PARAM_INVALID;
    }
    memcpy(context->dataip,addr6.s6_addr,16);
    context->datafamily = WZD_INET6;
    break;
  default:
    ret = send_message_with_args(501,context,"Invalid protocol");
    free(orig_param);
    return E_PARAM_INVALID;
  }

  context->dataport = tcp_port;

  user = GetUserByID(context->userid);

  if (fxp_is_denied(user) && test_fxp((const char*)context->dataip,context->datafamily,context) != 0) {
    memset(context->dataip,0,16);
    ret = send_message_with_args(501,context,"FXP not allowed");
    free(orig_param);
    return E_NOPERM;
  }

  /** \todo check destination port for security: >= 1024 */

  free(orig_param);
  ret = send_message_with_args(200,context,"Command okay");
#else /* defined(IPV6_SUPPORT) */
  send_message(502,context);
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
  unsigned char buffer[16];

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

  myip = getmyip(context->controlfd, context->family, buffer); /* FIXME use a variable to get pasv ip ? */

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

  FD_REGISTER(context->pasvsock,"Client PASV socket");

  myip = getmyip(context->controlfd, context->family, buffer); /* FIXME use a variable to get pasv ip ? */

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
  connection_state_t restorestate;

  param = str_tochar(arg);
  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_RETR) ) {
    ret = send_message_with_args(550,context,"RETR","No access");
    return E_NOPERM;
  }

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

  /*
   * Ignore some checkpath_new errorst for the moment,
   * test_path will do this after the predownload hook runs
   * in case the hook changes something
   */
  ret = checkpath_new(param,path,context);

  if ((ret != 0) && (ret != E_NOPERM) && (ret != E_FILE_NOEXIST))
  {
    ret = send_message_with_args(501,context,"Invalid file name");
    return E_PARAM_INVALID;
  }

  /* we need to put context into TOK_RETR state before the hook runs
   * so that any cookie parsing in the hook works correctly
   */
  restorestate = context->current_action.token;
  context->current_action.token = TOK_RETR;
  strncpy(context->current_action.arg,path,HARD_LAST_COMMAND_LENGTH);


  {
    wzd_string_t * event_args = str_allocate();
    str_sprintf(event_args,"%s %s",user->username,path);
    ret = event_send(mainConfig->event_mgr, EVENT_PREDOWNLOAD, 0, event_args, context);
    str_deallocate(event_args);
  }

  if (ret != EVENT_OK && ret != EVENT_BREAK) {
    out_log(LEVEL_NORMAL, "Download denied by hook (returned %d)\n", ret);
    ret = send_message_with_args(501,context,"Download denied");
    context->current_action.token = restorestate;
    return E_XFER_REJECTED;
  }

  /* restore the context state in case we exit before downloading*/
  context->current_action.token = restorestate;

  if (test_path(path,context)) {
    ret = send_message_with_args(501,context,"Invalid file name");
    return E_PARAM_INVALID;
  }


  /* trailing / ? */
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1] = '\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Forbidden");
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

  if (CFG_GET_OPTION(mainConfig,CFG_OPT_EXPERIMENTAL)) {
    if (context->transfer_thread != NULL) {
      out_log(LEVEL_HIGH,"ERROR a transfer thread is already started\n");
      data_end_transfer(0 /* is_upload */, 0 /* end_ok */, context);
      ret = send_message(426,context);
      return E_XFER_PROGRESS;
    }
    context->is_transferring = 1;
    ret = data_start_thread_retr(context);
/*    ret = do_local_retr(context);*/
  }

  return E_OK;
}

/*************** do_stor *****************************/
/** \brief Store file on the FTP server
 *
 * Check permissions, open a data connection and stores data
 * in a file on the server. If the file does not exist, it is created,
 * otherwise it depends if a resume marker was received (see REST).
 *
 * The corresponding FTP commands are STOR (RFC959 p29) and APPE (RFC959 p29)
 */
int do_stor(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH],path2[WZD_MAX_PATH];
  int fd;
  u64_t bytesnow, byteslast;
  fd_t sock;
  int ret;
  wzd_user_t * user;
  const char *param;
  unsigned long open_flags;

  param = str_tochar(arg);

  user = GetUserByID(context->userid);

  if ( !(user->userperms & RIGHT_STOR) ) {
    ret = send_message_with_args(550,context,"STOR","No access");
    return E_NOPERM;
  }

/* TODO FIXME send all error or any in this function ! */
  /* we must have a data connection */
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

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Forbidden");
    return E_FILE_FORBIDDEN;
  }

  {
    wzd_string_t * event_args = str_allocate();
    str_sprintf(event_args,"%s %s",user->username,path);
    ret = event_send(mainConfig->event_mgr, EVENT_PREUPLOAD, 0, event_args, context);
    str_deallocate(event_args);
  }

  if (ret != EVENT_OK && ret != EVENT_BREAK) {
    out_log(LEVEL_NORMAL, "Upload denied by hook (returned %d)\n", ret);
    ret = send_message_with_args(501,context,"Upload denied");
    return E_XFER_REJECTED;
  }


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

  open_flags = O_WRONLY|O_CREAT;

  if ((fd=file_open(path,open_flags,RIGHT_STOR,context))==-1) {
    ret = send_message_with_args(501,context,"Nonexistant file or permission denied");
    return E_FILE_NOEXIST;
  }
  FD_REGISTER(fd,"Client file (STOR)");

  if (context->pasvsock == (fd_t)-1) { /* PORT ! */
    sock = waitconnect(context);
    if (sock == (fd_t)-1) {
      file_close(fd,context);
      FD_UNREGISTER(fd,"Client file (STOR)");
      /* note: reply is done in waitconnect() */
      return E_CONNECTTIMEOUT;
    }
  } else { /* PASV ! */
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

  /* set owner */
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

  context->current_ul_limiter.maxspeed = user->max_ul_speed;
  context->current_ul_limiter.bytes_transfered = 0;
#ifndef WIN32 /* FIXME VISUAL */
  gettimeofday(&context->current_ul_limiter.current_time,NULL);
#else
  _ftime(&context->current_ul_limiter.current_time);
#endif

  context->resume=0;
  context->idle_time_start = time(NULL);

  if (CFG_GET_OPTION(mainConfig,CFG_OPT_EXPERIMENTAL)) {
    if (context->transfer_thread != NULL) {
      out_log(LEVEL_HIGH,"ERROR a transfer thread is already started\n");
      data_end_transfer(0 /* is_upload */, 0 /* end_ok */, context);
      ret = send_message(426,context);
      return E_XFER_PROGRESS;
    }
    context->is_transferring = 1;
    ret = data_start_thread_stor(context);
/*    ret = do_local_stor(context);*/
  }

  return E_OK;
}

/*************** do_mdtm *****************************/
int do_mdtm(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH], tm[32];
  fs_filestat_t s;
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
      ret = send_message_with_args(501,context,"Forbidden");
      return E_FILE_FORBIDDEN;
    }

    if (fs_file_stat(path,&s)==0) {
      context->resume = 0L;
      strftime(tm,sizeof(tm),"%Y%m%d%H%M%S",gmtime(&s.mtime));
      ret = send_message_with_args(213,context,tm);
      return E_OK;
    }
  }
  ret = send_message_with_args(501,context,"File inexistent or no access?");
  return E_FILE_NOEXIST;
}

/*************** do_size *****************************/
int do_moda(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
#ifdef HAVE_STRPTIME
  extern char *strptime (__const char *__restrict __s,
    __const char *__restrict __fmt, struct tm *__tp);
#endif
  int ret, command_ok=0;
  char * facts, * fact, * value, * ptr;
  struct tm tm_atime, tm_mtime;
  struct utimbuf utime_buf = {0, 0};
  char * filename;
  char path[WZD_MAX_PATH];

  if (!param) {
    ret = send_message_with_args(501,context,"Invalid syntax");
    return E_PARAM_INVALID;
  }

  facts = strdup(str_tochar(param));
  filename = strstr(facts,"; ");
  if (!filename) {
    free(facts);
    ret = send_message_with_args(501,context,"Invalid syntax");
    return E_PARAM_INVALID;
  }
  filename++; /* skip ';' */
  *filename++ = '\0';

  if (checkpath_new(filename,path,context)) {
    free(facts);
    ret = send_message_with_args(501,context,"Invalid filename");
    return E_PARAM_INVALID;
  }
  if (path[strlen(path)-1]=='/')
    path[strlen(path)-1]='\0';

  /** \todo XXX open file to avoid race conditions */

  fact = strtok_r(facts,"=",&ptr);
  if (!fact) {
    free(facts);
    ret = send_message_with_args(501,context,"Invalid syntax");
    return E_PARAM_INVALID;
  }

  while (fact) {
    value = strtok_r(NULL,";",&ptr);
    if (!value) {
      free(facts);
      ret = send_message_with_args(501,context,"Invalid syntax");
      return E_PARAM_INVALID;
    }

    /* test 'fact' and make action */
    /** \todo XXX it would be a good idea to make 'atomic' modifications, or to lock file ! */

/**** accessed *******/
    if (strcmp(fact,"accessed")==0) {
      memset(&tm_atime,0,sizeof(struct tm));
      ptr=strptime(value,"%Y%m%d%H%M%S",&tm_atime);
      if (ptr == NULL || *ptr != '\0') {
        snprintf(path,WZD_MAX_PATH,"Invalid value for fact '%s', aborting",fact);
        ret = send_message_with_args(501,context,path);
        return E_PARAM_INVALID;
      }

      utime_buf.actime = mktime(&tm_atime);
      ret = utime(path,&utime_buf);

      if (ret) {
        snprintf(path,WZD_MAX_PATH,"Error in fact %s: '%s', aborting",fact,value);
        free(facts);
        ret = send_message_with_args(501,context,path);
        return E_PARAM_INVALID;
      }
      command_ok++;

    } else
/**** modify *******/
    if (strcmp(fact,"modify")==0) {
      memset(&tm_mtime,0,sizeof(struct tm));
      ptr=strptime(value,"%Y%m%d%H%M%S",&tm_mtime);
      if (ptr == NULL || *ptr != '\0') {
        snprintf(path,WZD_MAX_PATH,"Invalid value for fact '%s', aborting",fact);
        ret = send_message_with_args(501,context,path);
        return E_PARAM_INVALID;
      }

      utime_buf.modtime = mktime(&tm_mtime);
      ret = utime(path,&utime_buf);

      if (ret) {
        snprintf(path,WZD_MAX_PATH,"Error in fact %s: '%s', aborting",fact,value);
        free(facts);
        ret = send_message_with_args(501,context,path);
        return E_PARAM_INVALID;
      }
      command_ok++;

    } else
/**** unknown *******/
    {
      snprintf(path,WZD_MAX_PATH,"Unsupported fact '%s', aborting",fact);
      free(facts);
      ret = send_message_with_args(501,context,path);
      return E_PARAM_INVALID;
    }

    fact = strtok_r(NULL,"=",&ptr);
  }

  free(facts);

  if (command_ok)
    ret = send_message_with_args(200,context,"Command okay");
  else
    ret = send_message_with_args(501,context,"Not yet implemented");

  return E_PARAM_INVALID;
}

/*************** do_size *****************************/
int do_size(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  fs_filestat_t s;
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
      ret = send_message_with_args(501,context,"Forbidden");
      return E_FILE_FORBIDDEN;
    }


    if (fs_file_stat(path,&s)==0) {
      snprintf(buffer,1024,"%" PRIu64,s.size);
      ret = send_message_with_args(213,context,buffer);
      return E_OK;
    }
  }
  ret = send_message_with_args(501,context,"File inexistent or no access?");
  return E_FILE_NOEXIST;
}

/*************** do_abor *****************************/
/** \brief Abort current transfer
 *
 * Abort current service command and any associated transfer of data.
 * The command connection is not closed, but the data connection is closed.
 *
 * The corresponding FTP command is ABOR (RFC959 p30)
 */
int do_abor(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if (context->pasvsock != (fd_t)-1 && context->datafd != context->pasvsock) {
    socket_close(context->pasvsock);
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
    context->pasvsock=-1;
  }
  if (context->current_action.current_file != (fd_t)-1) {
    /* transfer aborted, we should send a 426 */
    ret = send_message(426,context);
    out_xferlog(context, 0 /* incomplete */);

    if (context->current_action.token == TOK_STOR || context->current_action.token == TOK_RETR) {
      data_end_transfer((context->current_action.token == TOK_STOR) ? 1:0 /* is_upload */, 0 /* end_ok */, context);
    }

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

  if (param == NULL) {
    param = "/";
  }
  /* avoir error if current is "/" and action is ".." */
  if (!strcmp("..",param)
      && ( !strcmp("/",context->currentpath)
         || ( (strlen(context->currentpath)<=3) && (context->currentpath[2]==':') ) )
      ) {
    ret = send_message_with_args(250,context,context->currentpath," now current directory.");
    return E_OK;
  }
  if ( (ret=do_chdir(param,context)) ) {
    switch (ret) {
    case E_NOTDIR:
      /* return 501 for syntax error, see rfc3659 at section 7.2.1 */
      ret = send_message_with_args(501,context,param?param:"(null)","Not a directory");
      break;
    case E_WRONGPATH:
      ret = send_message_with_args(550,context,param?param:"(null)","Invalid path");
      break;
    case E_FILE_NOEXIST:
      ret = send_message_with_args(550,context,param?param:"(null)","No such file or directory (no access?)");
      break;
    case E_FILE_FORBIDDEN:
    case E_NOPERM:
      ret = send_message_with_args(550,context,param?param:"(null)","Negative on that, Houston (access denied)");
      break;
    default:
      ret = send_message_with_args(501,context,param?param:"(null)","CWD failed (syntax error?)");
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
  fs_filestat_t s;
  u64_t file_size;
  wzd_user_t * user, * owner;

  if (!str_checklength(param,1,WZD_MAX_PATH-1)) {
    ret = send_message_with_args(501,context,"Syntax error");
    return E_PARAM_INVALID;
  }

  user = GetUserByID(context->userid);
  if (!user) {
    ret = send_message_with_args(501,context,"Mama says I don't exist!");
    return E_USER_IDONTEXIST;
  }

  if ( !(user->userperms & RIGHT_DELE) ) {
    ret = send_message_with_args(501,context,"Permission denied");
    return E_NOPERM;
  }

  if (checkpath_new(str_tochar(param),path,context)) {
    ret = send_message_with_args(501,context,"Permission denied or inexistant file");
    return E_FILE_NOEXIST;
  }

  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Forbidden");
    return E_FILE_FORBIDDEN;
  }

  if (fs_file_lstat(path,&s)) {
    /* non-existent file ? */
    ret = send_message_with_args(501,context,"File does not exist");
    return E_FILE_NOEXIST;
  }
  if (S_ISDIR(s.mode)) {
    ret = send_message_with_args(501,context,"This is a directory!");
    return E_ISDIR;
  }
  if (S_ISREG(s.mode))
    file_size = s.size;
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
    send_message_raw("250- Command okay\r\n",context);
    {
      wzd_string_t * event_args = STR(path);
      event_send(mainConfig->event_mgr, EVENT_DELE, 250, event_args, context);
      str_deallocate(event_args);
    }
    ret = send_message_with_args(250,context,"DELE"," command successful");

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

  ret = send_message_with_args(200,context,"Command okay");
  return E_OK;
}

/*************** do_print_message ********************/
int do_print_message(wzd_string_t *name, wzd_string_t *filename, wzd_context_t * context)
{
  int cmd;
  int ret;
  char buffer[WZD_BUFFER_LEN];
  wzd_string_t * str;

  cmd = identify_token(str_tochar(name));
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
/*************** do_pbsz *****************************/
int do_pbsz(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  const char *arg;

  arg = str_tochar(param);
  /** \todo TOK_BSZ: if user is NOT in TLS mode, insult him */
  /** \todo TOK_BSZ: use argument */
  ret = send_message_with_args(200,context,"PBSZ command okay");
  return E_OK;
}
#else
int do_pbsz(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  send_message(502,context);
  return E_PARAM_INVALID;
}
#endif

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
/*************** do_prot *****************************/
int do_prot(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  const char *arg;

  arg = str_tochar(param);
  /** \todo TOK_PROT: if user is NOT in TLS mode, insult him */
  if (strcasecmp("P",arg)==0)
    context->tls_data_mode = TLS_PRIV;
  else if (strcasecmp("C",arg)==0)
    context->tls_data_mode = TLS_CLEAR;
  else {
    ret = send_message_with_args(550,context,"PROT","must be C or P");
    return E_PARAM_INVALID;
  }
  ret = send_message_with_args(200,context,"PROT command okay");
  return E_OK;
}
#else
int do_prot(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  send_message(502,context);
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
    int af = (context->family == WZD_INET6) ? AF_INET6 : AF_INET;

    user = GetUserByID(context->userid);

    if (user->group_num > 0) groupname = GetGroupByID(user->groups[0])->groupname;
    inet_str[0] = '\0';
    inet_ntop(af,context->hostip,inet_str,sizeof(inet_str));
    h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),af);
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
    ret = send_message_with_args(501,context,"Forbidden");
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
    ret = send_message_with_args(553,context,"RNTO","wrong file name?");
    return E_PARAM_INVALID;
  }
  if (context->current_action.token != TOK_RNFR) {
    ret = send_message_with_args(553,context,"RNTO","send RNFR before!");
    return E_PARAM_INVALID;
  }

  checkpath_new(str_tochar(filename),path,context);
  if (path[strlen(path)-1]=='/') path[strlen(path)-1]='\0';

  /* deny retrieve to permissions file */
  if (is_hidden_file(path)) {
    ret = send_message_with_args(501,context,"Forbidden");
    return E_FILE_FORBIDDEN;
  }
  context->current_action.token = TOK_UNKNOWN;
  context->current_action.current_file = -1;
  context->current_action.bytesnow = 0;

  ret = file_rename(context->current_action.arg,path,context);
  if (ret) {
    ret = send_message_with_args(550,context,"RNTO","command failed");
  } else {
    ret = send_message_with_args(250,context,"RNTO"," command okay");
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
  fs_filestat_t s;
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
      ret = send_message_with_args(501,context,"Forbidden");
      return E_FILE_FORBIDDEN;
    }


    if (fs_file_stat(path,&s)==0) {
      ret = calc_crc32(path,&crc,startpos,length);
      snprintf(buffer,1024,"%lX",crc);
/*      snprintf(buffer,1024,"%d %lX\r\n",250,crc);*/
/*      ret = send_message_raw(buffer,context);*/
      ret = send_message_with_args(250,context,buffer,"");
      return E_OK;
    }
  }
  ret = send_message_with_args(550,context,"XCRC","File inexistent or no access?");
  return E_FILE_NOEXIST;
}

/*************** do_xmd5 *****************************/
int do_xmd5(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  char path[WZD_MAX_PATH];
  char buffer[1024];
  const char * ptr;
  char * ptest;
  fs_filestat_t s;
  int ret;
  unsigned char crc[16];
  char md5str[33];
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
      ret = send_message_with_args(501,context,"Forbidden");
      return E_FILE_FORBIDDEN;
    }


    if (fs_file_stat(path,&s)==0) {
      ret = calc_md5(path,crc,startpos,length);
      for (i=0; i<16; i++)
        snprintf(md5str+i*2,3,"%02x",crc[i]);
      ret = send_message_with_args(250,context,md5str,"");
      return E_OK;
    }
  }
  ret = send_message_with_args(550,context,"XMD5","File inexistent or no access?");
  return E_FILE_NOEXIST;
}

/*************** do_help *****************************/
int do_help(wzd_string_t *name, wzd_string_t *arg, wzd_context_t * context)
{
  /* TODO maybe add HELP SITE? */
  send_message_with_args(214,context);

  return E_OK;
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
  unsigned long max_wait_time;
  wzd_context_t * context;
  char *buffer = NULL;
  int save_errno;
  fd_t sockfd;
  int ret;
  wzd_user_t * user;
  wzd_command_t * command;
  wzd_string_t * command_buffer;
  struct ftp_command_t * ftp_command;
#ifndef _MSC_VER
  int oldtype;
#endif

  context = arg;
  sockfd = context->controlfd;
  context->last_file.name[0] = '\0';
  context->last_file.token = TOK_UNKNOWN;
  context->data_buffer = wzd_malloc(mainConfig->data_buffer_length);

#ifdef WIN32
  context->thread_id = GetCurrentThreadId();
#else
  context->thread_id = pthread_self();
#endif
 _tls_store_context(context);

  out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);
#ifndef WIN32
#ifdef WZD_MULTITHREAD
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);
  pthread_cleanup_push((void (*) (void *))client_die, (void *) context);
#endif /* WZD_MULTITHREAD */
#endif

  ret = do_login(context);

  if (ret) {
#if defined (WIN32)
    client_die(context);
#else
    /* on other platforms, the cleanup function will be executed
     * using pthread_cleanup_pop
     */
    pthread_exit(NULL);
#endif /* WIN32 */
    return NULL;
  }

  context->state = STATE_COMMAND;

  user = GetUserByID(context->userid);

  /* user+pass ok */
  send_message_raw("230- Command okay\r\n",context);
  {
    wzd_string_t * event_args = STR(user->username);
    event_send(mainConfig->event_mgr, EVENT_LOGIN, 230, event_args, context);
    str_deallocate(event_args);
  }
  ret = send_message(230,context);

  /* update last login time */
  time(&user->last_login);

  context->control_buffer = buffer = malloc(WZD_BUFFER_LEN);

  /* get value for server tick */
  max_wait_time = config_get_integer(mainConfig->cfg_file, "GLOBAL", "client tick", &ret);
  if (ret != CF_OK) {
    max_wait_time = DEFAULT_CLIENT_TICK;
  }

  /* main loop */
  context->exitclient=0;
  context->idle_time_start = time(NULL);

  user = GetUserByID(context->userid);
  while (!context->exitclient) {
#ifdef DEBUG
    if (check_context(context) != 0) {
      out_log(LEVEL_CRITICAL,"CRITICAL check_context failed\n");
      context->exitclient = 1;
      break;
    }
#endif /* DEBUG */

    /* check for finished transfers
     * Remember that this will be checked every max_wait_time seconds
     * (default: DEFAULT_CLIENT_TICK = 10), so at this point the transfer
     * can be finished while the thread is waiting to be joined
     */
    if (context->transfer_thread != NULL &&
        context->is_transferring == 0) {
      void * return_value;

      out_log(LEVEL_FLOOD,"DEBUG waiting for transfer thread\n");

      wzd_thread_join(context->transfer_thread,&return_value);
      context->transfer_thread = NULL;

      free(context->transfer_thread);
      context->transfer_thread = NULL;
    }

    save_errno = 666;
    /* 1. read */
    FD_ZERO(&fds_r);
    FD_ZERO(&fds_w);
    FD_ZERO(&efds);
    /* set control fd */
    FD_SET(sockfd,&fds_r);
    FD_SET(sockfd,&efds);
    /* set data fd */
    if (context->transfer_thread == NULL) {
      ret = data_set_fd(context,&fds_r,&fds_w,&efds);
    }
    if ((signed)sockfd > ret) ret = sockfd;

    tv.tv_sec=max_wait_time; tv.tv_usec=0L;
    /* bug in windows implementation of select(): when aborting a data connection,
     * next calls to select() always return immediatly, causing wzdftpd
     * to use 100% cpu (infinite loop).
     * The solution is not to use efds
     */
/*    ret = select(ret+1,&fds_r,&fds_w,&efds,&tv);*/
    ret = select(ret+1,&fds_r,&fds_w,NULL,&tv);
    FD_ZERO(&efds);
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
    if (context->transfer_thread == NULL) {
      ret = data_check_fd(context,&fds_r,&fds_w,&efds);
    }
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

    if (buffer[0]=='\xff') {
      const char * ptr = buffer;
      char * ptr2;
      /* skip telnet characters */
      while (*ptr != '\0' &&
          ((unsigned char)*ptr == 255 || (unsigned char)*ptr == TELNET_IP || (unsigned char)*ptr == TELNET_SYNCH))
        ptr++;
      /* TODO replace this by a working memmove or copy characters directly */
      ptr2 = strdup(ptr);
      wzd_strncpy(buffer,ptr2,WZD_BUFFER_LEN-1);
      free(ptr2);
    }

    command_buffer = STR(buffer);

    str_trim_right(command_buffer);

    set_action(context,str_tochar(command_buffer));

/*    context->idle_time_start = time(NULL);*/
#ifdef DEBUG
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,str_tochar(command_buffer));
#endif

    /* reset current reply */
    reply_clear(context);

    /* parse and identify command */
    ftp_command = parse_ftp_command(command_buffer);

    if (ftp_command != NULL) {
      command = ftp_command->command;

      /** For FTP commands, the default permission (if not specified)
       * is to ALLOW users to use command, unless restricted !
       */
      if (command->perms && commands_check_permission(command,context)) {
        ret = send_message_with_args(501,context,"Permission Denied");
        free_ftp_command(ftp_command);
        continue;
      }

      if (command->command)
        ret = (*(command->command))(ftp_command->command_name,ftp_command->args,context);
      else { /* external command */
        char buffer_command[4096];
        wzd_group_t * group = NULL;

        if (user->group_num > 0) group = GetGroupByID(user->groups[0]);
        cookie_parse_buffer(str_tochar(command->external_command), user, group, context, buffer_command, sizeof(buffer_command));
        chop(buffer_command);

        /* add arguments given on CLI to event */
        if (str_length(ftp_command->args)>0) {
          strlcat(buffer_command, " ", sizeof(buffer_command));
          strlcat(buffer_command, str_tochar(ftp_command->args), sizeof(buffer_command));
        }

        ret = event_exec(buffer_command,context);
      }

      /** \todo When all functions use reply_push, test reply and send error if -1 */
      ret = reply_send(context);
    } else { /* no command found */
      ret = send_message(502,context);
      str_deallocate(command_buffer);
    }
    free_ftp_command(ftp_command);

  } /* while (!exitclient) */


#ifdef WZD_MULTITHREAD
#ifndef WIN32
  pthread_cleanup_pop(1); /* 1 means the cleanup fct is executed !*/
#else
  client_die(context);
#endif /* _MSC_VER */
#else /* WZD_MULTITHREAD */
  client_die(context);
#endif /* WZD_MULTITHREAD */

  return NULL;
}

/** \brief Test if remote address is different from the connected client (i.e,
 * if client is trying to transfer files to use site-to-site transfer)
 *
 * \return 1 if transfer is FXP
 */
static int test_fxp(const char * remote_ip, net_family_t family, wzd_context_t * context)
{
  switch (family) {
    case WZD_INET4:
      return (memcmp(remote_ip,context->hostip,4) != 0);
    case WZD_INET6:
      return (memcmp(remote_ip,context->hostip,16) != 0);
    default:
      out_log(LEVEL_HIGH,"ERROR test_fxp called with invalid family\n");
  };
  return -1;
}

static int fxp_is_denied(wzd_user_t * user)
{
  return (strchr(user->flags,FLAG_FXP_DISABLE) != NULL);
}

/** \brief Store context in Thread Local Store (TLS)
 *
 * \param[in] context Client context
 * \return 0 if ok
 */
int _tls_store_context(wzd_context_t * context)
{
  if (_key_context == NULL) {
    _key_context = wzd_tls_allocate();
    if (_key_context == NULL) return -1;
  }

  if (wzd_tls_setspecific(_key_context, context) != 0) {
    out_log(LEVEL_HIGH,"ERROR Could not store context in TLS\n");
    wzd_tls_free(_key_context);
    _key_context = NULL;
    return -1;
  }
  return 0;
}

/** \brief Get current context from Thread Local Storage (TLS)
 *
 * \return
 * - a valid wzd_context_t structure if found
 * - NULL if the value was not found in TLS
 */
wzd_context_t * _tls_get_context(void)
{
  if (_key_context != NULL)
    return wzd_tls_getspecific(_key_context);

  return NULL;
}

/** \brief Remove current context from Thread Local Storage (TLS)
 *
 * This is used by threads to release properly TLS resources used
 * to store context pointer.
 *
 * \return 0 if ok
 */
int _tls_remove_context(void)
{
  if (_key_context != NULL)
    return wzd_tls_remove(_key_context);

  return 0;
}



