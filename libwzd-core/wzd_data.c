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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#if defined(WIN32) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#include <io.h>
#endif
#else
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#endif /* WZD_USE_PCH */

#define Sleep(x)        usleep((x)*1000)

#include <time.h>


#include "wzd_hardlimits.h"
#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_tls.h"
#include "wzd_misc.h"
#include "wzd_ClientThread.h"
#include "wzd_messages.h"
#include "wzd_configfile.h"
#include "wzd_crc32.h"
#include "wzd_events.h"
#include "wzd_file.h"
#include "wzd_libmain.h"
#include "wzd_mod.h"
#include "wzd_data.h"
#include "wzd_socket.h"
#include "wzd_threads.h"
#include "wzd_user.h"

#include "wzd_debug.h"

/** \brief Close pasv connection (if opened) */
void pasv_close(wzd_context_t * context)
{
  int ret;

  if (context->pasvsock >= 0) {
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
    ret = socket_close(context->pasvsock);
    context->pasvsock = -1;
  }
}

/** \brief Create a socket and bind it to a port in the PASV range
 *
 * Any previously pasv socket is closed.
 * The socket is stored in context->pasvsock
 *
 * \note this function relies on the fact that bind() does not modify the input structure
 *
 * \return the bound port, or -1 on error
 */
int get_pasv_port(net_family_t family, wzd_context_t * context)
{
  int ret;
  fd_t sock;
  unsigned int port, count;
  socklen_t len;
#if defined(IPV6_SUPPORT)
  struct sockaddr_in6 addr6;
#endif
  struct sockaddr_in addr4;

  struct sockaddr * addr;

  /* close existing pasv connections */
  if (context->pasvsock != (fd_t)-1) {
    FD_UNREGISTER(context->pasvsock,"Client PASV socket");
    socket_close(context->pasvsock);
    context->pasvsock = -1;
  }

  count = mainConfig->pasv_high_range - mainConfig->pasv_low_range + 1;

#if defined(IPV6_SUPPORT)
  if (family == WZD_INET6) {
    sock = socket(AF_INET6,SOCK_STREAM,0);
    if (sock < 0) return -1;

    addr = (struct sockaddr *)&addr6;
    len = sizeof(addr6);
    addr6.sin6_family = AF_INET6;
    addr6.sin6_flowinfo = 0;
    memset(&addr6.sin6_addr,0,16);
    addr6.sin6_port = htons((unsigned short)port);
  } else
#endif
  if (family == WZD_INET4) {
    sock = socket(AF_INET,SOCK_STREAM,0);
    if (sock < 0) return -1;

    addr = (struct sockaddr *)&addr4;
    len = sizeof(addr4);
    addr4.sin_family = AF_INET;
    if (mainConfig->pasv_ip[0] != 0) {
      /* checks on pasv_ip are done when loading config */
      memcpy(&addr4.sin_addr.s_addr,mainConfig->pasv_ip,4);
    } else {
      addr4.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    addr4.sin_port = htons((unsigned short)port);
  }
  else {
    return -1;
  }


  /* first port is taken using random */
  port = mainConfig->pasv_low_range;
#ifndef WIN32
  port = port + (random()) % count;
#else
  port = port + (rand()) % count;
#endif

  /* naive algorithm: try all ports sequentially */
  while (count > 0) { /* use pasv range max */
    /* memset(&sai,0,size); */
#if defined(IPV6_SUPPORT)
    if (family == WZD_INET6) {
      addr6.sin6_port = htons((unsigned short)port);
    } else
#endif
    {
      addr4.sin_port = htons((unsigned short)port);
    }

    ret = bind(sock,addr,len);
    if (ret == 0) break;

    port++; /* retry with next port */
    if (port >= mainConfig->pasv_high_range) {
      /* see comment in libwzd-core/wzd_ClientThread.c for a potential problem
       * (not really convinced of it anyway)
       */
      port = mainConfig->pasv_low_range;
    }

    WZD_ASSERT( port >= mainConfig->pasv_low_range && port <= mainConfig->pasv_high_range && port <= 65535 );

    count--;
  }

  if (count == 0 && ret < 0) {
    out_log(LEVEL_HIGH,"Could not bind to any port in the PASV range\n");
    socket_close(sock);
    return -1;
  }

  if (listen(sock,5 /* XXX backlog */) < 0) {
    out_log(LEVEL_HIGH,"PASV: listen() operation failed\n");
    socket_close(sock);
    return -1;
  }

  context->pasvsock = sock;
  FD_REGISTER(context->pasvsock,"Client PASV socket");

  return port;
}

void update_last_file(wzd_context_t * context)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  strncpy(context->last_file.name,context->current_action.arg,WZD_MAX_PATH);
  context->last_file.size = context->current_action.bytesnow; /* size */
  if (server_time > context->current_action.tm_start)
    context->last_file.time = (server_time - context->current_action.tm_start); /* size */
  else
    context->last_file.time = 0;
  context->last_file.tv.tv_sec = tv.tv_sec - context->current_action.tv_start.tv_sec;
  context->last_file.tv.tv_usec = tv.tv_usec - context->current_action.tv_start.tv_usec;
  context->last_file.token = context->current_action.token;
}

/** \brief Close data connection (if opened) */
void data_close(wzd_context_t * context)
{
  int ret;

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->tls_data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
#ifdef DEBUG
out_err(LEVEL_FLOOD,"closing data connection fd: %d (control fd: %d)\n",context->datafd, context->controlfd);
#endif
  ret = socket_close(context->datafd);
  FD_UNREGISTER(context->datafd,"Client data socket");
  context->datafd = -1;
  context->pasvsock = -1;
  context->state = STATE_UNKNOWN;
}

/** \brief End current transfer if any, close data connection and send event
 */
void data_end_transfer(int is_upload, int end_ok, wzd_context_t * context)
{
  file_unlock(context->current_action.current_file);
  file_close(context->current_action.current_file, context);
  FD_UNREGISTER(context->current_action.current_file,"Client file (RETR or STOR)");

  out_xferlog(context,end_ok /* complete */);
  update_last_file(context);

  context->current_action.current_file = -1;
  context->current_action.bytesnow = 0;
  context->state = STATE_COMMAND;
  data_close(context);

  context->current_action.token = TOK_UNKNOWN;

  {
    u32_t event_id = (is_upload) ? EVENT_POSTUPLOAD : EVENT_POSTDOWNLOAD;
    unsigned int reply_code = (end_ok) ? 226 : 426;
    wzd_user_t * user = GetUserByID(context->userid);
    wzd_string_t * event_args = str_allocate();

    /** \todo Find a way to indicate if transfer was ok in event */
    str_sprintf(event_args,"%s %s",user->username,context->current_action.arg);
    event_send(mainConfig->event_mgr, event_id, reply_code, event_args, context);
    str_deallocate(event_args);
  }
}

int data_set_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde)
{
  unsigned int action;

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    if (context->state != STATE_XFER) {
      out_log(LEVEL_HIGH,"Assertion failed: state != XFER but current action is RETR. Please report me to authors\n");
      return -1;
    }
    if (context->datafd==(fd_t)-1 || !fd_is_valid(context->datafd)) {
      out_err(LEVEL_HIGH,"Trying to set invalid datafd (%d) %s:%d\n",
          context->datafd,__FILE__,__LINE__);
      return -1;
    }
    FD_SET(context->datafd,fdw);
    FD_SET(context->datafd,fde);
    return context->datafd;
    break;
  case TOK_STOR:
    if (context->state != STATE_XFER) {
      out_log(LEVEL_HIGH,"Assertion failed: state != XFER but current action is STOR. Please report me to authors\n");
      return -1;
    }
    if (context->datafd==(fd_t)-1 || !fd_is_valid(context->datafd)) {
      out_err(LEVEL_HIGH,"Trying to set invalid datafd (%d) %s:%d\n",
          context->datafd,__FILE__,__LINE__);
      return -1;
    }
    FD_SET(context->datafd,fdr);
    FD_SET(context->datafd,fde);
    return context->datafd;
    break;
  }
  return -1;
}

int data_check_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde)
{
  unsigned int action;

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    if (FD_ISSET(context->datafd,fdw)) return 1;
    if (FD_ISSET(context->datafd,fde)) return -1;
    break;
  case TOK_STOR:
    if (FD_ISSET(context->datafd,fdr)) return 1;
    if (FD_ISSET(context->datafd,fde)) return -1;
    return context->datafd;
    break;
  }
  return 0;
}

int data_execute(wzd_context_t * context, wzd_user_t * user, fd_set *fdr, fd_set *fdw)
{
  int n;
  unsigned int action;
  int ret;

  if (!context || !user) return -1;

  WZD_ASSERT( context->data_buffer != NULL );

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    n = file_read(context->current_action.current_file,context->data_buffer,mainConfig->data_buffer_length);
    if (n>0) {
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
      if (context->tls_data_mode == TLS_CLEAR)
        ret = clear_write(context->datafd,context->data_buffer,(size_t)n,0,HARD_XFER_TIMEOUT,context);
      else
#endif
        ret = (context->write_fct)(context->datafd,context->data_buffer,(unsigned int)n,0,HARD_XFER_TIMEOUT,context);
      if (ret <= 0) {
/*        out_log(LEVEL_INFO,"INFO error or timeout sending data\n");*/
        /* error/timeout sending data */
        data_end_transfer(0 /* is_upload */, 0 /* end_ok */, context);

        ret = send_message(426,context);

        context->idle_time_start = time(NULL);
        return 1;
      }
      context->current_action.bytesnow += n;

      limiter_add_bytes(&mainConfig->global_dl_limiter,limiter_mutex,n,0);
      limiter_add_bytes(&context->current_dl_limiter,limiter_mutex,n,0);

      user->stats.bytes_dl_total += n;
      if (user->ratio)
        user->credits -= n;
      context->idle_time_data_start = server_time;
    } else { /* end */
      data_end_transfer(0 /* is_upload */, 1 /* end_ok */, context);

      ret = send_message(226,context);
#ifdef DEBUG
out_err(LEVEL_INFO,"Send 226 message returned %d\n",ret);
#endif

      /* user will be invalidated */
      backend_mod_user(mainConfig->backends->filename, user->uid, user, _USER_BYTESDL | _USER_CREDITS);

      context->current_action.token = TOK_UNKNOWN;
      context->idle_time_start = server_time;
    }
    break;
  case TOK_STOR:
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
      if (context->tls_data_mode == TLS_CLEAR)
        n = clear_read(context->datafd,context->data_buffer,mainConfig->data_buffer_length,0,HARD_XFER_TIMEOUT,context);
      else
#endif
      n = (context->read_fct)(context->datafd,context->data_buffer,mainConfig->data_buffer_length,0,HARD_XFER_TIMEOUT,context);
    if (n>0) {
      if (file_write(context->current_action.current_file,context->data_buffer,(size_t)n) != (ssize_t)n) {
        out_log(LEVEL_NORMAL,"Write failed %d bytes (returned %d %s)\n",n,errno,strerror(errno));
      }
      context->current_action.bytesnow += n;

      limiter_add_bytes(&mainConfig->global_ul_limiter,limiter_mutex,n,0);
      limiter_add_bytes(&context->current_ul_limiter,limiter_mutex,n,0);

      user->stats.bytes_ul_total += n;
      if (user->ratio)
        user->credits += (user->ratio * n);
      context->idle_time_data_start = server_time;
    } else { /* consider it is finished */
      off_t current_position;

      /** If we don't resume a previous upload, we have to truncate the current file
       * or we won't be able to overwrite a file by a smaller one
       */
      current_position = lseek(context->current_action.current_file,0,SEEK_CUR);
      ftruncate(context->current_action.current_file,current_position);

      file_unlock(context->current_action.current_file);
      data_end_transfer(1 /* is_upload */, 1 /* end_ok */, context);

      ret = send_message(226,context);
#ifdef DEBUG
      out_err(LEVEL_INFO,"Send 226 message returned %d\n",ret);
#endif
      /* we increment the counter of uploaded files at the end
       * of the upload
       */
      user->stats.files_ul_total++;

      /* user will be invalidated */
      backend_mod_user(mainConfig->backends->filename, user->uid, user, _USER_BYTESUL | _USER_CREDITS);

      context->current_action.token = TOK_UNKNOWN;
      context->idle_time_start = server_time;
    }
    break;
  }

  return 0;
}

/** \brief run local transfer loop for RETR
 */
int do_local_retr(wzd_context_t * context)
{
  struct timeval tv;
  fd_set fds_w;
  int ret, err;
  ssize_t count;
  int file = context->current_action.current_file;
  int maxfd = context->datafd;
  wzd_user_t * user = GetUserByID(context->userid);
  int exit_ok = 0;
  write_fct_t write_fct;
  unsigned long crc = 0;
  int auto_crc = 0;

  _tls_store_context(context);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->tls_data_mode == TLS_CLEAR)
    write_fct = clear_write;
  else
#endif
    write_fct = context->write_fct;

  context->last_file.crc = 0;
  ret = config_get_boolean(mainConfig->cfg_file, "GLOBAL", "auto crc", &err);
  if (err == CF_OK && (ret)) {
    auto_crc = 1;
  }

  do {
    FD_ZERO(&fds_w);

    FD_SET(context->datafd,&fds_w);

    tv.tv_sec=30; tv.tv_usec=0L;

    ret = select(maxfd+1,NULL,&fds_w,NULL,&tv);

    if (ret > 0) {
      count = read(file, context->data_buffer, mainConfig->data_buffer_length);
      if (count > 0) {
        ret = (write_fct)(context->datafd,context->data_buffer,(size_t)count,0,0,context);

        if (ret <= 0) goto _local_retr_exit;

        context->current_action.bytesnow += count;

        limiter_add_bytes(&mainConfig->global_dl_limiter,limiter_mutex,count,0);
        limiter_add_bytes(&context->current_dl_limiter,limiter_mutex,count,0);

        /* compute incremental crc32 for later use */
        if (auto_crc) calc_crc32_buffer( context->data_buffer, &crc, count);

        user->stats.bytes_dl_total += count;
        if (user->ratio)
          user->credits -= count;
        context->idle_time_data_start = server_time;
      } else {
        exit_ok = 1;
        goto _local_retr_exit;
      }
    } else {
      out_log(LEVEL_HIGH,"do_local_retr select returned %d\n",ret);
      goto _local_retr_exit;
    }
  } while (1);

_local_retr_exit:
  if (exit_ok) { /* send header */
    context->last_file.crc = crc;
  }

  data_end_transfer(0 /* is_upload */, exit_ok /* end_ok */, context);

  if (exit_ok) {
    ret = send_message(226,context);
  } else {
    ret = send_message(426,context);
  }

  /* user will be invalidated */
  backend_mod_user(mainConfig->backends->filename, user->uid, user, _USER_BYTESDL | _USER_CREDITS);

  context->current_action.token = TOK_UNKNOWN;
  context->idle_time_start = server_time;
  context->is_transferring = 0;

  out_log(LEVEL_HIGH,"DEBUG transfer thread exiting\n");

  return 0;
}

/** \brief run local transfer loop for STOR
 */
int do_local_stor(wzd_context_t * context)
{
  struct timeval tv;
  fd_set fds_r;
  int ret, err;
  ssize_t count;
  int file = context->current_action.current_file;
  int maxfd = context->datafd;
  wzd_user_t * user = GetUserByID(context->userid);
  int exit_ok = 0;
  read_fct_t read_fct;
  unsigned long crc = 0;
  int auto_crc = 0;

  _tls_store_context(context);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  if (context->tls_data_mode == TLS_CLEAR)
    read_fct = clear_read;
  else
#endif
    read_fct = context->read_fct;

  context->last_file.crc = 0;
  ret = config_get_boolean(mainConfig->cfg_file, "GLOBAL", "auto crc", &err);
  if (err == CF_OK && (ret)) {
    auto_crc = 1;
  }

  do {
    FD_ZERO(&fds_r);

    FD_SET(context->datafd,&fds_r);

    tv.tv_sec=30; tv.tv_usec=0L;

    ret = select(maxfd+1,&fds_r,NULL,NULL,&tv);

    if (ret > 0) {
      count = (read_fct)(context->datafd,context->data_buffer,mainConfig->data_buffer_length,0,0,context);
      if (count > 0) {
        ret = write(file, context->data_buffer, count);

        if (ret <= 0) goto _local_stor_exit;
        if (ret != count) {
          out_log(LEVEL_HIGH,"ERROR short write (%d bytes instead of %d)\n",(int)ret,(int)count);
          goto _local_stor_exit;
        }

        context->current_action.bytesnow += count;

        limiter_add_bytes(&mainConfig->global_ul_limiter,limiter_mutex,count,0);
        limiter_add_bytes(&context->current_ul_limiter,limiter_mutex,count,0);

        /* compute incremental crc32 for later use */
        if (auto_crc) calc_crc32_buffer( context->data_buffer, &crc, count);

        user->stats.bytes_ul_total += count;
        if (user->ratio)
          user->credits += (user->ratio * ret);
        context->idle_time_data_start = server_time;
      } else {
        exit_ok = 1;
        goto _local_stor_exit;
      }
    } else {
      out_log(LEVEL_HIGH,"do_local_stor select returned %d\n",ret);
      goto _local_stor_exit;
    }
  } while (1);

_local_stor_exit:
  if (exit_ok) { /* send header */
    off_t current_position;

    context->last_file.crc = crc;

    /** If we don't resume a previous upload, we have to truncate the current file
     * or we won't be able to overwrite a file by a smaller one
     */
    current_position = lseek(context->current_action.current_file,0,SEEK_CUR);
    ftruncate(context->current_action.current_file,current_position);

    /* we increment the counter of uploaded files at the end
     * of the upload
     */
    user->stats.files_ul_total++;
  }

  file_unlock(context->current_action.current_file);
  data_end_transfer(1 /* is_upload */, exit_ok /* end_ok */, context);

  if (exit_ok) {
    ret = send_message(226,context);
  } else {
    ret = send_message(426,context);
  }

  /* user will be invalidated */
  backend_mod_user(mainConfig->backends->filename, user->uid, user, _USER_BYTESUL | _USER_CREDITS);

  context->current_action.token = TOK_UNKNOWN;
  context->idle_time_start = server_time;
  context->is_transferring = 0;

  return 0;
}

/** \brief Create thread for data transfer (RETR)
 */
int data_start_thread_retr(wzd_context_t * context)
{
  wzd_thread_t * thread;
  int ret;

  thread = malloc(sizeof(wzd_thread_t));
  ret = wzd_thread_create(thread, NULL, do_local_retr, context);

  context->transfer_thread = thread;

  return 0;
}

/** \brief Create thread for data transfer (STOR)
 */
int data_start_thread_stor(wzd_context_t * context)
{
  wzd_thread_t * thread;
  int ret;

  thread = malloc(sizeof(wzd_thread_t));
  ret = wzd_thread_create(thread, NULL, do_local_stor, context);

  context->transfer_thread = thread;

  return 0;
}

