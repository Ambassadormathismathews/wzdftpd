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

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#ifdef _MSC_VER
#include <io.h>
#endif
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#define Sleep(x)        usleep((x)*1000)

#include <time.h>


#include "wzd_hardlimits.h"
#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_tls.h"
#include "wzd_misc.h"
#include "wzd_ClientThread.h"
#include "wzd_messages.h"
#include "wzd_file.h"
#include "wzd_mod.h"
#include "wzd_data.h"
#include "wzd_socket.h"
#include "wzd_ServerThread.h"

#include "wzd_debug.h"

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

void data_close(wzd_context_t * context)
{
  int ret;

#ifdef HAVE_OPENSSL
  if (context->ssl.data_mode == TLS_PRIV)
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

int data_set_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde)
{
  unsigned int action;

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    if (context->datafd<0 || !fd_is_valid(context->datafd)) {
      fprintf(stderr,"Trying to set invalid datafd (%d) %s:%d\n",
          context->datafd,__FILE__,__LINE__);
    }
    FD_SET(context->datafd,fdw);
    FD_SET(context->datafd,fde);
    return context->datafd;
    break;
  case TOK_STOR:
    if (context->datafd<0 || !fd_is_valid(context->datafd)) {
      fprintf(stderr,"Trying to set invalid datafd (%d) %s:%d\n",
          context->datafd,__FILE__,__LINE__);
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

int data_execute(wzd_context_t * context, fd_set *fdr, fd_set *fdw)
{
  int n;
  unsigned int action;
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if (!context) return -1;

  WZD_ASSERT( context->data_buffer != NULL );

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    n = file_read(context->current_action.current_file,context->data_buffer,mainConfig->data_buffer_length);
    if (n>0) {
#ifdef HAVE_OPENSSL
      if (context->ssl.data_mode == TLS_CLEAR)
        ret = clear_write(context->datafd,context->data_buffer,n,0,HARD_XFER_TIMEOUT,context);
      else
#endif
        ret = (context->write_fct)(context->datafd,context->data_buffer,n,0,HARD_XFER_TIMEOUT,context);
      if (ret <= 0) {
        /* XXX error/timeout sending data */
        file_close(context->current_action.current_file, context);
        FD_UNREGISTER(context->current_action.current_file,"Client file (RETR)");
        context->current_action.current_file = 0;
        context->current_action.bytesnow = 0;
        context->current_action.token = TOK_UNKNOWN;
        data_close(context);
        ret = send_message(426,context);
        out_err(LEVEL_INFO,"Send 426 message returned %d\n",ret);
        /*	limiter_free(context->current_limiter);
                context->current_limiter = NULL;*/
        context->idle_time_start = time(NULL);
        context->state = STATE_COMMAND;
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
      file_close(context->current_action.current_file, context);
      FD_UNREGISTER(context->current_action.current_file,"Client file (RETR)");

      out_xferlog(context,1 /* complete */);
      update_last_file(context);

      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->state = STATE_COMMAND;
      data_close(context);
/*      limiter_free(context->current_limiter);
      context->current_limiter = NULL;*/

      /* send message header */
      send_message_raw("226- command ok\r\n",context);
      FORALL_HOOKS(EVENT_POSTDOWNLOAD)
        typedef int (*login_hook)(unsigned long, const char*, const char *);
        if (hook->hook)
          ret = (*(login_hook)hook->hook)(EVENT_POSTDOWNLOAD,user->username,context->current_action.arg);
        else
          ret = hook_call_external(hook,226);
      END_FORALL_HOOKS
      
      ret = send_message(226,context);
#ifdef DEBUG
out_err(LEVEL_INFO,"Send 226 message returned %d\n",ret);
#endif

      context->current_action.token = TOK_UNKNOWN;
      context->idle_time_start = server_time;
    }
    break;
  case TOK_STOR:
#ifdef HAVE_OPENSSL
      if (context->ssl.data_mode == TLS_CLEAR)
        n = clear_read(context->datafd,context->data_buffer,mainConfig->data_buffer_length,0,HARD_XFER_TIMEOUT,context);
      else
#endif
      n = (context->read_fct)(context->datafd,context->data_buffer,mainConfig->data_buffer_length,0,HARD_XFER_TIMEOUT,context);
    if (n>0) {
      if (file_write(context->current_action.current_file,context->data_buffer,n) != n) {
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
      file_unlock(context->current_action.current_file);
      file_close(context->current_action.current_file,context);
      FD_UNREGISTER(context->current_action.current_file,"Client file (STOR)");

      out_xferlog(context,1 /* complete */);
      update_last_file(context);
      /* we increment the counter of uploaded files at the end
       * of the upload
       */
      user->stats.files_ul_total++;

      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->state = STATE_COMMAND;
      data_close(context);
/*      limiter_free(context->current_limiter);
      context->current_limiter = NULL;*/

      /* send message header */
      send_message_raw("226- command ok\r\n",context);
      FORALL_HOOKS(EVENT_POSTUPLOAD)
        typedef int (*login_hook)(unsigned long, const char*, const char *);
        if (hook->hook)
          ret = (*(login_hook)hook->hook)(EVENT_POSTUPLOAD,user->username,context->current_action.arg);
        else
          ret = hook_call_external(hook,226);
      END_FORALL_HOOKS

      ret = send_message(226,context);
#ifdef DEBUG
      out_err(LEVEL_INFO,"Send 226 message returned %d\n",ret);
#endif

      context->current_action.token = TOK_UNKNOWN;
      context->idle_time_start = server_time;
    }
    break;
  }

  return 0;
}
