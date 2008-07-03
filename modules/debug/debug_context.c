/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

#if defined(WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#ifndef WIN32
#include <unistd.h>
#endif

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_messages.h>

#include <libwzd-core/wzd_mod.h>

#include "debug_context.h"

static void _debug_print_context(wzd_context_t * ctx, wzd_context_t * current_ctx)
{
  int ret;
  char buffer[4096];
  char inet_buf[64];

  snprintf(buffer,sizeof(buffer)," context %p\r\n",(void*)ctx);
  ret = send_message_raw(buffer,current_ctx);

  if (ctx->magic != CONTEXT_MAGIC) {
    snprintf(buffer,sizeof(buffer),"   WARNING: context magic is invalid\n");
    return;
  }

  ip_numeric_to_string((const char*)ctx->hostip, ctx->family, inet_buf, sizeof(inet_buf));
  snprintf(buffer,sizeof(buffer),"   host %s\r\n", inet_buf);
  ret = send_message_raw(buffer,current_ctx);

  if (ctx->ident && ctx->idnt_address) {
    snprintf(buffer,sizeof(buffer),"   ident %s@%s\r\n", ctx->ident, ctx->idnt_address);
    ret = send_message_raw(buffer,current_ctx);
  }

  snprintf(buffer,sizeof(buffer),"   uid %u\r\n", ctx->userid);
  ret = send_message_raw(buffer, current_ctx);

  snprintf(buffer,sizeof(buffer),"   current path: [%s]\r\n", ctx->currentpath);
  ret = send_message_raw(buffer, current_ctx);

  snprintf(buffer,sizeof(buffer),"   pid_child: %lu  thread_id: %lu\r\n", ctx->pid_child, ctx->thread_id);
  ret = send_message_raw(buffer, current_ctx);
}

int do_site_listcontexts(UNUSED wzd_string_t *name,
        UNUSED wzd_string_t *param,
        wzd_context_t * context)
{
  int ret;
  ListElmt * elmnt;

  send_message_raw("200-\r\n",context);

  for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt)) {
    _debug_print_context(list_data(elmnt), context);
  }


  ret = send_message_raw("200 command ok\r\n",context);

  return 0;
}

