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

#ifndef WIN32
#include <unistd.h>
#endif

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_messages.h>

#include <libwzd-core/wzd_mod.h>

#include "debug_backends.h"

int do_site_listbackends(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  char buffer[4096];
  wzd_backend_def_t * backend;

  backend = getlib_mainConfig()->backends;

  send_message_raw("200-\r\n",context);

  snprintf(buffer,sizeof(buffer)," %s\n",backend->filename);
  ret = send_message_raw(buffer,context);

  snprintf(buffer,sizeof(buffer),"  -> name: %s\n",backend->b->name);
  ret = send_message_raw(buffer,context);

  snprintf(buffer,sizeof(buffer),"  -> version: %s\n",backend_get_version(backend));
  ret = send_message_raw(buffer,context);

  snprintf(buffer,sizeof(buffer),"  -> id: %d\n",backend->b->backend_id);
  ret = send_message_raw(buffer,context);

  snprintf(buffer,sizeof(buffer),"  -> used by: %d\n",backend_inuse(backend->b->name));
  ret = send_message_raw(buffer,context);

  ret = send_message_raw("200 command ok\r\n",context);

  return 0;
}

