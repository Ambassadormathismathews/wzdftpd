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

#include "debug_modules.h"

int do_site_listmodules(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  wzd_module_t * module_list;
  char buffer[4096];
  const char * module_name;
  const char * module_version;

  module_list = getlib_mainConfig()->module;

  send_message_raw("200-\r\n",context);

  while (module_list) {
    snprintf(buffer,sizeof(buffer)," %s\r\n",module_list->name);
    ret = send_message_raw(buffer,context);

    module_name = module_get_name(module_list);
    module_version = module_get_version(module_list);

    snprintf(buffer,sizeof(buffer),"  -> name: %s\n",module_name ? module_name : "(null)");
    ret = send_message_raw(buffer,context);

    snprintf(buffer,sizeof(buffer),"  -> version: %s\n",module_version ? module_version : "(null)");
    ret = send_message_raw(buffer,context);

    module_list = module_list->next_module;
  }

  ret = send_message_raw("200 command ok\r\n",context);

  return 0;
}

