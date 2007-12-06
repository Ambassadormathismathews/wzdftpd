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

#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h> /* WZD_MODULE_INIT */
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_file.h>
#include <libwzd-core/wzd_messages.h>

#include "libwzd_dupecheck_dupelog.h"
#include "libwzd_dupecheck_commands.h"

int dupecheck_command_dupe(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  out_log(LEVEL_INFO, "Dupecheck: site dupe!\n");

  int limit = 10;
  char *parameters, *temp;
  if (str_length(param) == 0)
  {
    send_message_with_args(211, context, " == DUPECHECK ==");
    send_message_with_args(200, context, "Syntax: site dupe <pattern>");
    // TODO: Show syntax.
    return 0;
  }

  // TODO: Parse arguments more sensibly? Allow changing of limit?
  
  str_prepend(param, "*");
  str_append(param, "*");

  out_log(LEVEL_INFO, "Dupecheck: site dupe '%s'\n", str_tochar(param));
  dupelog_print_matching(str_tochar(param), limit, context);

  /*
  str_prepend(param, "%");
  str_append(param, "%");

  parameters = strdup(str_tochar(param));

  out_log(LEVEL_INFO, "Dupecheck: site dupe '%s'\n", parameters);

  for (temp = parameters; *temp; ++temp)
  {
    switch (*temp)
    {
        case ' ':
          *temp = '%';
          break;
        case '?':
          *temp = '_';
          break;
        case '*':
          *temp = '%';
          break;
        default:
          break;
    }
  }
  dupelog_print_matching(parameters, limit, context);

  free(parameters); */

  return 0;
}

