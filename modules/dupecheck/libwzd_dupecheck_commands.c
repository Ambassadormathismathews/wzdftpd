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

#include "dupelog.h"
#include "libwzd_dupecheck_commands.h"

int dupecheck_command_undupe(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int limit = 10;
  char *parameters, *temp;
  if (str_length(param) == 0)
  {
    dupecheck_command_help_undupe(context);
    return 0;
  }

  // TODO: Parse arguments more sensibly? Allow changing of limit?

  out_log(LEVEL_INFO, "Dupecheck: site undupe '%s'\n", str_tochar(param));
  dupelog_delete_matching_files(str_tochar(param), context);

  send_message_raw_formatted(context, "210 site undupe done!");
  return 0;
}

int dupecheck_command_dupe(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int limit = 10;
  char *parameters, *temp;
  if (str_length(param) == 0)
  {
    dupecheck_command_help_dupe(context);
    return 0;
  }

  // TODO: Parse arguments more sensibly? Allow changing of limit?
  
  str_prepend(param, "*");
  str_append(param, "*");

  out_log(LEVEL_INFO, "Dupecheck: site dupe '%s'\n", str_tochar(param));
  dupelog_print_matching_dirs(str_tochar(param), limit, context);

  send_message_raw_formatted(context, "210 site dupe done!");
  return 0;
}

void dupecheck_command_help_dupe(wzd_context_t * context)
{
  send_message_raw_formatted(context, "510- Syntax: site dupe <pattern>");
  send_message_raw_formatted(context, "510-  site dupe searches all (recently) uploaded directories, and shows you the matching ones.");
  send_message_raw_formatted(context, "510-");
  send_message_raw_formatted(context, "510-  <pattern> is a glob-style wildcard pattern, meaning you can use the following wildcards:");
  send_message_raw_formatted(context, "510-   * - matches zero or more characters.");
  send_message_raw_formatted(context, "510-   ? - matches one or zero characters.");
  send_message_raw_formatted(context, "510-");
  send_message_raw_formatted(context, "510  Note: Searching always adds a * to the start and end of your query. :-)");
}
void dupecheck_command_help_undupe(wzd_context_t * context)
{
  send_message_raw_formatted(context, "510- Syntax: site undupe <pattern>");
  send_message_raw_formatted(context, "510-  site undupe searches the dupedb for all filenames matching the pattern, and undupes them.");
  send_message_raw_formatted(context, "510-");
  send_message_raw_formatted(context, "510-  <pattern> is a glob-style wildcard pattern, meaning you can use the following wildcards:");
  send_message_raw_formatted(context, "510-   * - matches zero or more characters.");
  send_message_raw_formatted(context, "510    ? - matches one or zero characters.");
}
