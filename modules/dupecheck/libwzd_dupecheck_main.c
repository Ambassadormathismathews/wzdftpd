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

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h> /* WZD_MODULE_INIT */
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_file.h>

#include "libwzd_dupecheck_events.h"
#include "libwzd_dupecheck_commands.h"

MODULE_NAME(dupecheck);
MODULE_VERSION(100);

int WZD_MODULE_INIT (void)
{ 
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_PREUPLOAD, dupecheck_event_preupload, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_POSTUPLOAD_DENIED, dupecheck_event_postupload_denied, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_DELE, dupecheck_event_dele, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_PRERENAME, dupecheck_event_prerename, NULL);
  event_connect_function(getlib_mainConfig()->event_mgr, EVENT_POSTRENAME, dupecheck_event_postrename, NULL);

  commands_add(getlib_mainConfig()->commands_list, "site_dupe", dupecheck_command_dupe , NULL, TOK_CUSTOM);
  commands_add(getlib_mainConfig()->commands_list, "site_undupe", dupecheck_command_undupe , NULL, TOK_CUSTOM);
//  commands_set_permission(getlib_mainConfig()->commands_list, "site_dupe", "+O"); TODO?
//  commands_set_permission(getlib_mainConfig()->commands_list, "site_undupe", "+O"); TODO?
  
  out_log(LEVEL_INFO, "Dupecheck: Module loaded!\n");
  return 0;
}

int WZD_MODULE_CLOSE(void)
{
  out_log(LEVEL_INFO, "Dupecheck: Module unloaded!\n");
  return 0;
}
