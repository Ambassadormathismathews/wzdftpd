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

#include <stdio.h>
#include <string.h>

#include "wzd_structs.h"

#include "wzd_libmain.h"
#include "wzd_log.h"

wzd_config_t *  mainConfig;
wzd_context_t * context_list;
static int _wzd_server_uid;

wzd_config_t * getlib_mainConfig(void)
{ return mainConfig; }

void setlib_mainConfig(wzd_config_t *c)
{ mainConfig = c; }

wzd_context_t * getlib_contextList(void)
{ return context_list; }

void setlib_contextList(wzd_context_t *c)
{ context_list = c; }

int getlib_server_uid(void)
{ return _wzd_server_uid; }

void setlib_server_uid(int uid)
{ _wzd_server_uid = uid; }

void libtest(void)
{
  out_log(LEVEL_CRITICAL,"TEST LIB OK\n");
}
