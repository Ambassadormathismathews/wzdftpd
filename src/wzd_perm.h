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

#ifndef __WZD_PERM__
#define __WZD_PERM__

int perm_is_valid_perm(const char *permname);

wzd_command_perm_t * perm_find(const char *commandname, wzd_config_t * config);
wzd_command_perm_t * perm_find_create(const char *permname, wzd_config_t * config);
wzd_command_perm_entry_t * perm_find_entry(const char * target, wzd_cp_t cp, wzd_command_perm_t * command_perm);
wzd_command_perm_entry_t * perm_find_create_entry(const char * target, wzd_command_perm_t * command_perm);

int perm_add_perm(const char *permname, const char *permline, wzd_config_t * config);

void perm_free_recursive(wzd_command_perm_t * perm);

/* returns 0 if ok, 1 otherwise */
int perm_check(const char *permname, const wzd_context_t * context, wzd_config_t * config);

#endif /* __WZD_PERM__ */
