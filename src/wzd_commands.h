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

#ifndef __WZD_COMMANDS__
#define __WZD_COMMANDS__

#include "wzd_string.h"

typedef int (*wzd_function_command_t)(wzd_string_t *name, wzd_string_t *param, wzd_context_t *context);

typedef struct _wzd_command_t {

  char *name;
  unsigned int id;

  wzd_function_command_t command;
  wzd_function_command_t help_function;

  struct wzd_command_perm_t * perms;
} wzd_command_t;

int commands_init(CHTBL ** _ctable);
void commands_fini(CHTBL * _ctable);

int commands_add(CHTBL * _ctable,
    const char *name,
    wzd_function_command_t command,
    wzd_function_command_t help,
    u32_t id);

int commands_add_defaults(CHTBL * _ctable);

wzd_command_t * commands_find(CHTBL * _ctable, wzd_string_t *str);

/** \brief Set permissions associated to a command
 *
 * Add (or replace if existing) permissions for the specified command.
 * The command must exist.
 * \return 0 if command is ok
 */
int commands_set_permission(CHTBL * _ctable, const char * permname, const char * permline);

/** \brief Check if user is authorized to run specified command
 *
 * Check if the user in the specific context is allowed to run the command.
 * \return 0 if command is ok
 */
int commands_check_permission(wzd_command_t * command, wzd_context_t * context);

/****** to be implemented ********/
int commands_add_permission();

#endif /* __WZD_COMMANDS__ */

