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

#ifndef __WZD_COMMANDS__
#define __WZD_COMMANDS__

#include "wzd_string.h"

typedef int (*wzd_function_command_t)(wzd_string_t *name, wzd_string_t *param, wzd_context_t *context);

typedef struct {
  char *name;
  unsigned int id;

  wzd_function_command_t command;
  wzd_function_command_t help_function;

  wzd_string_t * external_command;

  struct wzd_command_perm_t * perms;
} wzd_command_t;

/** \brief Initialize storage for server commands
 *
 * \param[out] _ctable Pointer to the allocated hash table
 *
 * \return 0 if ok
 */
int commands_init(CHTBL ** _ctable);

/** \brief Destroy stored commands, and free memory used for commands
 *
 * \param[in] _ctable Hash table containing commands
 */
void commands_fini(CHTBL * _ctable);

/** \brief Add a new FTP command, linked to a C function
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] name The FTP command (for ex, XCRC). For a site command, append command
 * name with a space: SITE_HELP
 * \param[in] command The function which will be executed when receiving the FTP command
 * \param[in] help A pointer to a help function (not used at the moment)
 * \param[in] id A unique identifier (32 bits unsigned integer) for the command (see \ref wzd_token_t)
 *
 * \note Command names are case insensitive, and must be valid ASCII
 */
int commands_add(CHTBL * _ctable,
    const char *name,
    wzd_function_command_t command,
    wzd_function_command_t help,
    u32_t id);

/** \brief Add a new FTP command, linked to an external program (for ex, a perl module)
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] name The FTP command (for ex, XCRC). For a site command, append command
 * name with a space: SITE_HELP
 * \param[in] external_command The application which will be executed when receiving the FTP command.
 * The application can use protocols (see \ref hook_add_protocol)
 *
 * \note Command names are case insensitive, and must be valid ASCII
 */
int commands_add_external(CHTBL * _ctable,
    const char *name,
    const wzd_string_t *external_command);

/** \brief Add default FTP commands to hash table
 *
 * \param[in] _ctable Hash table containing commands
 *
 * \return 0 if ok
 */
int commands_add_defaults(CHTBL * _ctable);

/** \brief Search for command in registered commands
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] str Command name to find
 *
 * \return
 * - a wzd_command_t structure if the command has been found
 * - NULL if not found
 */
wzd_command_t * commands_find(CHTBL * _ctable, wzd_string_t *str);

/** \brief Set permissions associated to a command
 *
 * Replace permissions for the specified command.
 * The command must exist.
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] permname The permission name
 * \param[in] permline A string describing permissions
 * \return 0 if command is ok
 */
int commands_set_permission(CHTBL * _ctable, const char * permname, const char * permline);

/** \brief Add permissions to a command
 *
 * Add permissions for the specified command.
 * The command must exist.
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] permname The permission name
 * \param[in] permline A string describing permissions, to be appended
 * \return 0 if command is ok
 */
int commands_add_permission(CHTBL * _ctable, const char * permname, const char * permline);

/** \brief Check if user is authorized to run specified command
 *
 * Check if the user in the specific context is allowed to run the command.
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] context The client context
 * \return 0 if ok
 */
int commands_check_permission(wzd_command_t * command, wzd_context_t * context);

/** \brief Delete permissions associated to a command
 *
 * Delete permissions associated to the command.
 *
 * \param[in] _ctable Hash table containing commands
 * \param[in] str The command name
 * \return 0 if ok
 */
int commands_delete_permission(CHTBL * _ctable, wzd_string_t * str);

#endif /* __WZD_COMMANDS__ */

