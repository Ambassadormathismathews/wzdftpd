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

#ifndef __WZD_PERM__
#define __WZD_PERM__

/**************** COMMANDS PERMISSIONS ********************/
typedef enum {
  CPERM_USER,
  CPERM_GROUP,
  CPERM_FLAG
} wzd_cp_t;

typedef struct wzd_command_perm_entry_t wzd_command_perm_entry_t;
typedef struct wzd_command_perm_t wzd_command_perm_t;
struct wzd_command_perm_entry_t {
  wzd_cp_t cp;
  char target[256];
  struct wzd_command_perm_entry_t * next_entry;
};

struct wzd_command_perm_t {
  char  command_name[256];
  wzd_command_perm_entry_t * entry_list;
  struct wzd_command_perm_t * next_perm;
};


/** \brief Find permission structure for a command and return the structure
 * \param[in] commandname the command name
 * \param[in] perm_list permission list
 * \return
 *  - the permission structure if found
 *  - NULL if not found
 */
wzd_command_perm_t * perm_find(const char *commandname, wzd_command_perm_t * perm_list);

/** \brief Find permission structure (create it if needed) for a command and return the structure
 * \param[in] commandname the command name
 * \param[in,out] perm_list permission list
 * \return
 *  - the permission structure if found
 *  - a new structure if none was found
 *  - NULL on error
 */
wzd_command_perm_t * perm_find_create(const char *permname, wzd_command_perm_t ** perm_list);

/** \brief Find permission entry applying for a command and a target, and return the structure
 * \param[in] target the target name (user, group or flag)
 * \param[in] cp the command type
 * \param[in] command_perm the permission to check
 * \return
 *  - the permission entry if found
 *  - NULL if not found
 */
wzd_command_perm_entry_t * perm_find_entry(const char * target, wzd_cp_t cp, wzd_command_perm_t * command_perm);

/** \brief Find permission entry structure (create it if needed) applying for a command and a target, and return the structure
 * \param[in] target the target name (user, group or flag)
 * \param[in] cp the command type
 * \param[in,out] command_perm the permission to check
 * \return
 *  - the permission entry if found
 *  - a new entry if none was found
 *  - NULL on error
 */
wzd_command_perm_entry_t * perm_find_create_entry(const char * target, wzd_cp_t cp, wzd_command_perm_t * command_perm);

/** \brief Create a new permission, parse entries, and add it to permission list
 * \param[in] permname command name
 * \param[in] permline text describing permissions
 * \param[out] perm_list permission list
 * \return 0 if ok
 */
int perm_add_perm(const char *permname, const char *permline, wzd_command_perm_t ** perm_list);

/** \brief Remove the permission structure associated with \a commandname from list
 * \param[in] commandname command name
 * \param[in,out] perm_list permission list
 * \return
 *  - 0 if ok
 *  - 1 if the command was not found
 *  - -1 on error
 */
int perm_remove(const char *commandname, wzd_command_perm_t ** perm_list);

/** \brief Free \a perm and all contained structures recursively
 * \param perm permission list
 */
void perm_free_recursive(wzd_command_perm_t * perm);

/** \brief Check if user is authorized to execute command
 * \note the default choice is to \b deny execution if nothing specific was found
 * \param[in] perm permission structure
 * \param[in] context user context
 * \return
 *  - 0 if ok
 *  - 1 if denied
 *  - -1 on error
 */
int perm_check_perm(const wzd_command_perm_t *perm, const wzd_context_t * context);

/** \brief Check if user is authorized to execute command
 * \note the default choice is to \b deny execution if nothing specific was found
 * \param[in] permname command name
 * \param[in] context user context
 * \param[in] perm_list permission list
 * \return
 *  - 0 if ok
 *  - 1 if denied
 *  - -1 on error
 */
int perm_check(const char *permname, const wzd_context_t * context, wzd_command_perm_t * perm_list);

/** \brief Convert permission structure to printable string
 * \note: result string will start with a space
 * \param[in] perm A wzd_command_perm_t strcture
 * \param[out] perm_buffer Output buffer
 * \param[out] max_length Maximum number of bytes that can be written to output buffer
 * \return 0 if ok
 */
int perm2str(wzd_command_perm_t * perm, char * perm_buffer, size_t max_length);

#endif /* __WZD_PERM__ */
