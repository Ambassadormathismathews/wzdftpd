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

#ifndef __WZD_VARS__
#define __WZD_VARS__

/** \file wzd_vars.h
 * \brief Get or change values from server variables
 *
 * \addtogroup libwzd_core
 * @{
 */

/** \brief Shared variables between connections
 *
 * Theses variables are not really shared, since classic memory is
 * implicitely shared between threads.
 */
struct wzd_shm_vars_t {
  char *key;
  void * data;
  unsigned long datalength;

  struct wzd_shm_vars_t * next_var;
};

/** \brief Get the value of a server variable
 * \returns 0 if ok, 1 if an error occured
 */
int vars_get(const char *varname, char *data, unsigned int datalength, wzd_config_t * config);

/** \brief Change value of server variable
 * \returns 0 if ok, 1 if an error occured
 */
int vars_set(const char *varname, const char *data, unsigned int datalength, wzd_config_t * config);

/** \brief Get the value of a user variable
 * \returns 0 if ok, 1 if an error occured
 */
int vars_user_get(const char *username, const char *varname, char *data, unsigned int datalength, wzd_config_t * config);

/** \brief Change value of user variable
 * \param username the name of the user
 * \param varname the name of the variable to change
 * \param data the new value
 * \param datalength size of data
 * \param config the running server config
 * \returns 0 if ok, 1 if an error occured
 */
int vars_user_set(const char *username, const char *varname, const char *data, unsigned int datalength, wzd_config_t * config);

/** \brief Create a new user
 * \returns 0 if ok, 1 if an error occured
 */
int vars_user_new(const char *username, const char *pass, const char *groupname, wzd_config_t * config);

/** \brief Add an authorized ip to user
 * \return 0 if ok
 */
int vars_user_addip(const char *username, const char *ip, wzd_config_t *config);

/** \brief Remove an authorized ip to user
 * \param username the user s name
 * \param ip either the slot number or the ip
 * \param config the running server config
 * \returns 0 if ok
 */
int vars_user_delip(const char *username, const char *ip, wzd_config_t *config);

/** \brief Get the value of a group variable
 * \returns 0 if ok, 1 if an error occured
 */
int vars_group_get(const char *groupname, const char *varname, char *data, unsigned int datalength, wzd_config_t * config);

/** \brief Change value of group variable
 * \param groupname the name of the group
 * \param varname the name of the variable to change
 * \param data the new value
 * \param datalength size of data
 * \param config the running server config
 * \returns 0 if ok, 1 if an error occured
 */
int vars_group_set(const char *groupname, const char *varname, const char *data, unsigned int datalength, wzd_config_t * config);

/** create a new group
 * @returns 0 if ok, 1 if an error occured
 */
int vars_group_new(const char *groupname, wzd_config_t * config);


void vars_shm_init(void);
void vars_shm_free(void);

/* finds shm entry corresponding to 'varname'
 * @returns a pointer to the struct or NULL
 */
struct wzd_shm_vars_t * vars_shm_find(const char *varname, wzd_config_t * config);

/** fills data with varname content, max size: datalength
 * @returns 0 if ok, 1 if an error occured
 */
int vars_shm_get(const char *varname, char *data, unsigned int datalength, wzd_config_t * config);

/** change varname with data contents size of data is datalength
 * @returns 0 if ok, 1 if an error occured
 */
int vars_shm_set(const char *varname, const char *data, unsigned int datalength, wzd_config_t * config);

/** @} */

#endif /* __WZD_VARS__ */
