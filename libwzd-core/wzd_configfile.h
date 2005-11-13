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

#ifndef __WZD_CONFIGFILE__
#define __WZD_CONFIGFILE__

/** \file wzd_configfile.h
 * \brief Simple config file parser (.ini like)
 *
 * \addtogroup libwzd_core
 * @{
 */

typedef struct _wzd_configfile_t wzd_configfile_t;

typedef enum {
  CF_OK = 0,
  CF_ERROR_INVALID_ARGS = -1,
  CF_ERROR_GROUP_NOT_FOUND = -2,
  CF_ERROR_NO_CURRENT_GROUP = -3,
  CF_ERROR_PARSE = -4,
  CF_ERROR_NOT_FOUND = -5,
  CF_ERROR_INVALID_ENCODING = -6,
  CF_ERROR_FILE = -7,
  CF_ERROR_KEY_ALREADY_EXISTS = -8,

  CF_ERROR_NEED_MORE_DATA = -20,
} cf_error_t;

typedef enum {
  CF_FILE_NONE           = 0,
  CF_FILE_MERGE_MULTIPLE = 1 << 0,

  CF_FILE_DEBUG = 1 << 7,
} cf_flags_t;

/** \brief Creates a new empty wzd_configfile_t object.
 */
wzd_configfile_t * config_new(void);

/** \brief Frees a wzd_configfile_t
 */
void config_free(wzd_configfile_t * file);

/** \brief Returns the list of groups contained in \a file
 */
wzd_string_t ** config_get_groups(const wzd_configfile_t * file);

/** \brief Returns the list of keys contained in \a group
 */
wzd_string_t ** config_get_keys(const wzd_configfile_t * file, const char * groupname, int * errcode);

/** \brief Looks whether the config file has the group \a groupname.
 * \return 1 if \a groupname is part of \a file
 */
int config_has_group(wzd_configfile_t * file, const char * groupname);

/** \brief Looks whether the config file has the key \a key in the group \a groupname.
 * \return 1 if \a key is part of \a groupname
 */
int config_has_key(wzd_configfile_t * file, const char * groupname, const char * key);

/** \brief Returns the value associated with \a key under \a groupname.
 * \return the value, or NULL if the key is not found
 */
char * config_get_value(const wzd_configfile_t * file, const char * groupname, const char * key);

/** \brief Associates a new value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created. If \a groupname cannot be found then it is
 * created.
 */
int config_set_value(wzd_configfile_t * file, const char * groupname, const char * key, const char * value);

/** \brief Returns the value associated with \a key under \a groupname as a string.
 * \return the value, else \a errcode is set to nonzero.
 */
wzd_string_t * config_get_string(const wzd_configfile_t * file, const char * groupname, const char * key, int * errcode);

/** \brief Associates a new string value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_string(wzd_configfile_t * file, const char * groupname, const char * key, wzd_string_t * value);

/** \brief Returns the value associated with \a key under \a groupname as a string.
 * \return a NULL-terminated string array,, or NULL and set \a errcode to nonzero.
 * The array should be freed using str_deallocate_array()
 */
wzd_string_t ** config_get_string_list(wzd_configfile_t * file, const char * groupname, const char * key, int * errcode);

/** \brief Associates a list of string values with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_string_list(wzd_configfile_t * file, const char * groupname, const char * key, wzd_string_t ** value, size_t length);

/** \brief Returns the value associated with \a key under \a groupname as a boolean.
 * \return the value, else \a errcode is set to nonzero.
 */
int config_get_boolean(wzd_configfile_t * file, const char * groupname, const char * key, int * errcode);

/** \brief Associates a new boolean value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_boolean(wzd_configfile_t * file, const char * groupname, const char * key, int value);

/** \brief Returns the value associated with \a key under \a groupname as an integer.
 * \return the value, else \a errcode is set to nonzero.
 */
int config_get_integer(wzd_configfile_t * file, const char * groupname, const char * key, int * errcode);

/** \brief Associates a new integer value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_integer(wzd_configfile_t * file, const char * groupname, const char * key, int value);

/** \brief Places a comment above \a key from \a groupname.
 *
 * If \a key is NULL then \a comment will be written above \a groupname.
 * If both \a key and \a groupname are NULL, then \a comment will be written
 * above the first group in the file.
 */
int config_set_comment(wzd_configfile_t * file, const char * groupname, const char * key, const char * comment);

/** \brief Removes a comment above \a key from \a groupname
 *
 * If \a key is \a NULL then the comment above \a groupname is removed.
 * If both \a key and \a groupname are \a NULL, then the comment before the
 * first group is removed.
 */
int config_remove_comment(wzd_configfile_t * file, const char * groupname, const char * key);

/** \brief Removes a \a key in \a groupname from the key file.
 */
int config_remove_key(wzd_configfile_t * file, const char * groupname, const char * key);

/** \brief Removes a \a groupname (and all associated keys and comments) from the key file.
 */
int config_remove_group(wzd_configfile_t * file, const char * groupname);

/** \brief Loads a key file from disk into an empty wzd_configfile_t structure.
 *
 * If the object cannot be created then the return value is non-zero.
 */
int config_load_from_file (wzd_configfile_t * config, const char * file, unsigned long flags);

/** \brief Loads a key file from an opened file descriptor into an empty
 * wzd_configfile_t structure.
 *
 * If the object cannot be created then the return value is non-zero.
 */
int config_load_from_fd (wzd_configfile_t * config, int fd, unsigned long flags);

/** \brief Loads a key file from memory into an empty wzd_configfile_t structure.
 *
 * If the object cannot be created then the return value is non-zero.
 */
int config_load_from_data (wzd_configfile_t * config, const char * data, size_t length, unsigned long flags);

/** \brief Outputs \a config as a wzd_string_t.
 */
wzd_string_t * config_to_data (wzd_configfile_t * config, size_t * length);

/** @} */

#endif /* __WZD_CONFIGFILE__ */
