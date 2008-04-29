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

#ifndef __WZD_LOGIN_H__
#define __WZD_LOGIN_H__

/** \brief Check username
 *
 * The following checks are performed:
 *  - check if a backlend validates the username
 *  - check if the user is not marked as deleted
 *  - check if site is not closed
 *  - check if maximum number of logins for user or
 *    his groups has been reached
 *  - check if TLS is enforced but not enabled
 *
 * \return E_OK if ok
 * E_USER_REJECTED if user name is rejected by backend
 * E_USER_DELETED if user has been deleted
 * E_USER_NUMLOGINS if user has reached num_logins
 * E_USER_CLOSED if site is closed and user is not a siteop
 * E_USER_TLSFORCED if user must use SSL/TLS
 * E_GROUP_NUMLOGINS if user has reached group num_logins
 */
int do_user(const char *username, wzd_context_t * context);

/** \brief Check password (or authentication method)
 *
 * The following checks are performed:
 * - user exists and has not been deleted
 * - the backend validates the password or authentication method
 * - home directory exists, and user can enter directory
 *
 * \return E_OK if ok
 * E_USER_REJECTED if user does not exist
 * E_PASS_REJECTED if wrong pass
 * E_USER_DELETED if user has been deleted
 * E_LOGIN_NO_HOME if ok but homedir does not exist */
int do_pass(const char *username, const char * pass, wzd_context_t * context);

/*************** do_user_ip **************************/
/** \brief Check if user is connecting from an authorized ip
 *
 * IP addresses are checked in user list first, then in all of
 * its groups.
 *
 * Checks are stopped at the first match.
 */
int do_user_ip(const char *username, wzd_context_t * context);

/** \brief Execute login loop
 *
 * \return 0 if login is ok
 */
int do_login(wzd_context_t * context);

#endif /* __WZD_LOGIN_H__ */
