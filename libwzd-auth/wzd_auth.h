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

#ifndef __WZD_AUTH__
#define __WZD_AUTH__

/*! \addtogroup libwzd_auth
 *  Authentication functions for wzdftpd
 *  @{
 */

/* return 1 if password matches */

int checkpass_crypt(const char *pass, const char *encrypted);

/* first chars of challenge indicate the password form (crypt, md5, etc.) */
int checkpass(const char *user, const char *pass, const char *challenge);

/* first chars of challenge indicate the password form (crypt, md5, etc.) */
int check_auth(const char *user, const char *data, const char *challenge);




/* return 0, or -1 if error */

int changepass_crypt(const char *pass, char *buffer, size_t len);

/** \brief Encrypt password using SHA and store it into buffer
 */
int changepass_sha(const char *pass, char *buffer, size_t len);

/** \brief Change password when possible.
 *
 * The first characters of \a pass are used to determine the method. If
 * \a buffer is not \a NULL, it is used to write the correct password
 * string into the \a userpass field of wzd_user_t .
 *
 * \return 0 if ok
 */
int changepass(const char *user, const char *pass, char *buffer, size_t len);


#define AUTH_SIG_MD5  "$1$"
#define AUTH_SIG_PAM  "{pam}"
#define AUTH_SIG_SHA  "{SHA}"
#define AUTH_SIG_CERT "{cert}"

/*! @} */

#endif /* __WZD_AUTH__ */

