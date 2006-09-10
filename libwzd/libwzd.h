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

/** \file libwzd.h
 *  \brief Routines to access wzdftpd from applications
 */

#ifndef __LIBWZD__
#define __LIBWZD__

/*! \addtogroup libwzd
 *  Library for wzdftpd
 *  @{
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
  int code;
  char **data;
} wzd_reply_t;

void wzd_free_reply(wzd_reply_t *reply);



/** \brief parse command line arguments to detect libwzd-specific switches
 */
int wzd_parse_args(int argc, const char **argv);

/** \brief Set username for connection
 * \note Can only be called before connecting.
 */
int wzd_set_username(const char * username);

/** \brief Set password for connection
 * \note Can only be called before connecting.
 */
int wzd_set_password(const char * password);

/** \brief Set hostname for connection
 * \note Can only be called before connecting.
 */
int wzd_set_hostname(const char * hostname);

/** \brief Set port for connection
 * \note Can only be called before connecting.
 */
int wzd_set_port(int port);

/** \brief Set TLS policy for connection
 * \note Can only be called before connecting.
 */
int wzd_set_tls_policy(int use_tls);

/** \brief Initialize libwzd
 * 
 * \note parameters are still being defined
 */
int wzd_init(void);

/** \brief Close connection and free memory used by libwzd
 */
int wzd_fini(void);

/** \brief Connect to server
 * \return The file descriptor, or -1
 */
int wzd_connect(void);

/* \brief Send \a buffer to server
 * 
 * \a buffer must be one-line, without CR or LF
 */
wzd_reply_t * wzd_send_message(const char *buffer, int length);

/* \todo missing functions:
 *
 * - disconnect
 * - send_command(const char *)
 *     |-> send_command should check connection status and re-connect if needed
 *
 * shortcuts to send_command: site_who, kick, kill, stop_server, etc.
 */


#ifdef	__cplusplus
} /* extern "C" */
#endif

#ifndef WIN32

# include <unistd.h>

#else /* WIN32 */

# define strncasecmp strnicmp

#endif /* WIN32 */

/*! @} */

#endif /* __LIBWZD__ */

