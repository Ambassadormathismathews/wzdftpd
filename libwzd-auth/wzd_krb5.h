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

#ifndef __WZD_KRB5__
#define __WZD_KRB5__

/*! \addtogroup libwzd_auth
 *  @{
 */

typedef struct _auth_gssapi_data_t * auth_gssapi_data_t;

int auth_gssapi_init(auth_gssapi_data_t * data);

int auth_gssapi_accept_sec_context(auth_gssapi_data_t data, char * ptr_in,size_t length_in, char ** ptr_out, size_t * length_out);

/* return 1 if user is validated */
int check_krb5(const char *user, const char *data);

int changepass_krb5(const char *pass, char *buffer, size_t len);

/*! @} */

#endif /* __WZD_KRB5__ */

