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

#ifndef __WZD_TLS__
#define __WZD_TLS__

void tls_context_init(wzd_context_t * context);

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)

int tls_init(void);
int tls_exit(void);
int tls_auth (const char *type, wzd_context_t * context);
int tls_auth_cont(wzd_context_t * context);
int tls_init_datamode(int sock, wzd_context_t * context);
int tls_close_data(wzd_context_t * context);
int tls_free(wzd_context_t * context);

int tls_auth_data_cont(wzd_context_t * context);

int tls_read(socket_t sock, char *msg, size_t length, int flags, unsigned int timeout, void * vcontext);
int tls_write(socket_t sock, const char *msg, size_t length, int flags, unsigned int timeout, void * vcontext);

#ifdef HAVE_OPENSSL
  void * ssl_get_obj(wzd_context_t * context);
#endif

#ifdef HAVE_GNUTLS
int tls_dh_params_regenerate(void);
#endif

#endif

#endif /* __WZD_TLS__ */
