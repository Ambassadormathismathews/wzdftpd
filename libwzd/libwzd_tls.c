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

/** \file libwzd.c
 *  \brief Routines to access wzdftpd from applications
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include "libwzd.h"
#include "libwzd_pv.h"

#include "libwzd_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#endif

#ifdef HAVE_GNUTLS

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#define DH_BITS 1024

static gnutls_session session;
static gnutls_certificate_credentials x509_cred;
static char * certificate = "/home/pollux/DEL/etc/wzdftpd/wzd.pem";
#if 0
static gnutls_dh_params dh_params;

static int generate_dh_params(void)
{
  gnutls_dh_params_init(&dh_params);
  gnutls_dh_params_generate2(dh_params, DH_BITS);

  return 0;
}
#endif

int tls_init(void)
{
  /* order matters */
  gnutls_global_init();

  gnutls_certificate_allocate_credentials(&x509_cred);
  gnutls_certificate_set_x509_trust_file(x509_cred, certificate, GNUTLS_X509_FMT_PEM);

#if 0
  gnutls_certificate_set_x509_key_file(x509_cred,
      certificate /* CERTFILE */,
      certificate /* KEYFILE */,
      GNUTLS_X509_FMT_PEM);
#endif

  gnutls_init(&session, GNUTLS_CLIENT);

  gnutls_set_default_priority(session);

  gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

#if 0
  generate_dh_params();

  gnutls_certificate_set_dh_params(x509_cred, dh_params);
#endif

  return 0;
}

int tls_handshake(int fd)
{
  int ret;

  if (!_config) return -1;
  if ( (_config->options & OPTION_TLS) ) return -1; /* already in TLS mode ?! */
  if (fd < 0) return -1;

  gnutls_transport_set_ptr( session, (gnutls_transport_ptr)fd);

  /* Perform the TLS handshake */
  ret = gnutls_handshake( session );
  if (ret < 0) {
    /* handshake failed */
    fprintf(stderr, "*** Handshake failed\n");
    gnutls_perror(ret);
    /* TODO deinit */
    return -1;
  }

  return 0;
}

int tls_read(char *buffer, int length)
{
  if (!_config) return -1;
  if ( !(_config->options & OPTION_TLS) ) return -1;
  if (_config->sock < 0) return -1;

  return gnutls_record_recv( session, buffer, length );
}

int tls_write(const char *buffer, int length)
{
  if (!_config) return -1;
  if ( !(_config->options & OPTION_TLS) ) return -1;
  if (_config->sock < 0) return -1;

  return gnutls_record_send( session, buffer, length );
}

int tls_deinit(void)
{
  if (!_config) return -1;
  if ( !(_config->options & OPTION_TLS) ) return -1;
  if (_config->sock < 0) return -1;

  gnutls_deinit(session);
  gnutls_certificate_free_credentials(x509_cred);
  gnutls_global_deinit();

  return 0;
}

#else /* HAVE_GNUTLS */

#warning "no TLS support"

int tls_init(void)
{
  return -1;
}

int tls_handshake(void)
{
  return -1;
}

#endif /* HAVE_GNUTLS */
