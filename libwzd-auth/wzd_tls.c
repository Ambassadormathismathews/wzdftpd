/* vi:ai:et:ts=8 sw=2
 */
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "wzd_auth.h"

#include <libwzd-core/wzd_structs.h> /* struct wzd_context_t */
#include <libwzd-core/wzd_log.h> /* out_log */
#include <libwzd-core/wzd_misc.h> /* GetMyContext */

#include <libwzd-core/wzd_tls.h> /* ssl_get_obj */

#if defined(HAVE_OPENSSL)

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* check certificates, etc. */
/* use SSL_get_verify_result */

/* return 1 if certificate is validated */
int check_certificate(const char *user, const char *data)
{
  wzd_context_t * context;
  X509 * client_cert=NULL;
  int status;
  char *name=NULL, *ptr;

  context = GetMyContext();
  if (!context) return 0;

  /* is connection switched to TLS ? */
  if ( !(context->connection_flags & CONNECTION_TLS) ) return 0;

  client_cert = SSL_get_peer_certificate(ssl_get_obj(context));
  out_log(LEVEL_FLOOD, "[%p] = SSL_get_peer_certificate(...)\n", (void*)client_cert);

  if (!client_cert) return 0; /* no client cert */

  /* return codes are documented in verify(1)
   * or /usr/include/openssl/x509_vfy.h
   */
  status = SSL_get_verify_result(ssl_get_obj(context));
  out_log(LEVEL_FLOOD, "[%d] = SSL_get_verify_result(...)\n", status);
  if (status) goto ssl_check_exit_1;

  status = 0;

  name = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
  if (!name) goto ssl_check_exit_1;
  out_log(LEVEL_NORMAL,"Certificate: %s\n",name);

  /* check that login name matches certificate field CN */

  /* XXX assume challenge is {cert}C=FR,ST=France,... */

  ptr = strstr(name,"CN=");
  if (!ptr) goto ssl_check_exit_2;

  if (strncmp(user,ptr+3,strlen(user))==0) status=1;

ssl_check_exit_2:
  OPENSSL_free(name);
ssl_check_exit_1:
  X509_free(client_cert);
  return status;
}

int changepass_cert(const char *pass, char *buffer, size_t len)
{
  if (!pass || !buffer || len<=0) return -1;

  if (len < strlen(AUTH_SIG_CERT)) return -1;

  strncpy(buffer,AUTH_SIG_CERT,len);
  strlcat(buffer,pass,len);

  return 0;
}

#elif defined(HAVE_GNUTLS)

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* check certificates, etc. */

/* return 1 if certificate is validated */
int check_certificate(const char *user, UNUSED const char *data)
{
  wzd_context_t * context;
  unsigned int status=0;
  int ret=0;
  const gnutls_datum *cert_list;
  unsigned int cert_list_size;
  gnutls_x509_crt cert;
  gnutls_session *session;
  size_t name_size;
  char name[256];
  char *ptr;

  context = GetMyContext();
  if (!context) return 0;

  /* is connection switched to TLS ? */
  if ( !(context->connection_flags & CONNECTION_TLS) ) return 0;

  session = context->tls.session;

  /* XXX use gnutls_certificate_verify_peers[2]? */
  ret = gnutls_certificate_verify_peers2(*session,&status);

  out_log(LEVEL_FLOOD, "[%d] = gnutls_certificate_verify_peers2({session},%d)\n",ret,status);
  /* GNUTLS_E_NO_CERTIFICATE_FOUND: -49 */

  if (ret == 0) { /* verification ok, now checking result */
    if (status & GNUTLS_CERT_INVALID) {
      out_log(LEVEL_NORMAL,"certificate is invalid: ");
      if (status & GNUTLS_CERT_REVOKED) out_log(LEVEL_NORMAL," revoked");
      if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) out_log(LEVEL_NORMAL," signer not found");
      if (status & GNUTLS_CERT_SIGNER_NOT_CA) out_log(LEVEL_NORMAL," signer not a CA");
      out_log(LEVEL_NORMAL,"\n");
      return 0;
    }

    /* this will only work for X.509 certficates, but can easily be
     * extended to work with openpgp keys.
     */
    if (gnutls_certificate_type_get(*session) != GNUTLS_CRT_X509)
      return 0;

    if (gnutls_x509_crt_init(&cert) < 0) {
      out_log(LEVEL_HIGH,"error in initialization\n");
      return 0;
    }

    cert_list = gnutls_certificate_get_peers(*session,&cert_list_size);
    if (cert_list==NULL) {
      out_log(LEVEL_HIGH,"No certificate was found\n");
      gnutls_x509_crt_deinit(cert);
      return 0;
    }

    /* only check the first certificate in the chain */
    if (gnutls_x509_crt_import(cert,&cert_list[0],GNUTLS_X509_FMT_DER) < 0) {
      out_log(LEVEL_HIGH,"Error parsing certificate\n");
      gnutls_x509_crt_deinit(cert);
      return 0;
    }

    name_size = sizeof(name);
    gnutls_x509_crt_get_dn(cert,name,&name_size);

    out_log(LEVEL_NORMAL,"Certificate: %s\n",name);

    gnutls_x509_crt_deinit(cert);

    /* check that login name matches certificate field CN */

    /* XXX assume challenge is {cert}C=FR,ST=France,... */

    ptr = strstr(name,"CN=");
    if (!ptr) return 0;

    if (strncmp(user,ptr+3,strlen(user))==0) return 1;

    return 0;
  }

  return 0;
}

int changepass_cert(const char *pass, char *buffer, size_t len)
{
  if (!pass || !buffer || len<=0) return -1;

  if (len < strlen(AUTH_SIG_CERT)) return -1;

  strncpy(buffer,AUTH_SIG_CERT,len);
  strlcat(buffer,pass,len);


  return 0;
}

#else

int check_certificate(const char *user, const char *data)
{
  return -1;
}

int changepass_cert(const char *pass, char *buffer, size_t len)
{
  return -1;
}

#endif /* HAVE_OPENSSL || HAVE_GNUTLS */
