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

#include "wzd_all.h"

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#ifdef HAVE_OPENSSL

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#else
#include <dlfcn.h>
#endif

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_tls.h"

#include "wzd_messages.h"

#include "wzd_debug.h"



/*************** tls_auth_setfd_set *********************/

void tls_auth_setfd_set(wzd_context_t * context, fd_set *r, fd_set *w)
{
  unsigned int socket;

  socket = SSL_get_fd(context->ssl.obj);

  if (context->ssl.ssl_fd_mode == TLS_READ)
    FD_SET(socket,r);
  else if (context->ssl.ssl_fd_mode == TLS_WRITE)
    FD_SET(socket,w);
}

/*************** tls_auth_data_setfd_set ***************/

void tls_auth_data_setfd_set(wzd_context_t * context, fd_set *r, fd_set *w)
{
  unsigned int socket;

  socket = SSL_get_fd(context->ssl.data_ssl);

  if (context->ssl.ssl_fd_mode == TLS_READ)
    FD_SET(socket,r);
  else if (context->ssl.ssl_fd_mode == TLS_WRITE)
    FD_SET(socket,w);
}


static int _tls_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
#ifdef DEBUG
  out_log(LEVEL_FLOOD,"_tls_verify_callback (%d, %p)\n",preverify_ok,x509_ctx);
#endif

  return 1;
}

static int _tls_X509NameCmp(X509_NAME **a, X509_NAME **b)
{
  return(X509_NAME_cmp(*a, *b));
}

static void _tls_push_ca_list(STACK_OF(X509_NAME) *ca_list, const char *ca_file)
{
  STACK_OF(X509_NAME) *sk;
  int i;

  if (!(sk = SSL_load_client_CA_file(ca_file))) return;

  for (i=0; i<sk_X509_NAME_num(sk); i++) {
    char name_buf[256];
    X509_NAME *name;

    name = sk_X509_NAME_value(sk, i);
    out_err(LEVEL_FLOOD,"CA certificate: %s\n",X509_NAME_oneline(name, name_buf, sizeof(name_buf)));

    /*
     * note that SSL_load_client_CA_file() checks for duplicates,
     * but since we call it multiple times when reading a directory
     * we must also check for duplicates ourselves.
     */

    if (sk_X509_NAME_find(ca_list, name) < 0) {
      /* this will be freed when ca_list is */
      sk_X509_NAME_push(ca_list, name);
    }
    else {
      /* need to free this ourselves, else it will leak */
      X509_NAME_free(name);
    }
  }

  sk_X509_NAME_free(sk);
}

static STACK_OF(X509_NAME) * _tls_init_ca_list(const char *ca_file, const char *ca_path)
{
  STACK_OF(X509_NAME) * ca_list;

  /* sorted order */
  ca_list = sk_X509_NAME_new(_tls_X509NameCmp);

  if (ca_file) {
    _tls_push_ca_list(ca_list,ca_file);
  }

  /*
   * Process CA certificate path files
   */
  if (ca_path) {
    /* parse directory and call _tls_push_ca_list(ca_list,ca_file)
     * for each entry
     */
  }

  /*
   * Cleanup
   */
  sk_X509_NAME_set_cmp_func(ca_list, NULL);

  return ca_list;
}

/*************** tls_init ****************************/

int tls_init(void)
{
  int status;
  SSL_CTX * tls_ctx;
  char * tls_certificate;
  char * tls_certificate_key;
  char * tls_ca_file=NULL, * tls_ca_path=NULL;

  if (chtbl_lookup((CHTBL*)mainConfig->htab, "tls_certificate", (void**)&tls_certificate))
  {
    out_log(LEVEL_CRITICAL,"TLS: no certificate provided. (use tls_certificate directive in config)\n");
    return 1;
  }
  /* ignore errors */
  chtbl_lookup((CHTBL*)mainConfig->htab, "tls_ca_file", (void**)&tls_ca_file);
  chtbl_lookup((CHTBL*)mainConfig->htab, "tls_ca_path", (void**)&tls_ca_path);

  ERR_load_ERR_strings();
  SSL_load_error_strings();	/* readable error messages */
  SSL_library_init();		/* initialize library */

  mainConfig->tls_ctx = tls_ctx = SSL_CTX_new(SSLv23_server_method());
  if (!tls_ctx) {
    out_log(LEVEL_CRITICAL,"SSL_CTX_new() %s\r\n",(char *)ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  if (RAND_status() != 1) {
    out_log(LEVEL_HIGH,"ssl_init: System without entropy source\n");
  }

  /* TODO choose the ssl algorithm ? */
  SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_default_verify_paths(tls_ctx);

  /* set certificate */
  /* from manual: SSL_CTX_use_certificate_chain_file should be prefered to
   * SSL_CTX_use_certificate_file
   */
/*  status = SSL_CTX_use_certificate_file(tls_ctx, mainConfig->tls_certificate, X509_FILETYPE_PEM);*/
  status = SSL_CTX_use_certificate_chain_file(tls_ctx, tls_certificate);
  if (status <= 0) {
    out_log(LEVEL_CRITICAL,"SSL_CTX_use_certificate_chain_file(%s) %s\n", tls_certificate, (char *)ERR_error_string(ERR_get_error(), NULL));
    SSL_CTX_free(tls_ctx);
    mainConfig->tls_ctx = NULL;
    return 1;
  }

  /* set private key file - usually the same */
  if (chtbl_lookup((CHTBL*)mainConfig->htab, "tls_certificate_key", (void**)&tls_certificate_key))
  {
    /* if no key provided, try using the same certificate */
    tls_certificate_key = tls_certificate;
  }

  status = SSL_CTX_use_PrivateKey_file(tls_ctx, tls_certificate_key, X509_FILETYPE_PEM);
  if (status <= 0) {
    out_log(LEVEL_CRITICAL,"SSL_CTX_use_PrivateKey_file(%s) %s\n", tls_certificate_key, (char *)ERR_error_string(ERR_get_error(), NULL));
    SSL_CTX_free(tls_ctx);
    mainConfig->tls_ctx = NULL;
    return 1;
  }

  SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, _tls_verify_callback);

  if (tls_ca_file || tls_ca_path) {
    STACK_OF(X509_NAME) * ca_list;

    if (!SSL_CTX_load_verify_locations(tls_ctx, tls_ca_file, tls_ca_path))
    {
      out_log(LEVEL_CRITICAL,"SSL_CTX_load_verify_locations(%s,%s) %s\n", tls_ca_file, tls_ca_path, (char *)ERR_error_string(ERR_get_error(), NULL));
      SSL_CTX_free(tls_ctx);
      mainConfig->tls_ctx = NULL;
      return 1;
    }

    ca_list = _tls_init_ca_list(tls_ca_file,tls_ca_path);
    if (!ca_list) {
      out_log(LEVEL_CRITICAL,"_tls_init_ca_list(%s,%s) %s\n", tls_ca_file, tls_ca_path, (char *)ERR_error_string(ERR_get_error(), NULL));
      SSL_CTX_free(tls_ctx);
      mainConfig->tls_ctx = NULL;
      return 1;
    }

    SSL_CTX_set_client_CA_list(tls_ctx, (STACK *)ca_list);
  }

  SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_CLIENT);
  SSL_CTX_set_session_id_context(tls_ctx, (const unsigned char *) "1", 1);

  out_log(LEVEL_INFO,"TLS initialization successful.\n");

  return 0;
}

/*************** tls_exit ****************************/

int tls_exit(void)
{
  SSL_CTX_free(mainConfig->tls_ctx);
  return 0;
}


/*************** tls_read ****************************/

int tls_read(fd_t sock, char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
{
  wzd_context_t * context = (wzd_context_t*)vcontext;
  SSL * ssl;
  int ret;
  int sslerr;
  int r;
  fd_set fd_r, fd_w;
  struct timeval tv;

  /* FIXME bad conception of parameters ... */
  if (sock == context->controlfd)
  {
    ssl = context->ssl.obj;
  }
  else
  {
    ssl = context->ssl.data_ssl;
    /* XXX we assume that if sock != context->controlfd, then we have datas ... */
  }
  do {
    ret = SSL_read(ssl, msg, length);
    sslerr = SSL_get_error(ssl, ret);
    if (ret>0) {
      r = 1;
      break;
    }

    FD_ZERO(&fd_r);
    FD_ZERO(&fd_w);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    switch (sslerr) {
    case SSL_ERROR_WANT_READ:
      FD_SET(sock,&fd_r);
      break;
    case SSL_ERROR_WANT_WRITE:
      FD_SET(sock,&fd_w);
      break;
    default:
      /* FIXME - could also mean peer has closed connection - test error code ? */
      if (sslerr == SSL_ERROR_ZERO_RETURN) { /* remote host has closed connection */
        return -1;
      }
      out_err(LEVEL_INFO,"SSL_read failed %d\n",sslerr);
      return -1;
    }

    r = select(sock+1,&fd_r,&fd_w,NULL,&tv);
  } while (ret == -1 && r != 0);

  if (r==0)
    return -1;
  return ret;
}

/*************** tls_write ***************************/

int tls_write(fd_t sock, const char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
{
  wzd_context_t * context = (wzd_context_t*)vcontext;
  SSL * ssl;
  int ret;
  int sslerr;
  int r;
  fd_set fd_r, fd_w;
  struct timeval tv;

  /* FIXME bad conception of parameters ... */
  if (sock == context->controlfd)
    ssl = context->ssl.obj;
  else
    ssl = context->ssl.data_ssl;
    /* XXX we assume that if sock != context->controlfd, then we have datas ... */

  WZD_ASSERT( ssl != NULL );

  do {
    ret = SSL_write(ssl, msg, length);
    sslerr = SSL_get_error(ssl, ret);

    if (ret > 0) {
      r = 1;
      break;
    }

    FD_ZERO(&fd_r);
    FD_ZERO(&fd_w);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    switch (sslerr) {
    case SSL_ERROR_WANT_READ:
      FD_SET(sock,&fd_r);
      break;
    case SSL_ERROR_WANT_WRITE:
      FD_SET(sock,&fd_w);
      break;
    default:
      out_err(LEVEL_INFO,"SSL_write failed\n");
      return -1;
    }

    r = select(sock+1,&fd_r,&fd_w,NULL,&tv);
  } while (ret == -1 && r != 0);

  if (r==0)
    return -1;
  return ret;
}

/*************** tls_auth ****************************/

/** The mode distinction is REALLY important
 *
 * in implicit mode, we do not send anything (there's no client at this point)
 *
 * in explicit mode, the client is waiting for our answer
 */
int tls_auth (const char *type, wzd_context_t * context)
{
  int ret;
  char * tls_cipher_list;

#if 0
  if (!type || type[0]==0) return 1;

  if (strcasecmp(type,"SSL")==0 || mainConfig->tls_type == TLS_IMPLICIT)
    context->ssl.data_mode = TLS_PRIV; /* SSL must hava encrypted data connection */
  else
    context->ssl.data_mode = TLS_CLEAR;

  if (mainConfig->tls_type != TLS_IMPLICIT) {
    ret = send_message_with_args(234, context, type);
  }
#endif

  if (chtbl_lookup((CHTBL*)mainConfig->htab, "tls_cipher_list", (void**)&tls_cipher_list))
  {
    tls_cipher_list = "ALL";
  }

  context->ssl.obj = SSL_new(mainConfig->tls_ctx);
  SSL_set_cipher_list(context->ssl.obj,tls_cipher_list);
  ret = SSL_set_fd(context->ssl.obj,context->controlfd);
  if (ret != 1) {
    out_log(LEVEL_CRITICAL,"SSL_set_fd failed (%s)\n",ERR_error_string(ERR_get_error(),NULL));
    return 1;
  }

#ifdef WZD_DBG_TLS
  out_err(LEVEL_HIGH,"tls_auth ok\n");
#endif

  return tls_auth_cont(context);
}

/*************** tls_auth_cont ***********************/

int tls_auth_cont(wzd_context_t * context)
{
/* non blocking test */
#if 1
  SSL * ssl = context->ssl.obj;
  unsigned int fd;
  int ret, status, sslerr;
  fd_set fd_r, fd_w;
  struct timeval tv;

#ifdef WZD_DBG_TLS
  out_err(LEVEL_HIGH,"TLS: Non-blocking accept\n");
#endif

  SSL_set_accept_state(ssl);
  fd = SSL_get_fd(ssl);
  /* ensure socket is non-blocking */
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
    {
    unsigned long noBlock=1;
    ioctlsocket(fd,FIONBIO,&noBlock);
  }
#else
  fcntl(fd,F_SETFL,(fcntl(fd,F_GETFL)|O_NONBLOCK));
#endif
  do {
    status = SSL_accept(ssl);
    sslerr = SSL_get_error(ssl,status);
    if (status == 1) {
      out_log(LEVEL_FLOOD,"control connection succesfully switched to ssl (cipher: %s)\n",SSL_get_cipher(ssl));
      ret = 1;
      break;
    } else {
      context->ssl.ssl_fd_mode = TLS_NONE;
      FD_ZERO(&fd_r);
      FD_ZERO(&fd_w);
      tv.tv_usec = 0;
      tv.tv_sec = 5;
      switch (sslerr) {
      case SSL_ERROR_WANT_READ:
        FD_SET(fd,&fd_r);
        context->ssl.ssl_fd_mode = TLS_READ;
        break;
      case SSL_ERROR_WANT_WRITE:
        FD_SET(fd,&fd_w);
        context->ssl.ssl_fd_mode = TLS_WRITE;
        break;
      default:
        out_log(LEVEL_HIGH,"Error accepting connection: ret %d error code %d : %s\n",status,sslerr,
          ERR_error_string(SSL_get_error(context->ssl.obj,status),NULL));
        out_log(LEVEL_HIGH,"Error accepting connection: ret %d error code %d : %s\n",status,ERR_get_error(),
            ERR_error_string(ERR_get_error(),NULL));
        return 1;
      }
      ret = select(fd+1,&fd_r,&fd_w,NULL,&tv);
      if ( ! (FD_ISSET(fd,&fd_r) || FD_ISSET(fd,&fd_w)) ) { /* timeout */
        out_err(LEVEL_HIGH,"tls_auth_cont failed\n");
        return -1;
      }
    }
  } while (status == -1 && ret != 0);

  if (ret==0) {
    out_err(LEVEL_CRITICAL,"tls_auth_cont failed\n");
    return -1;
  }

  context->ssl.data_ssl = NULL;

  /* set read/write functions */
  context->read_fct = (read_fct_t)tls_read;
  context->write_fct = (write_fct_t)tls_write;

  return 0;
#else
  int ret;

#ifdef WZD_DBG_TLS
  out_err(LEVEL_HIGH,"TLS: Blocking accept\n");
#endif

  ret = SSL_accept(context->ssl.obj);
  if (ret == 1) {
  } else {
    context->ssl.ssl_fd_mode = TLS_NONE;
    switch (ret) {
    case SSL_ERROR_WANT_READ:
      context->ssl.ssl_fd_mode = TLS_READ;
      break;
    case SSL_ERROR_WANT_WRITE:
      context->ssl.ssl_fd_mode = TLS_WRITE;
      break;
    default:
      out_log(LEVEL_HIGH,"Error accepting connection: ret %d error code %d : %s\n",ret,SSL_get_error(context->ssl.obj,ret),
        ERR_error_string(SSL_get_error(context->ssl.obj,ret),NULL));
      out_log(LEVEL_HIGH,"Error accepting connection: ret %d error code %d : %s\n",ret,ERR_get_error(),
          ERR_error_string(ERR_get_error(),NULL));
      return 1;
    }
  }

  context->ssl.data_ssl = NULL;

  /* set read/write functions */
  context->read_fct = (read_fct_t)tls_read;
  context->write_fct = (write_fct_t)tls_write;

  return 0;
#endif
}

/*************** tls_init_datamode *******************/

int tls_init_datamode(int sock, wzd_context_t * context)
{
  char * tls_cipher_list;

  if (!context->ssl.data_ssl) {
    context->ssl.data_ssl = SSL_new(mainConfig->tls_ctx);
  }
  else {
    out_log(LEVEL_CRITICAL,"tls_init_datamode: this should NOT be happening\n");
    return 1;
  }

  if (!context->ssl.data_ssl) {
    out_log(LEVEL_CRITICAL,"SSL_new error\n");
    return 1;
  }

  if (chtbl_lookup((CHTBL*)mainConfig->htab, "tls_cipher_list", (void**)&tls_cipher_list))
  {
    tls_cipher_list = "ALL";
  }

  SSL_set_cipher_list(context->ssl.data_ssl, tls_cipher_list);

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
  {
    unsigned long noBlock=1;
    ioctlsocket(sock,FIONBIO,&noBlock);
  }
#else
  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));
#endif
  if (SSL_set_fd(context->ssl.data_ssl, sock) != 1)
  /* FIXME PORT ? */
    out_log(LEVEL_CRITICAL,"SSL_set_fd error\n");

  return tls_auth_data_cont(context);
}

/*************** tls_auth_data_cont ******************/

int tls_auth_data_cont(wzd_context_t * context)
{
  SSL * ssl = context->ssl.data_ssl;
  int status, sslerr;
  fd_set fd_r, fd_w;
  struct timeval tv;
  unsigned int fd,r;

  if (context->tls_role == TLS_SERVER_MODE)
    SSL_set_accept_state(ssl);
  else
    SSL_set_connect_state(ssl);

  fd = SSL_get_fd(ssl);
  do {
    if (context->tls_role == TLS_SERVER_MODE)
      status = SSL_accept(ssl);
    else
      status = SSL_connect(ssl);

    sslerr = SSL_get_error(ssl,status);

    if (status==1) {
      out_err(LEVEL_INFO,"Data connection successfully switched to ssl mode\n");
      context->ssl.data_mode = TLS_PRIV;
      return 0;
    } else {
      FD_ZERO(&fd_r);
      FD_ZERO(&fd_w);
      tv.tv_usec = 0;
      tv.tv_sec = 5;
      switch (sslerr) {
        case SSL_ERROR_WANT_READ:
          FD_SET(fd,&fd_r);
out_err(LEVEL_FLOOD,"SSL_ERROR_WANT_READ\n");
          break;
        case SSL_ERROR_WANT_WRITE:
          FD_SET(fd,&fd_w);
out_err(LEVEL_FLOOD,"SSL_ERROR_WANT_WRITE\n");
          break;
        default:
          out_log(LEVEL_HIGH,"tls_auth_data_cont: error accepting: %s\n",
            (char*)ERR_error_string(sslerr,NULL));
          return 1;
      }
      r = select(fd+1, &fd_r, &fd_w, NULL, &tv);
    }
  } while (status == -1 && r != 0);

  if (r == 0) {
    out_err(LEVEL_CRITICAL,"tls_auth_data_cont failed\n");
    return -1;
  }

  return 0;
}

/*************** tls_close_data **********************/

int tls_close_data(wzd_context_t * context)
{
  if (context->ssl.data_ssl) {
    SSL_free(context->ssl.data_ssl);
/*    if (SSL_shutdown(context->ssl.data_ssl)==0)
      SSL_shutdown(context->ssl.data_ssl);*/
  }
  context->ssl.data_ssl = NULL;

  return 0;
}

/***************** tls_free **************************/

int tls_free(wzd_context_t * context)
{
  if (context->ssl.data_ssl) {
    SSL_free(context->ssl.data_ssl);
/*    if (SSL_shutdown(context->ssl.data_ssl)==0)
      SSL_shutdown(context->ssl.data_ssl);*/
  }
  context->ssl.data_ssl = NULL;
  if (context->ssl.obj) {
    SSL_free(context->ssl.obj);
  }
  context->ssl.obj = NULL;

  return 0;
}

#endif /* HAVE_OPENSSL */

#ifdef HAVE_GNUTLS

#include <stdlib.h>
#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>
#include <errno.h>
#include <pthread.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;

#include <fcntl.h>


#define DH_BITS 768


#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_tls.h"

#include "wzd_messages.h"

#include "wzd_debug.h"

/*************** tls_init ****************************/

static gnutls_dh_params dh_params;

static int generate_dh_params(void)
{

  /* Generate Diffie Hellman parameters - for use with DHE
   * kx algorithms. These should be discarded and regenerated
   * once a day, once a week or once a month. Depending on the
   * security requirements.
   */
  gnutls_dh_params_init(&dh_params);
  gnutls_dh_params_generate2(dh_params, DH_BITS);

  return 0;
}

/* These are global */
static gnutls_certificate_credentials x509_cred;

int tls_init(void)
{
  char * tls_certificate;
  char * tls_certificate_key;
  char * tls_ca_file=NULL, * tls_ca_path=NULL;

  if (chtbl_lookup((CHTBL*)mainConfig->htab, "tls_certificate", (void**)&tls_certificate))
  {
    out_log(LEVEL_CRITICAL,"TLS: no certificate provided. (use tls_certificate directive in config)\n");
    return 1;
  }
  /* ignore errors */
  chtbl_lookup((CHTBL*)mainConfig->htab, "tls_ca_file", (void**)&tls_ca_file);
  chtbl_lookup((CHTBL*)mainConfig->htab, "tls_ca_path", (void**)&tls_ca_path);

  /* The order matters.
   */
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init();

  /** \todo TODO XXX move this code to global init ? */
  gnutls_certificate_allocate_credentials(&x509_cred);
  if (tls_ca_file) {
    gnutls_certificate_set_x509_trust_file(x509_cred, tls_ca_file,
        GNUTLS_X509_FMT_PEM);
  }

/*
  gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,
      GNUTLS_X509_FMT_PEM);
*/
  if (chtbl_lookup((CHTBL*)mainConfig->htab, "tls_certificate_key", (void**)&tls_certificate_key))
  {
    /* if no key provided, try using the same certificate */
    tls_certificate_key = tls_certificate;
  }

  gnutls_certificate_set_x509_key_file(x509_cred,
      tls_certificate /* CERTFILE */,
      tls_certificate_key /* KEYFILE */,
      GNUTLS_X509_FMT_PEM);

  generate_dh_params();

  gnutls_certificate_set_dh_params(x509_cred, dh_params);

  out_log(LEVEL_INFO,"TLS initialization successful.\n");

  return 0;
}

int tls_exit(void)
{
  gnutls_certificate_free_credentials(x509_cred);
  gnutls_global_deinit();

  return 0;
}

static gnutls_session initialize_tls_session(gnutls_connection_end con_end)
{
  /* Allow connections to servers that have OpenPGP keys as well.
   */
  const int cert_type_priority[3] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };

  gnutls_session session;

  gnutls_init(&session, con_end);

  /* avoid calling all the priority functions, since the defaults
   * are adequate.
   */
  gnutls_set_default_priority(session);
  gnutls_certificate_type_set_priority(session, cert_type_priority);

  gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  if (con_end == GNUTLS_SERVER) {
    /* request client certificate if any.
    */
    gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
  }

  gnutls_dh_set_prime_bits(session, DH_BITS);

  return session;
}

int tls_auth (const char *type, wzd_context_t * context)
{
  int ret;
  gnutls_session session;
  int fd = context->controlfd;
  int was_writing=0;
  fd_set fd_r, fd_w;
  struct timeval tv;


  session = initialize_tls_session(GNUTLS_SERVER);

  gnutls_transport_set_ptr(session, (gnutls_transport_ptr) fd);

  /* ensure socket is non-blocking */
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
    {
    unsigned long noBlock=1;
    ioctlsocket(fd,FIONBIO,&noBlock);
  }
#else
  fcntl(fd,F_SETFL,(fcntl(fd,F_GETFL)|O_NONBLOCK));
#endif

  /* Perform the TLS handshake
   */
  do {
    ret = gnutls_handshake(session);
    if (ret == 0) {
      out_log(LEVEL_FLOOD,"control connection succesfully switched to ssl (cipher: %s)\n",gnutls_cipher_get_name(gnutls_cipher_get(session)));
      break;
    }
    if (gnutls_error_is_fatal(ret)) {
      out_log(LEVEL_HIGH,"GnuTLS: handshake failed: %s\n",gnutls_strerror(ret));
      gnutls_deinit(session);
      return 1;
    }
    switch (ret) {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
        was_writing = gnutls_record_get_direction(session);
        break;
      default:
        out_log(LEVEL_HIGH,"GnuTLS: handshake failed, unknown non-fatal error: %s\n",gnutls_strerror(ret));
        gnutls_deinit(session);
        return 1;
    }

    /* we need to wait before continuing the handshake */
    FD_ZERO(&fd_r);
    FD_ZERO(&fd_w);
    tv.tv_usec = 0;
    tv.tv_sec = 5;
    if (was_writing) { FD_SET(fd,&fd_w); }
    else { FD_SET(fd,&fd_r); }

    ret = select(fd+1, &fd_r, &fd_w, NULL, &tv);

    if ( ! (FD_ISSET(fd,&fd_r) || FD_ISSET(fd,&fd_w)) ) { /* timeout */
      out_log(LEVEL_HIGH,"GnuTLS: tls_auth failed !\n");
      gnutls_deinit(session);
      return 1;
    }
    ret = 1;
  } while (ret != 0);

  /* set read/write functions */
  context->read_fct = (read_fct_t)tls_read;
  context->write_fct = (write_fct_t)tls_write;

  context->tls.session = malloc(sizeof(gnutls_session));
  *( (gnutls_session*)context->tls.session) = session;

  return 0;
}

int tls_auth_cont(wzd_context_t * context)
{
  out_log(LEVEL_CRITICAL,"Function not implemented: %s\n",__FUNCTION__);
  return 0;
}

int tls_init_datamode(int sock, wzd_context_t * context)
{
  int ret;
  gnutls_session session;
  int was_writing=0;
  fd_set fd_r, fd_w;
  struct timeval tv;

  if (context->tls.data_session) {
    out_log(LEVEL_NORMAL,"tls_init_datamode: a data session already exist (%p) !\n",
        context->tls.data_session);
    return 1;
  }

  session = initialize_tls_session( (context->tls_role == TLS_SERVER_MODE) ? GNUTLS_SERVER : GNUTLS_CLIENT );

  gnutls_transport_set_ptr(session, (gnutls_transport_ptr) sock);

  /* ensure socket is non-blocking */
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
    {
    unsigned long noBlock=1;
    ioctlsocket(fd,FIONBIO,&noBlock);
  }
#else
  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));
#endif

  /* Perform the TLS handshake
   */
  do {
    ret = gnutls_handshake(session);
    if (ret == 0) {
      break;
    }
    if (gnutls_error_is_fatal(ret)) {
      out_log(LEVEL_HIGH,"GnuTLS: handshake failed: %s\n",gnutls_strerror(ret));
      gnutls_deinit(session);
      return 1;
    }
    switch (ret) {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
        was_writing = gnutls_record_get_direction(session);
        break;
      default:
        out_log(LEVEL_HIGH,"GnuTLS: handshake failed, unknown non-fatal error: %s\n",gnutls_strerror(ret));
        gnutls_deinit(session);
        return 1;
    }

    /* we need to wait before continuing the handshake */
    FD_ZERO(&fd_r);
    FD_ZERO(&fd_w);
    tv.tv_usec = 0;
    tv.tv_sec = 5;
    if (was_writing) { FD_SET(sock,&fd_w); }
    else { FD_SET(sock,&fd_r); }

    ret = select(sock+1, &fd_r, &fd_w, NULL, &tv);

    if ( ! (FD_ISSET(sock,&fd_r) || FD_ISSET(sock,&fd_w)) ) { /* timeout */
      out_log(LEVEL_HIGH,"GnuTLS: tls_auth failed !\n");
      gnutls_deinit(session);
      return 1;
    }
    ret = 1;
  } while (ret != 0);


  context->tls.data_session = malloc(sizeof(gnutls_session));
  *( (gnutls_session*)context->tls.data_session) = session;

  return 0;
}

int tls_close_data(wzd_context_t * context)
{
  if (context->tls.data_session) {
    gnutls_deinit( *(gnutls_session*)context->tls.data_session );
    free ( (gnutls_session*)context->tls.data_session );
  }
  context->tls.data_session = NULL;
  return 0;
}

int tls_free(wzd_context_t * context)
{
  out_log(LEVEL_HIGH,"tls_free\n");
  tls_close_data(context);
  if (context->tls.session) {
    gnutls_deinit( *(gnutls_session*)context->tls.session );
    free ( (gnutls_session*)context->tls.session );
  }
  context->tls.session = NULL;
  return 0;
}

int tls_read(fd_t sock, char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
{
  wzd_context_t * context = vcontext;
  int ret=0, r;
  fd_set fd_r;
  struct timeval tv;
  gnutls_session * session;
  int alert;

  if (sock == context->controlfd)
    session = context->tls.session;
  else
    session = context->tls.data_session;

  do {
    ret = gnutls_record_recv(*session, msg, length);
    if (ret >= 0) return ret;

    if (gnutls_error_is_fatal(ret)) {
      out_log(LEVEL_HIGH,"gnutls_record_recv returned %d (%s)\n",ret,gnutls_strerror(ret));
      return -1;
    }
    switch(ret) {
      case GNUTLS_E_INTERRUPTED:
      case GNUTLS_E_AGAIN:
        FD_ZERO(&fd_r);
        FD_SET(sock,&fd_r);
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        if (timeout) {
          r = select(sock+1,&fd_r,NULL,NULL,&tv);
          if (r <= 0) return -1;
        }

        continue;
      case GNUTLS_E_WARNING_ALERT_RECEIVED:
      case GNUTLS_E_FATAL_ALERT_RECEIVED:
        alert = gnutls_alert_get (*session);
        out_log(LEVEL_INFO,"* Received alert [%d]: %s\n", alert,
            gnutls_alert_get_name(alert));
        return -1;
      case GNUTLS_E_REHANDSHAKE:
        out_log(LEVEL_HIGH,"* Received re-handshake request (gnutls)\n");
        out_log(LEVEL_HIGH,"* Report this to authors !\n");
        return -1;
      default:
        if (ret < 0) {
          out_log(LEVEL_HIGH,"* unhandled error (%d)\n",ret);
          return -1;
        }
    }
  } while (1);

  return ret;
}

int tls_write(fd_t sock, const char *msg, size_t length, int flags, unsigned int timeout, void * vcontext)
{
  wzd_context_t * context = vcontext;
  int ret=0, r;
  fd_set fd_w;
  struct timeval tv;
  gnutls_session * session;
  int alert;

  if (sock == context->controlfd)
    session = context->tls.session;
  else
    session = context->tls.data_session;

  do {
    ret = gnutls_record_send(*session, msg, length);
    if (ret >= 0) return ret;

    if (gnutls_error_is_fatal(ret)) {
      out_log(LEVEL_HIGH,"gnutls_record_send returned %d (%s)\n",ret,gnutls_strerror(ret));
      return -1;
    }
    switch(ret) {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:

        FD_ZERO(&fd_w);
        FD_SET(sock,&fd_w);
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        r = select(sock+1,NULL,&fd_w,NULL,&tv);
        if (r <= 0) return -1;

        continue;
      case GNUTLS_E_WARNING_ALERT_RECEIVED:
      case GNUTLS_E_FATAL_ALERT_RECEIVED:
        alert = gnutls_alert_get (*session);
        out_log(LEVEL_INFO,"* Received alert [%d]: %s\n", alert,
            gnutls_alert_get_name(alert));
        return -1;
      case GNUTLS_E_REHANDSHAKE:
        out_log(LEVEL_HIGH,"* Received re-handshake request (gnutls)\n");
        out_log(LEVEL_HIGH,"* Report this to authors !\n");
        return -1;
    }
  } while (1);

  return ret;
}

#endif /* HAVE_GNUTLS */
