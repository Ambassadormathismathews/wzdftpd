/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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

#ifdef SSL_SUPPORT

#if defined  __CYGWIN__ && defined WINSOCK_SUPPORT
#include <winsock2.h>
#endif

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <string.h>
#include <sys/time.h>
#include <fcntl.h>
#include <dlfcn.h>

#include "wzd_debug.h"
#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_tls.h"

#include "wzd_messages.h"


#if defined __CYGWIN__ && defined WINSOCK_SUPPORT


typedef int (*imp_tls_init)(SSL_CTX **ctx, const char *certificate);
typedef int (*imp_tls_exit)(SSL_CTX **tls_ctx);

typedef int (*imp_tls_auth)(const char *type, wzd_context_t * context, wzd_config_t * config);
typedef int (*imp_tls_auth_cont)(wzd_context_t * context);
typedef int (*imp_tls_init_datamode)(int sock, wzd_ssl_t * wzd_ssl,SSL_CTX * tls_ctx, const char * tls_cipher_list);
typedef int (*imp_tls_close_data)(wzd_ssl_t * ssl);
typedef int (*imp_tls_free)(wzd_ssl_t * ssl);

typedef int (*imp_tls_auth_data_cont)(wzd_ssl_t * wzd_ssl);

typedef int (*imp_tls_read)(int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext);
typedef int (*imp_tls_write)(int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext);

/*#define TLS_WRAPPER_NAME "./wzd_tlswrap.dll"*/

typedef struct {
  void *		handle;
  imp_tls_init		tls_init;
  imp_tls_exit		tls_exit;
  imp_tls_auth		tls_auth;
  imp_tls_auth_cont	tls_auth_cont;
  imp_tls_init_datamode	tls_init_datamode;
  imp_tls_close_data	tls_close_data;
  imp_tls_free		tls_free;
  imp_tls_auth_data_cont	tls_auth_data_cont;
  imp_tls_read		tls_read;
  imp_tls_write		tls_write;
} tls_wrapper_fct_t;

tls_wrapper_fct_t * tls_wrapper_fct=NULL;

int tls_init(void)
{
  void * handle;
  void * ptr;
  int ret;
  char TLS_WRAPPER_NAME[256];

  out_err(LEVEL_FLOOD,"Loading TLS wrapper\n");

  if (server_get_param("tls_wrapper",TLS_WRAPPER_NAME,256,mainConfig->param_list))
  {
    out_err(LEVEL_CRITICAL,"Could not get wrapper name\n");
    return 1;
  }

  handle = dlopen(TLS_WRAPPER_NAME,RTLD_NOW);
  if (!handle)
  {
    out_err(LEVEL_CRITICAL,"Could not open wrapper %s (error %s)\n",
	TLS_WRAPPER_NAME, dlerror());
    return 1;
  }
  
  tls_wrapper_fct = malloc(sizeof(tls_wrapper_fct_t));
  tls_wrapper_fct->handle = handle;

  ptr = dlsym(handle,"tls_init");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_init\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_init = ptr;
  ptr = dlsym(handle,"tls_exit");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_exit\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_exit = ptr;
  ptr = dlsym(handle,"tls_auth");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_auth\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_auth = ptr;
  ptr = dlsym(handle,"tls_auth_cont");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_auth_cont\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_auth_cont = ptr;
  ptr = dlsym(handle,"tls_init_datamode");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_init_datamode\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_init_datamode = ptr;
  ptr = dlsym(handle,"tls_close_data");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_close_data\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_close_data = ptr;
  ptr = dlsym(handle,"tls_free");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_free\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_free = ptr;
  ptr = dlsym(handle,"tls_auth_data_cont");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_auth_data_cont\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_auth_data_cont = ptr;
  ptr = dlsym(handle,"tls_read");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_read\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_read = ptr;
  ptr = dlsym(handle,"tls_write");
  if (!ptr) {
    out_err(LEVEL_CRITICAL,"Missing function tls_write\n");
    free(tls_wrapper_fct);
    return 1;
  }
  tls_wrapper_fct->tls_write = ptr;

  ret = (tls_wrapper_fct->tls_init)(&mainConfig->tls_ctx,mainConfig->tls_certificate);
  switch (ret) {
  case 0:
    return 0;
  case 1:
    out_err(LEVEL_CRITICAL,"tls_init error: SSL_CTX_new failed\n");
    break;
  case 2:
    out_err(LEVEL_CRITICAL,"tls_init error: SSL_CTX_use_certificate_file failed\n");
    out_err(LEVEL_CRITICAL,"  probable error causes: missing certificate,\n");
    out_err(LEVEL_CRITICAL,"  incorrect path, permissions etc.\n");
    break;
  case 3:
    out_err(LEVEL_CRITICAL,"tls_init error: SSL_CTX_use_PrivateKey_file failed\n");
    out_err(LEVEL_CRITICAL,"  probable error causes: missing certificate,\n");
    out_err(LEVEL_CRITICAL,"  incorrect path, permissions etc.\n");
    break;
  default:
    out_err(LEVEL_CRITICAL,"tls_init returned %d\n",ret);
  }
  return ret;
}

int tls_exit(void)
{
  int ret;
  if (!tls_wrapper_fct) return 1;
  ret = (tls_wrapper_fct->tls_exit)(&mainConfig->tls_ctx);
  free(tls_wrapper_fct);
  tls_wrapper_fct = NULL;
  return ret;
}

int tls_auth (const char *type, wzd_context_t * context)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_auth)(type,context,mainConfig);
}

int tls_auth_cont(wzd_context_t * context)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_auth_cont)(context);
}

int tls_init_datamode(int sock, wzd_context_t * context)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_init_datamode)(sock,&context->ssl,
      mainConfig->tls_ctx, mainConfig->tls_cipher_list);
}

int tls_close_data(wzd_context_t * context)
{
  if (!tls_wrapper_fct) return 1;
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_close_data)(&context->ssl);
}

int tls_free(wzd_context_t * context)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_free)(&context->ssl);
}

int tls_auth_data_cont(wzd_context_t * context)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_auth_data_cont)(&context->ssl);
}

int tls_read(int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_read)(sock,msg,length,flags,timeout,vcontext);
}

int tls_write(int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext)
{
  if (!tls_wrapper_fct) return 1;
  return (tls_wrapper_fct->tls_write)(sock,msg,length,flags,timeout,vcontext);
}





#else /* defined __CYGWIN__ && defined WINSOCK_SUPPORT */


/*************** tls_auth_setfd_set *********************/

void tls_auth_setfd_set(wzd_context_t * context, fd_set *r, fd_set *w)
{
  int socket;

  socket = SSL_get_fd(context->ssl.obj);

  if (context->ssl.ssl_fd_mode == TLS_READ)
    FD_SET(socket,r);
  else if (context->ssl.ssl_fd_mode == TLS_WRITE)
    FD_SET(socket,w);
}

/*************** tls_auth_data_setfd_set ***************/

void tls_auth_data_setfd_set(wzd_context_t * context, fd_set *r, fd_set *w)
{
  int socket;

  socket = SSL_get_fd(context->ssl.data_ssl);

  if (context->ssl.ssl_fd_mode == TLS_READ)
    FD_SET(socket,r);
  else if (context->ssl.ssl_fd_mode == TLS_WRITE)
    FD_SET(socket,w);
}


/*************** tls_init ****************************/

int tls_init(void)
{
  int status;
  SSL_CTX * tls_ctx;

  ERR_load_ERR_strings();
  SSL_load_error_strings();	/* readable error messages */
  SSL_library_init();		/* initialize library */

  mainConfig->tls_ctx = tls_ctx = SSL_CTX_new(SSLv23_method());
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
  status = SSL_CTX_use_certificate_chain_file(tls_ctx, mainConfig->tls_certificate);
  if (status <= 0) {
    out_log(LEVEL_CRITICAL,"SSL_CTX_use_certificate_chain_file(%s) %s\n", "", (char *)ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  /* set private key file - usually the same */
  status = SSL_CTX_use_PrivateKey_file(tls_ctx, mainConfig->tls_certificate, X509_FILETYPE_PEM);
  if (status <= 0) {
    out_log(LEVEL_CRITICAL,"SSL_CTX_use_PrivateKey_file(%s) %s\n", "", (char *)ERR_error_string(ERR_get_error(), NULL));
    return 1;
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

int tls_read(int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext)
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
      out_err(LEVEL_CRITICAL,"SSL_read failed %d\n",sslerr);
      return -1;
    }

    r = select(sock+1,&fd_r,&fd_w,NULL,&tv);
  } while (ret == -1 && r != 0);

  if (r==0)
    return -1;
  return ret;
}

/*************** tls_write ***************************/

int tls_write(int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext)
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
      out_err(LEVEL_CRITICAL,"SSL_write failed\n");
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

  context->ssl.obj = SSL_new(mainConfig->tls_ctx);
  SSL_set_cipher_list(context->ssl.obj,mainConfig->tls_cipher_list);
  ret = SSL_set_fd(context->ssl.obj,context->controlfd);
  if (ret != 1) {
    out_log(LEVEL_CRITICAL,"SSL_set_fd failed (%s)\n",ERR_error_string(ERR_get_error(),NULL));
    return 1;
  }

  return tls_auth_cont(context);
}

/*************** tls_auth_cont ***********************/

int tls_auth_cont(wzd_context_t * context)
{
/* non blocking test */
#if 1
  SSL * ssl = context->ssl.obj;
  int fd, ret, status, sslerr;
  fd_set fd_r, fd_w;
  struct timeval tv;

  SSL_set_accept_state(ssl);
  fd = SSL_get_fd(ssl);
  /* ensure socket is non-blocking */
#if defined  __CYGWIN__ && defined WINSOCK_SUPPORT
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
      out_log(LEVEL_FLOOD,"control connection succesfully switched to ssl\n");
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
        out_log(LEVEL_CRITICAL,"Error accepting connection: ret %d error code %d : %s\n",status,sslerr,
          ERR_error_string(SSL_get_error(context->ssl.obj,status),NULL));
        out_log(LEVEL_CRITICAL,"Error accepting connection: ret %d error code %d : %s\n",status,ERR_get_error(),
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
      out_log(LEVEL_CRITICAL,"Error accepting connection: ret %d error code %d : %s\n",ret,SSL_get_error(context->ssl.obj,ret),
        ERR_error_string(SSL_get_error(context->ssl.obj,ret),NULL));
      out_log(LEVEL_CRITICAL,"Error accepting connection: ret %d error code %d : %s\n",ret,ERR_get_error(),
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

  SSL_set_cipher_list(context->ssl.data_ssl, mainConfig->tls_cipher_list);

#if defined  __CYGWIN__ && defined WINSOCK_SUPPORT
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
  int fd,r;

  SSL_set_accept_state(ssl);
  fd = SSL_get_fd(ssl);
  do {
    status = SSL_accept(ssl);
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
          out_log(LEVEL_CRITICAL,"tls_auth_data_cont: error accepting: %s\n",
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

#endif /* defined __CYGWIN__ && defined WINSOCK_SUPPORT */

#endif /* SSL_SUPPORT */
