#if SSL_SUPPORT

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <string.h>
#include <sys/time.h>
#include <fcntl.h>

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_tls.h"

#include "wzd_messages.h"

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
  status = SSL_CTX_use_certificate_file(tls_ctx, mainConfig->tls_certificate, X509_FILETYPE_PEM);
  if (status <= 0) {
    out_log(LEVEL_CRITICAL,"SSL_CTX_use_certificate_file(%s) %s\n", "", (char *)ERR_error_string(ERR_get_error(), NULL));
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

/* The mode distinction is REALLY important
 *
 * in implicit mode, we do not send anything (there's no client at this point)
 * in explicit mode, the client is waiting for our answer
 */
int tls_auth (const char *type, wzd_context_t * context)
{
  int ret;

  if (!type || type[0]==0) return 1;

  if (strcasecmp(type,"SSL")==0 || mainConfig->tls_type == TLS_IMPLICIT)
    context->ssl.data_mode = TLS_PRIV; /* SSL must hava encrypted data connection */
  else
    context->ssl.data_mode = TLS_CLEAR;

  if (mainConfig->tls_type != TLS_IMPLICIT) {
    ret = send_message_with_args(234, context, type);
  }

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
  fcntl(fd,F_SETFL,(fcntl(fd,F_GETFL)|O_NONBLOCK));
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

  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));
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

#endif /* SSL_SUPPORT */
