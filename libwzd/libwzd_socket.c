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

/** \file libwzd_socket.c
 *  \brief network sockets help functions
 *
 *  Use sockets to connect to server, using standard FTP protocol.
 *  + does not require any special configuration on server
 *  + work everywhere
 *  - client showed in SITE WHO
 *  - clear connection, unless using SSL/TLS
 *  - risks of deconnection
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include "libwzd.h"
#include "libwzd_pv.h"

#include "libwzd_socket.h"
#include "libwzd_tls.h"

#ifndef WIN32
# include <unistd.h>
# include <netinet/in.h> /* struct sockaddr_in */
# include <netdb.h> /* gethostbyname */
# include <sys/socket.h>
#else
# include <winsock2.h>
# include <io.h> /* _close */
#endif /* WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int socket_connect(const char *host, int port, const char *user, const char *pass);
int socket_disconnect(void);
int socket_read(char *buffer, int length);
int socket_write(const char *buffer, int length);
int socket_is_secure(void);

int socket_tls_switch(void);


int server_try_socket(void)
{
  char * buffer;
  int ret;

  if (!_config) return -1;

  if (!tls_init()) _config->options &= ~OPTION_TLS;

  _config->connector.mode = CNT_SOCKET;
  _config->connector.connect = &socket_connect;
  _config->connector.disconnect = &socket_disconnect;
  _config->connector.read = &socket_read;
  _config->connector.write = &socket_write;
  _config->connector.is_secure = &socket_is_secure;

  /* connected */
  _config->sock = _config->connector.connect(_config->host,_config->port,_config->user,_config->pass);
  if (!_config->sock) return -1;

  buffer = malloc(1024);

  /* read welcome message (220) */
  ret = _config->connector.read(buffer,1024);
  if (ret <= 0) goto server_try_socket_abort;
  if (ret > 0) {
    buffer[ret] = '\0';
    printf("read: [%s]\n",buffer);
  }
  if (buffer[0] != '2' || buffer[1] != '2')
    goto server_try_socket_abort;

  /* TLS mode ? */
#ifdef HAVE_GNUTLS
  ret = socket_tls_switch();
  if (ret < 0) goto server_try_socket_abort; /* XXX abort, or continue in clear mode ? */
#endif /* HAVE_GNUTLS */

  /* USER name */
  snprintf(buffer,1024,"USER %s\r\n",_config->user);
  ret = _config->connector.write(buffer,strlen(buffer));
  if (ret < 0 || ret != strlen(buffer))
    goto server_try_socket_abort;

  /* 331 User name okay, need password. */
  ret = _config->connector.read(buffer,1024);
  if (ret <= 0) goto server_try_socket_abort;
  if (ret > 0) {
    buffer[ret] = '\0';
    printf("read: [%s]\n",buffer);
  }
  if (buffer[0] != '3' || buffer[1] != '3' || buffer[2] != '1')
    goto server_try_socket_abort;

  /* PASS xxx */
  snprintf(buffer,1024,"PASS %s\r\n",_config->pass);
  ret = _config->connector.write(buffer,strlen(buffer));
  if (ret < 0 || ret != strlen(buffer))
    goto server_try_socket_abort;

  /* 230 User logged in, proceed. */
  ret = _config->connector.read(buffer,1024);
  if (ret <= 0) goto server_try_socket_abort;
  if (ret > 0) {
    buffer[ret] = '\0';
    printf("read: [%s]\n",buffer);
  }
  if (buffer[0] != '2' || buffer[1] != '3' || buffer[2] != '0')
    goto server_try_socket_abort;

  /* go into ghost mode ? */


  return _config->sock;

server_try_socket_abort:
  printf("error (last message was: [%s]\n",buffer);
  free(buffer);
  _config->connector.disconnect();
  return -1;
}
  


int socket_connect(const char *host, int port, const char *user, const char *pass)
{
  struct sockaddr_in sai;
  struct hostent* host_info;
  int sock;
#ifndef WIN32
  int i;
#endif
  int ret;

  if (!_config) return -1;

  if( (host_info = gethostbyname(host)) == NULL)
  {
    return -1;
  }
  memcpy(&sai.sin_addr, host_info->h_addr, host_info->h_length);

  sock = socket(PF_INET,SOCK_STREAM,0);
  if (sock < 0) return -1;

#ifndef WIN32
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&i,sizeof(i));
#endif

  /* make connection */
  sai.sin_port = htons((unsigned short)port);
  sai.sin_family = AF_INET;

  /* set non-blocking mode ? */
  ret = connect(sock,(struct sockaddr*)&sai,sizeof(sai));
  if (ret < 0) {
    close(sock);
    return -1;
  }

  /* try to switch to tls/ssl ?
   * not now, (explicit)
   */

  return sock;
}

int socket_disconnect(void)
{
  if (!_config) return -1;

  if (_config->sock < 0) return -1;
#ifdef HAVE_GNUTLS
  if (_config->options & OPTION_TLS) {
    tls_deinit();
  }
#endif
  close(_config->sock);
  _config->sock = -1;

  memset( &(_config->connector), 0, sizeof(_config->connector) );

  return 0;
}

int socket_read(char *buffer, int length)
{
  if (!_config) return -1;
  if (_config->sock < 0) return -1;
  
  return read(_config->sock, buffer, length);
}

int socket_write(const char *buffer, int length)
{
  if (!_config) return -1;
  if (_config->sock < 0) return -1;

  return write(_config->sock, buffer, length);
}

int socket_is_secure(void)
{
  if (!_config) return 0; /* NOT secure */
  return ( (_config->options & OPTION_TLS) ? 1 : 0 );
}

int socket_tls_switch(void)
{
  char * buffer;
  int ret;

  if (!_config) return -1;
  if ( (_config->options & OPTION_TLS) ) return -1; /* already switched ?! */
  if (_config->sock < 0) return -1;

  buffer = malloc(1024);

  /* AUTH TLS */
  snprintf(buffer,1024,"AUTH TLS\r\n");
  ret = _config->connector.write(buffer,strlen(buffer));
  if (ret < 0 || ret != strlen(buffer))
    goto socket_tls_switch_abort;

  /* 234 234 AUTH command OK. Initializing TLS mode */
  ret = _config->connector.read(buffer,1024);
  if (ret <= 0) goto socket_tls_switch_abort;
  if (ret > 0) {
    buffer[ret] = '\0';
    printf("read: [%s]\n",buffer);
  }
  if (buffer[0] != '2' || buffer[1] != '3' || buffer[2] != '4')
    goto socket_tls_switch_abort;

  tls_handshake(_config->sock);
  if (ret < 0) goto socket_tls_switch_abort; /* ... */

  _config->connector.read = &tls_read;
  _config->connector.write = &tls_write;
  _config->options |= OPTION_TLS;

  return 0;

socket_tls_switch_abort:
  free(buffer);
  _config->options &= ~OPTION_TLS;
  return -1;
}
