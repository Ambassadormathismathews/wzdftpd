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

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

typedef void wzd_context_t;

#include "wzd_log.h"
#include "wzd_socket.h"

/*************** ul2a ***********************************/

char * ul2a(unsigned long q)
{
  static char host[64];

  sprintf(host, "%u.%u.%u.%u",
    ((unsigned char *)&q)[0], /* assume network order */
    ((unsigned char *)&q)[1],
    ((unsigned char *)&q)[2],
    ((unsigned char *)&q)[3]);

  return host;
}

/*************** socket_make ****************************/

/** bind socket at port, if port = 0 picks first free and set it
 * \return -1 or socket
 */
int socket_make(const char *ip, unsigned int *port, int nListen)
{
  struct sockaddr_in sai;
#if defined(IPV6_SUPPORT)
  struct sockaddr_in6 sai6;
#endif
  unsigned int c;
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
  SOCKET sock;
#else
  int sock;
#endif

  if (ip==NULL || strcmp(ip,"*")==0)
    sai.sin_addr.s_addr = htonl(INADDR_ANY);
  else
  {
    struct hostent* host_info;
    // try to decode dotted quad notation
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
    if ((sai.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
#else
    if(!inet_aton(ip, &sai.sin_addr))
#endif
    {
      const char *real_ip;
      real_ip = ip;
      if (real_ip[0]=='+') real_ip++;
      // failing that, look up the name
      if( (host_info = gethostbyname(real_ip)) == NULL)
      {
	out_err(LEVEL_CRITICAL,"Could not resolve ip %s %s:%d\n",real_ip,__FILE__,__LINE__);
	return -1;
      }
      memcpy(&sai.sin_addr, host_info->h_addr, host_info->h_length);
   }
  }

#if !defined(IPV6_SUPPORT)
  if ((sock = socket(PF_INET,SOCK_STREAM,0)) < 0) {
#else
  if ((sock = socket(PF_INET6,SOCK_STREAM,0)) < 0) {
#endif
    out_err(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

  c = 1;
#ifndef WINSOCK_SUPPORT
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&c,sizeof(c));
#endif

/*  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));*/

#if !defined(IPV6_SUPPORT)
  sai.sin_family = PF_INET;
  sai.sin_port = htons((unsigned short)*port); /* any port */

  if (bind(sock,(struct sockaddr *)&sai, sizeof(sai))==-1) {
#ifdef __CYGWIN__
    out_log(LEVEL_CRITICAL,"Could not bind sock on port %d %s:%d\n", *port, __FILE__, __LINE__);
#else
    out_log(LEVEL_CRITICAL,"Could not bind sock on port %d (error %s) %s:%d\n", *port, strerror(errno),__FILE__, __LINE__);
#endif
    socket_close(sock);
    return -1;
  }
#else /* IPV6_SUPPORT */
  sai6.sin6_family = PF_INET6;
  sai6.sin6_port = htons(*port); /* any port */
  sai6.sin6_flowinfo = 0;
  sai6.sin6_addr = in6addr_any;
  if (bind(sock,(struct sockaddr *)&sai6, sizeof(sai6))==-1) {
#ifdef __CYGWIN__
    out_log(LEVEL_CRITICAL,"Could not bind sock on port %d %s:%d\n", *port, __FILE__, __LINE__);
#else
    out_log(LEVEL_CRITICAL,"Could not bind sock on port %d (error %s) %s:%d\n", *port, strerror(errno),__FILE__, __LINE__);
#endif
    socket_close(sock);
    return -1;
  }
#endif /* IPV6_SUPPORT */

  c = sizeof(struct sockaddr_in);
  getsockname(sock, (struct sockaddr *)&sai, &c);
  {
    unsigned char myip[4];
    memcpy(myip,&sai.sin_addr,sizeof(myip));
  }

  listen(sock,nListen);

  *port = ntohs(sai.sin_port);
  return sock;
}

 
/*************** socket_close ***************************/
int socket_close(int sock)
{
#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
  char acReadBuffer[256];
  int nNewBytes;

  /* Disallow any further data sends.  This will tell the other side
   * that we want to go away now.  If we skip this step, we don't
   * shut the connection down nicely.
   */
  if (shutdown(sock, SD_SEND) == SOCKET_ERROR) {
    return -1;
  }
  /* Receive any extra data still sitting on the socket.  After all
   * data is received, this call will block until the remote host
   * acknowledges the TCP control packet sent by the shutdown above.
   * Then we'll get a 0 back from recv, signalling that the remote
   * host has closed its side of the connection.
   */
  while (1) {
	  nNewBytes = recv(sock, acReadBuffer, 256, 0);
	  if (nNewBytes == SOCKET_ERROR) {
		  return 1;
	  }
	  else if (nNewBytes != 0) {
		  out_err(LEVEL_CRITICAL,"\nFYI, received %d unexpected bytes during shutdown.\n",nNewBytes);
	  }
	  else {
		  /* Okay, we're done! */
		  break;
	  }
  }

    /* Close the socket. */
    if (closesocket(sock) == SOCKET_ERROR) {
        return 1;
    }

  return 0;
#else
  return close(sock);
#endif
}


/*************** socket_accept **************************/

int socket_accept(int sock, unsigned char *remote_host, unsigned int *remote_port)
{
  int new_sock;
#if !defined(IPV6_SUPPORT)
  struct sockaddr_in from;
  unsigned int len = sizeof(struct sockaddr_in);
#else
  struct sockaddr_in6 from;
  unsigned int len = sizeof(struct sockaddr_in6);
#endif
  int i;

  new_sock = accept(sock, (struct sockaddr *)&from, &len);

  if (new_sock < 0) {
    out_log(LEVEL_CRITICAL,"Accept failed %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

#if defined(_MSC_VER) || (defined(__CYGWIN__) && defined(WINSOCK_SUPPORT))
  {
    unsigned long noBlock=1;
    ioctlsocket(sock,FIONBIO,&noBlock);
  }
#else
  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));
#endif

#ifndef LINUX
#ifndef WINSOCK_SUPPORT
/* see lundftpd : socket.c for explanation */
  setsockopt(new_sock, SOL_SOCKET, SO_SNDLOWAT, (char*)&i, sizeof(i));
#endif
#endif

#if !defined(IPV6_SUPPORT)
#ifndef _MSC_VER
  bcopy((const char*)&from.sin_addr.s_addr, (char*)remote_host, sizeof(unsigned long));
#else
  /* FIXME VISUAL memory zones must NOT overlap ! */
  memcpy((char*)remote_host, (const char*)&from.sin_addr.s_addr, sizeof(unsigned long));
#endif
  *remote_port = ntohs(from.sin_port);
#else
  bcopy((const char*)&from.sin6_addr.s6_addr, (char*)remote_host, 16);
  *remote_port = ntohs(from.sin6_port);
#endif

  return new_sock;
}

/*************** socket_connect *************************/

int socket_connect(unsigned long remote_host, int remote_port, int localport, int fd)
{
  int sock;
  struct sockaddr_in sai;
  unsigned int len = sizeof(struct sockaddr_in);
  int ret;
  int on=1;

  if ((sock = socket(PF_INET,SOCK_STREAM,0)) < 0) {
    out_log(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

  /* See if we can get the local port we want to bind to */
  /* If we can't, just let the computer choose a port for us */
  sai.sin_family = AF_INET;
  getsockname(fd,(struct sockaddr *)&sai,&len);
  sai.sin_port = htons((unsigned short)localport);

#ifndef WINSOCK_SUPPORT
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
#endif

  /* attempt to bind the socket - if it doesn't work, it is not a problem */
  bind(sock,(struct sockaddr *)&sai,sizeof(sai));

  /* makes the connection */
  sai.sin_port = htons((unsigned short)remote_port);
  sai.sin_family = AF_INET;
  memcpy(&sai.sin_addr,&remote_host,sizeof(remote_host));

/*  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));*/

#ifndef LINUX
#ifndef WINSOCK_SUPPORT
/* see lundftpd : socket.c for explanation */
  setsockopt(sock, SOL_SOCKET, SO_SNDLOWAT, (char*)&ret, sizeof(ret));
#endif
#endif

  ret = connect(sock,(struct sockaddr *)&sai, len);
  if (ret < 0) {
    out_log(LEVEL_CRITICAL,"Connect failed %s:%d\n", __FILE__, __LINE__);
    socket_close (sock);
    return -1;
  }

  return sock;
}
