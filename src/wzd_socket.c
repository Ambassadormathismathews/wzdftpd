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
/** \file wzd_socket.c
  * \brief Helper routines for network access
  */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#if defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>

#define EINPROGRESS WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EISCONN     WSAEISCONN

#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "wzd_structs.h"

#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_socket.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

/*************** ul2a ***********************************/

char * ul2a(unsigned long q)
{
  static char host[64];

  snprintf(host, 64, "%u.%u.%u.%u",
    ((unsigned char *)&q)[0], /* assume network order */
    ((unsigned char *)&q)[1],
    ((unsigned char *)&q)[2],
    ((unsigned char *)&q)[3]);

  return host;
}

/*************** socket_make ****************************/

int socket_getipbyname(const char *name, char *buffer, size_t length)
{
  struct hostent * host;
  int ret=-1;
  int sz = MIN(length,sizeof(host->h_addr_list));

  wzd_mutex_lock(server_mutex);
  host = gethostbyname(name);
  if (host) {
    memcpy(buffer, host->h_addr, sz);
    ret = 0;
  }
  wzd_mutex_unlock(server_mutex);

  return ret;
}

/*************** socket_make ****************************/

/** bind socket at port, if port = 0 picks first free and set it
 * \return -1 or socket
 */
fd_t socket_make(const char *ip, unsigned int *port, int nListen)
{
  size_t c;
  fd_t sock;
  struct sockaddr_in sai;
#if defined(IPV6_SUPPORT)
  struct sockaddr_in6 sai6;

  memset(&sai6, 0, sizeof(struct sockaddr_in6));
#endif
  memset(&sai, 0, sizeof(struct sockaddr_in));

  if (ip==NULL || strcmp(ip,"*")==0)
#if defined(IPV6_SUPPORT)
    memset(&sai6.sin6_addr,0,16);
#else
    sai.sin_addr.s_addr = htonl(INADDR_ANY);
#endif
  else
  {
    struct hostent* host_info;
    // try to decode dotted quad notation
#if defined(_MSC_VER) || defined(__sun__)
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
  if ((sock = socket(PF_INET,SOCK_STREAM,0)) == (fd_t)-1) {
#else
  if ((sock = socket(PF_INET6,SOCK_STREAM,0)) == (fd_t)-1) {
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
  sai6.sin6_port = htons((unsigned short)*port); /* any port */
  sai6.sin6_flowinfo = 0;
/*  sai6.sin6_addr = IN6ADDR_ANY_INIT; */ /* FIXME VISUAL */
  memset(&sai6.sin6_addr,0,16);
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
int socket_close(fd_t sock)
{
#if defined(_MSC_VER)
  char acReadBuffer[256];
  int nNewBytes;

  if (sock == (fd_t)-1) return 0; /* invalid fd */

  /* Disallow any further data sends.  This will tell the other side
   * that we want to go away now.  If we skip this step, we don't
   * shut the connection down nicely.
   */
  if (shutdown(sock, SD_SEND) == SOCKET_ERROR) {
    /* Close the socket. */
    if (closesocket(sock) == SOCKET_ERROR) {
        return 1;
    }
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
      /* Close the socket. */
      if (closesocket(sock) == SOCKET_ERROR) {
          return 1;
      }
      return 1;
    }
    else if (nNewBytes != 0) {
      out_err(LEVEL_FLOOD,"\nFYI, received %d unexpected bytes during shutdown.\n",nNewBytes);
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

int socket_accept(fd_t sock, unsigned char *remote_host, unsigned int *remote_port)
{
  fd_t new_sock;
#if !defined(IPV6_SUPPORT)
  struct sockaddr_in from;
  size_t len = sizeof(struct sockaddr_in);
#else
  struct sockaddr_in6 from;
  size_t len = sizeof(struct sockaddr_in6);
#endif
#if 0
  int i=0;
#endif

  new_sock = accept(sock, (struct sockaddr *)&from, &len);

  if (new_sock == (fd_t)-1) {
    out_log(LEVEL_CRITICAL,"Accept failed %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

#if defined(WIN32)
  {
    unsigned long noBlock=1;
    ioctlsocket(sock,FIONBIO,&noBlock);
  }
#else
  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));
#endif

#if 0
#ifndef LINUX
#ifndef WINSOCK_SUPPORT
/* see lundftpd : socket.c for explanation */
  setsockopt(new_sock, SOL_SOCKET, SO_SNDLOWAT, &i, sizeof(i)); /** \fixme set correct value for SND_LOWAT ? */
#endif
#endif
#endif /* 0 */

#if !defined(IPV6_SUPPORT)
#ifndef _MSC_VER
  bcopy((const char*)&from.sin_addr.s_addr, (char*)remote_host, sizeof(unsigned long));
#else
  /* FIXME VISUAL memory zones must NOT overlap ! */
  memcpy((char*)remote_host, (const char*)&from.sin_addr.s_addr, sizeof(unsigned long));
#endif  /* _MSC_VER */
  *remote_port = ntohs(from.sin_port);
#else
#ifndef _MSC_VER
  bcopy((const char*)&from.sin6_addr.s6_addr, (char*)remote_host, 16);
  *remote_port = ntohs(from.sin6_port);
#else
  /* FIXME VISUAL memory zones must NOT overlap ! */
  memcpy((char*)remote_host, (const char*)&from.sin6_addr.s6_addr, 16);
#endif /* _MSC_VER */
#endif /* IPV6_SUPPORT */

  return new_sock;
}



#ifdef WIN32

/*
 * waitconnect() returns:
 * 0    fine connect
 * -1   select() error
 * 1    select() timeout
 * 2    select() returned with an error condition
 */
static int _waitconnect(fd_t sockfd, /* socket */
                int timeout_msec)
{
  fd_set fd;
  fd_set errfd;
  struct timeval interval;
  int rc;

  /* now select() until we get connect or timeout */
  FD_ZERO(&fd);
  FD_SET(sockfd, &fd);

  FD_ZERO(&errfd);
  FD_SET(sockfd, &errfd);

  interval.tv_sec = timeout_msec/1000;
  timeout_msec -= interval.tv_sec*1000;

  interval.tv_usec = timeout_msec*1000;

  rc = select(sockfd+1, NULL, &fd, &errfd, &interval);
  if(-1 == rc)
    /* error, no connect here, try next */
    return -1;

  else if(0 == rc)
    /* timeout, no connect today */
    return 1;

  if(FD_ISSET(sockfd, &errfd))
    /* error condition caught */
    return 2;

  /* we have a connect! */
  return 0;
}


#endif /* WIN32 */



/*************** socket_connect *************************/

int socket_connect(unsigned char * remote_host, int family, int remote_port, int localport, fd_t fd, unsigned int timeout)
{
  fd_t sock;
  struct sockaddr *sai;
  struct sockaddr_in sai4;
#if defined(IPV6_SUPPORT)
  struct sockaddr_in6 sai6;
#endif
  size_t len = sizeof(struct sockaddr_in);
  int ret;
  int on=1;
#ifdef WIN32
  int error;
#endif

  if (family == WZD_INET4)
  {
    len = sizeof(sai4);

    if ((sock = socket(PF_INET,SOCK_STREAM,0)) == (fd_t)-1) {
      out_log(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
      return -1;
    }

    /* See if we can get the local port we want to bind to */
    /* If we can't, just let the computer choose a port for us */
    sai4.sin_family = AF_INET;
    getsockname(fd,(struct sockaddr *)&sai4,&len);
    sai4.sin_port = htons((unsigned short)localport);

#ifndef WINSOCK_SUPPORT
    ret = setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
#endif

    /* attempt to bind the socket - if it doesn't work, it is not a problem */
    if (localport) {
      bind(sock,(struct sockaddr *)&sai4,sizeof(sai4));
    }

    /* makes the connection */
    sai4.sin_port = htons((unsigned short)remote_port);
    sai4.sin_family = AF_INET;
    memcpy(&sai4.sin_addr,remote_host,sizeof(sai4.sin_addr));

    sai = (struct sockaddr *)&sai4;

  } /* family == WZD_INET4 */
#if defined(IPV6_SUPPORT)
  else if (family == WZD_INET6)
  {
    len = sizeof(sai6);

#if 0
    {
      char buffer[256];
      inet_ntop(AF_INET6,remote_host,buffer,256);
      out_log(LEVEL_FLOOD,"Trying to connect to %s : %d (localport: %d)\n",buffer,remote_port,localport);
    }
#endif /* 0 */

    if ((sock = socket(PF_INET6,SOCK_STREAM,0)) < 0) {
      out_log(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
      return -1;
    }

    /* See if we can get the local port we want to bind to */
    /* If we can't, just let the computer choose a port for us */
    sai6.sin6_family = AF_INET6;
    sai6.sin6_flowinfo = 0;
#ifndef _MSC_VER /* FIXME VISUAL */
    sai6.sin6_scope_id = 0;
#endif
    getsockname(fd,(struct sockaddr *)&sai6,&len);
    sai6.sin6_port = htons((unsigned short)localport);

#ifndef WINSOCK_SUPPORT
    ret = setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
#endif

    /* attempt to bind the socket - if it doesn't work, it is not a problem */
    if (localport) {
      bind(sock,(struct sockaddr *)&sai6,sizeof(sai6));
    }

    /* makes the connection */
    sai6.sin6_port = htons((unsigned short)remote_port);
    sai6.sin6_family = AF_INET6;
    sai6.sin6_flowinfo = 0;
#ifndef _MSC_VER /* FIXME VISUAL */
    sai6.sin6_scope_id = 0;
#endif
    memcpy(&sai6.sin6_addr,remote_host,16);

    sai = (struct sockaddr *)&sai6;

  } /* family == WZD_INET6 */
#endif /* IPV6_SUPPORT */
  else
  {
    return -1; /* invalid protocol */
  }

#ifndef LINUX
#ifndef WINSOCK_SUPPORT
/* see lundftpd : socket.c for explanation */
  setsockopt(sock, SOL_SOCKET, SO_SNDLOWAT, (char*)&ret, sizeof(ret));
#endif
#endif

  if (timeout != 0)
  {

/* set non-blocking mode */
#if defined(WIN32)
    {
      unsigned long noBlock=1;
      ret = ioctlsocket(sock,FIONBIO,&noBlock);
    }
#else
    fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));
#endif

#if defined(WIN32)


    ret = connect(sock, sai, len);
    if (ret == -1) {
      /*long timeout_ms=300000;*/ /* default to 5 min */
      long timeout_ms=5000;
      error = WSAGetLastError();

      switch (error) {
        case EINPROGRESS:
        case WSAEWOULDBLOCK:
        case EAGAIN:
          ret = _waitconnect(sock,timeout_ms);
          error = WSAGetLastError();
          if (ret==1) ret=0; /* if we get a timeout here, we do as if we were connected */
          break;
        default:
          out_log(LEVEL_INFO,"Connect failed %s:%d\n", __FILE__, __LINE__);
          out_log(LEVEL_INFO," errno: %d\n",error);
          break;
      }
    }

    if (ret == 0 || error==0 || error==WSAEWOULDBLOCK || error==WSAEISCONN) {
      out_err(LEVEL_FLOOD,"Connection OK\n");
      return sock;
    }


    out_log(LEVEL_INFO,"Connect failed %s:%d\n", __FILE__, __LINE__);
    out_log(LEVEL_INFO," errno: %d\n",error);
    socket_close (sock);
    return -1;






    ret = connect(sock, sai, len);
    if (ret == SOCKET_ERROR) {
      errno = WSAGetLastError();
      if (errno != WSAEWOULDBLOCK)
      {
        out_log(LEVEL_INFO,"Connect failed %s:%d\n", __FILE__, __LINE__);
        out_log(LEVEL_INFO," errno: %d\n",errno);
        socket_close (sock);
        return -1;
      }
    } else
      return sock;
  if (ret == SOCKET_ERROR)
  {
    int retry;
    int save_errno;
    for (retry=0; retry<100; retry++)
    {
      ret = socket_wait_to_write(sock,timeout);
      if (ret == 0) /* ok */
        break;
      if (ret == 1) /* timeout */
      {
        socket_close(sock);
        errno = ETIMEDOUT;
        return -1;
      }
      if (errno == WSAEWOULDBLOCK) {
/*        out_log(LEVEL_FLOOD,"WSAEWOULDBLOCK (removed me: %s:%d)\n",__FILE__,__LINE__);*/
        Sleep(5); /* wait 5 milliseconds before retrying */
        continue;
      }
      /* error */
      out_log(LEVEL_INFO,"Error during connection %d: %s\n",errno,strerror(errno));
      save_errno = WSAGetLastError();
      socket_close(sock);
      WSASetLastError(save_errno);
      return -1;
    }
  }
#else /* WIN32 */

  ret = connect(sock, sai, len);
  if (ret >= 0) return sock;
    do {
      if ( (ret=socket_wait_to_write(sock,timeout))!=0) {
        if (ret == 1) { /* timeout */
          out_log(LEVEL_FLOOD,"Connect failed (timeout) %s:%d\n", __FILE__, __LINE__);
          socket_close(sock);
          errno = ETIMEDOUT;
          return -1;
        }
        if (errno == EINPROGRESS) continue;
        out_log(LEVEL_NORMAL,"Error during connection %d: %s\n",errno,strerror(errno));
        socket_close(sock);
        return -1;
      }
      break;
    } while (1);
#endif /* WIN32 */

  } /* if (timeout) */

  if (ret < 0) {
    ret = errno;
    out_log(LEVEL_FLOOD,"Connect failed %d %s:%d\n", errno, __FILE__, __LINE__);
    socket_close (sock);
    errno = ret;
#ifdef WIN32
    WSASetLastError(ret);
#endif
    return -1;
  }

  return sock;
}

/* Returns the local/remote port for the socket. */
int get_sock_port(int sock, int local)
{
#if !defined(WIN32) && !defined(__sun__)
  struct sockaddr_storage from;
  char strport[NI_MAXSERV];
#else
  struct sockaddr_in from;
#endif
  size_t fromlen;

  /* Get IP address of client. */
  fromlen = sizeof(from);
  memset(&from, 0, sizeof(from));
  if (local) {
    if (getsockname(sock, (struct sockaddr *)&from, &fromlen) < 0) {
      out_log(LEVEL_CRITICAL,"getsockname failed: %.100s", strerror(errno));
      return 0;
    }
  } else {
    if (getpeername(sock, (struct sockaddr *)&from, &fromlen) < 0) {
      out_log(LEVEL_CRITICAL,"getpeername failed: %.100s", strerror(errno));
      return 0;
    }
  }

#if !defined(WIN32) && !defined(__sun__)
  /* Work around Linux IPv6 weirdness */
  if (from.ss_family == AF_INET6)
    fromlen = sizeof(struct sockaddr_in6);

  /* Return port number. */
  if (getnameinfo((struct sockaddr *)&from, fromlen, NULL, 0,
        strport, sizeof(strport), NI_NUMERICSERV) != 0)
    out_log(LEVEL_CRITICAL,"get_sock_port: getnameinfo NI_NUMERICSERV failed");
  return atoi(strport);
#else
  return ntohs(from.sin_port);
#endif
}

/* Returns remote/local port number for the current connection. */

int socket_get_remote_port(fd_t sock)
{
  return get_sock_port(sock, 0);
}

int socket_get_local_port(fd_t sock)
{
  return get_sock_port(sock, 1);
}

int socket_wait_to_read(fd_t sock, unsigned int timeout)
{
  int ret;
  int save_errno;
  fd_set rfds, wfds, efds;
  struct timeval tv;

  if (sock<0) return -1;

  if (timeout==0)
    return 0; /* blocking sockets are always ready */
  else {
    while (1) {
      FD_ZERO(&rfds);
      FD_ZERO(&wfds);
      FD_ZERO(&efds);
      FD_SET(sock,&rfds);
      FD_SET(sock,&wfds);
      FD_SET(sock,&efds);
      tv.tv_sec = timeout; tv.tv_usec = 0;

#if defined(_MSC_VER)
      ret = select(0,&rfds,&wfds,&efds,&tv);
#else
      ret = select(sock+1,&rfds,&wfds,&efds,&tv);
#endif
      save_errno = errno;

      if (FD_ISSET(sock,&efds)) {
        if (save_errno == EINTR) continue;
        out_log(LEVEL_CRITICAL,"Error during socket_wait_to_read: %d %s\n",save_errno,strerror(save_errno));
        return -1;
      }
#if 0
      if (FD_ISSET(sock,&wfds)) {
        if (save_errno == EINTR) continue;
        out_log(LEVEL_CRITICAL,"WTF, socket %d wants to write during socket_wait_to_read: %s\n",sock,strerror(save_errno));
        return -1;
      }
#endif
      if (!FD_ISSET(sock,&rfds)) /* timeout */
        return 1;
      break;
    }
    return 0;
  } /* timeout */

  return -1;
}

int socket_wait_to_write(fd_t sock, unsigned int timeout)
{
  int ret;
  int save_errno;
  fd_set rfds, wfds, efds;
  struct timeval tv;

  if (sock<0) return -1;

  if (timeout==0)
    return 0; /* blocking sockets are always ready */
  else {
    while (1) {
      FD_ZERO(&rfds);
      FD_ZERO(&wfds);
      FD_ZERO(&efds);
      FD_SET(sock,&rfds);
      FD_SET(sock,&wfds);
      FD_SET(sock,&efds);
      tv.tv_sec = timeout; tv.tv_usec = 0;

#ifdef WIN32
      ret = select(0,NULL,&wfds,&efds,&tv);
#else
      ret = select(sock+1,NULL,&wfds,&efds,&tv);
#endif
      save_errno = errno;

      if (ret == -1) return -1;

      if (ret == 0) return 1; /* timeout */



      if (FD_ISSET(sock,&efds)) {
        if (save_errno == EINTR) continue;
#ifdef WIN32
        if (save_errno == WSAEWOULDBLOCK) return -1; /* no error message */
#endif
        out_log(LEVEL_CRITICAL,"Error during socket_wait_to_write: %d %s\n",save_errno,strerror(save_errno));
        return -1;
      }
#if 0
      if (!FD_ISSET(sock,&wfds)) /* timeout */
        return 1;
#endif
      return 0;
    }
    return 0;
  } /* timeout */

  return -1;
}
