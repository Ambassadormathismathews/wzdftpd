#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

extern int errno;

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

/* bind socket at port, if port = 0 picks first free and set it
 * returns -1 or socket
 */
int socket_make(const char *ip, int *port, int nListen)
{
  struct sockaddr_in sai;
  unsigned int c;
  int sock;

  if (ip==NULL || strcmp(ip,"*")==0)
    sai.sin_addr.s_addr = htonl(INADDR_ANY);
  else
  {
    struct hostent* host_info;
    // try to decode dotted quad notation
    if(!inet_aton(ip, &sai.sin_addr))
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

  if ((sock = socket(PF_INET,SOCK_STREAM,0)) < 0) {
    out_err(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

  c = 1;
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&c,sizeof(c));

/*  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));*/

  sai.sin_family = PF_INET;
  sai.sin_port = htons(*port); /* any port */

  if (bind(sock,(struct sockaddr *)&sai, sizeof(sai))) {
#ifdef __CYGWIN__
    out_log(LEVEL_CRITICAL,"Could not bind sock on port %d %s:%d\n", *port, __FILE__, __LINE__);
#else
    out_log(LEVEL_CRITICAL,"Could not bind sock on port %d (error %s) %s:%d\n", *port, strerror(errno),__FILE__, __LINE__);
#endif
    close(sock);
    return -1;
  }

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

/*************** socket_accept **************************/

int socket_accept(int sock, unsigned long *remote_host, unsigned int *remote_port)
{
  int new_sock;
  struct sockaddr_in from;
  unsigned int len = sizeof(struct sockaddr_in);
  int i;

  new_sock = accept(sock, (struct sockaddr *)&from, &len);

  if (new_sock < 0) {
    out_log(LEVEL_CRITICAL,"Accept failed %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));

#ifndef LINUX
/* see lundftpd : socket.c for explanation */
  setsockopt(new_sock, SOL_SOCKET, SO_SNDLOWAT, &i, sizeof(i));
#endif

  bcopy((const char*)&from.sin_addr.s_addr, (char*)remote_host, sizeof(unsigned long));
  *remote_port = ntohs(from.sin_port);

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
  sai.sin_port = htons(localport);

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));

  /* attempt to bind the socket - if it doesn't work, it is not a problem */
  bind(sock,(struct sockaddr *)&sai,sizeof(sai));

  /* makes the connection */
  sai.sin_port = htons(remote_port);
  sai.sin_family = AF_INET;
  memcpy(&sai.sin_addr,&remote_host,sizeof(remote_host));

/*  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));*/

#ifndef LINUX
/* see lundftpd : socket.c for explanation */
  setsockopt(sock, SOL_SOCKET, SO_SNDLOWAT, &ret, sizeof(ret));
#endif

  ret = connect(sock,(struct sockaddr *)&sai, len);
  if (ret < 0) {
    out_log(LEVEL_CRITICAL,"Connect failed %s:%d\n", __FILE__, __LINE__);
    close (sock);
    return -1;
  }

  return sock;
}
