#include "wzd.h"

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
int socket_make(int *port)
{
  struct sockaddr_in sai;
  int sock, c;

  if ((sock = socket(PF_INET,SOCK_STREAM,0)) < 0) {
    out_log(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

  c = 1;
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&c,sizeof(c));

/*  fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));*/

  sai.sin_family = PF_INET;
  sai.sin_addr.s_addr = htonl(INADDR_ANY);
  sai.sin_port = htons(*port); /* any port */

  if (bind(sock,(struct sockaddr *)&sai, sizeof(sai))) {
    out_log(LEVEL_CRITICAL,"Could not bind sock %s:%d\n", __FILE__, __LINE__);
    close(sock);
    return -1;
  }

  c = sizeof(struct sockaddr_in);
  getsockname(sock, (struct sockaddr *)&sai, &c);

  listen(sock,5);

  *port = ntohs(sai.sin_port);
  return sock;
}

/*************** socket_accept **************************/

int socket_accept(int sock, unsigned long *remote_host, int *remote_port)
{
  int new_sock;
  struct sockaddr_in from;
  int len = sizeof(struct sockaddr_in), i;

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

int socket_connect(unsigned long remote_host, int remote_port)
{
  int sock;
  struct sockaddr_in sai;
  int len = sizeof(struct sockaddr_in), ret;

  if ((sock = socket(PF_INET,SOCK_STREAM,0)) < 0) {
    out_log(LEVEL_CRITICAL,"Could not create socket %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

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
