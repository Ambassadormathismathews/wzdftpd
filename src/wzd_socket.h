#ifndef __WZD_SOCKET__
#define __WZD_SOCKET__

int socket_make(const char *ip, int *port, int nListen);

int socket_accept(int sock, unsigned long *remote_host, unsigned int *remote_port);

int socket_connect(unsigned long remote_host, int remote_port, int localport, int fd);

#endif /* __WZD_SOCKET__ */
