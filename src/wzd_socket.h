#ifndef __WZD_SOCKET__
#define __WZD_SOCKET__

int socket_make(int *port);

int socket_accept(int sock, unsigned long *remote_host, int *remote_port);

int socket_connect(unsigned long remote_host, int remote_port);

#endif /* __WZD_SOCKET__ */
