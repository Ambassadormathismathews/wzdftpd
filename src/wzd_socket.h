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

#ifndef __WZD_SOCKET__
#define __WZD_SOCKET__

int socket_make(const char *ip, unsigned int *port, int nListen);
int socket_close(int sock);

int socket_accept(int sock, unsigned char *remote_host, unsigned int *remote_port);

int socket_connect(unsigned char * remote_host, int family, int remote_port, int localport, int fd, unsigned int timeout);

/* Returns remote/local port number for the current connection. */
int socket_get_remote_port(int sock);
int socket_get_local_port(int sock);

/* wait for socket to be ready for read/write, for timeout seconds max
 * return 0 if ok, 1 if timeout, -1 on error
 */
int socket_wait_to_read(int sock, unsigned int timeout);
int socket_wait_to_write(int sock, unsigned int timeout);



int socket_getipbyname(const char *name, char *buffer, size_t length);

#endif /* __WZD_SOCKET__ */
