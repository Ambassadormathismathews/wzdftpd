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

/** \file libwzd.c
 *  \brief Routines to access wzdftpd from applications
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include "libwzd.h"
#include "libwzd_pv.h"

#include "libwzd_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#else
# include <windows.h>
#endif

static int _connect_server(void);

struct libwzd_config * _config=NULL;



/** parameters are still being defined */
int wzd_init(const char *host, int port, const char *user, const char *pass)
{
  /* 0- init structs */
  if (_config != NULL) return -1; /* init already done */
  _config = malloc(sizeof(struct libwzd_config));
  memset(_config,0,sizeof(struct libwzd_config));
  _config->host = strdup(host);
  _config->port = port;
  _config->user = strdup(user);
  _config->pass = strdup(pass);

  /* 1- connect to server */
  if (_connect_server()<0) { free(_config); return -1; }

  /* 2- fill static struct ? */

  return 0;
}

int wzd_fini(void)
{
  if (_config) {
    wzd_send_message("QUIT\r\n",6,NULL,0);
#ifdef WIN32
    Sleep(1000);
#else
    sleep(1);
#endif
    if (_config->host) free(_config->host);
    if (_config->user) free(_config->user);
    if (_config->pass) free(_config->pass);
    free(_config);
    _config = NULL;
  }

  return 0;
}

int wzd_send_message(const char *message, int msg_length, char * reply, int reply_length)
{
  int ret;
  char * buffer;
  int buffer_length;

  if (!_config) return -1;
  if (_config->connector.mode == CNT_NONE) return -1;
  if (!_config->connector.read || !_config->connector.write) return -1;
  if (!message) return -1;

  /* check connection status ? */

  /* ensure last bytes of message are \r\n ? */

  ret = _config->connector.write(message,msg_length);
  if (ret != msg_length) return -1;

  buffer_length = (reply_length > 4096) ? reply_length : 4096;
  buffer = malloc(buffer_length+1);
  buffer[0] = '\0';
  ret = _config->connector.read(buffer,buffer_length);

  if (reply) { memcpy(reply,buffer,reply_length); reply[reply_length]='\0'; }

  return 0;
}

/*************** STATIC *******************/

/** connect to server and return file descriptor or -1
 */
static int _connect_server(void)
{
  int ret;

  if (!_config) return -1;
  
  /* 1- first, try named pipe ? */
  /* 2- try unix socket ? */
  /* 3- try socket ? */
  if ( (ret = server_try_socket()) >= 0 ) return ret;

  return -1; /* not connected */
}
