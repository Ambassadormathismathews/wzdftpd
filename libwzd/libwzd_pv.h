/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

/** \file libwzd_pv.h
 *  \brief Routines and structures restricted only to libwzd
 */

#ifndef __LIBWZD_PV__
#define __LIBWZD_PV__

/*! \addtogroup libwzd
 *  @{
 */

enum connection_mode {
  CNT_NONE=0,
  CNT_NAMEDPIPE,
  CNT_UNIXSOCKET,
  CNT_SOCKET,
};

enum connection_state {
  STATE_NONE=0,
  STATE_CONNECTING,
  STATE_OK,
  STATE_WAITING,
};

struct libwzd_connector {
  enum connection_mode mode;
  int (*connect)(const char*,int,const char*,const char*);
  int (*disconnect)(void);
  int (*read)(char *,int);
  int (*write)(const char *,int);
  int (*is_secure)(void);
};

#define OPTION_TLS      0x00000010L     /* force tls */
#define OPTION_NOTLS    0x00000100L     /* prevent using tls */

struct libwzd_config {
  char * host;
  int port;
  char * user;
  char * pass; /**< \bug we should avoid storing that in clear */
  int sock;
  struct libwzd_connector connector;
  enum connection_state state;
  unsigned long options;
};


extern struct libwzd_config * _config;


/* some awfull things coming from win32 */
#ifdef WIN32

#define close           _close
#define snprintf        _snprintf

#endif /* WIN32 */

/*! @} */

#endif /* __LIBWZD_PV__ */

