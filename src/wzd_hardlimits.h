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

#ifndef __WZD_HARD_LIMITS__
#define __WZD_HARD_LIMITS__


#define	HARD_REACTION_TIME	1L

/* FIXME should be a variable */
#define	HARD_XFER_TIMEOUT	60L

#define	TRFMSG_INTERVAL		1000000


#define	HARD_THREADLIMIT	2000
#define	HARD_USERLIMIT		128
#define	HARD_DEF_USER_MAX	64
#define	HARD_DEF_GROUP_MAX	64
#define	HARD_MSG_LIMIT		1024
#define	HARD_MSG_LENGTH_MAX	16384

#define	MAX_IP_LENGTH		128
#define	HARD_IP_PER_USER	8
#define	HARD_IP_PER_GROUP	8

#define	MAX_FLAGS_NUM		32


#define	HARD_PERMFILE		".dirinfo"

/* interval of time to check dynamic ip (default: 10 mns) */
#define	HARD_DYNAMIC_IP_INTVL	60


#define	HARD_LS_BUFFERSIZE	4096

#define	HARD_BACKEND_NAME_LENGTH	256
#define	HARD_LAST_COMMAND_LENGTH	1024
#define	HARD_USERNAME_LENGTH		256

#endif /* __WZD_HARD_LIMITS__ */
