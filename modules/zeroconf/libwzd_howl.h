/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2006  Pierre Chifflier
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
#ifndef _LIBWZD_HOWL_H
#define _LIBWZD_HOWL_H

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>

#include <howl.h>

#define FTP_DNS_SERVICE_TYPE "_ftp._tcp"

/* prototype definitions */
void* ho_zeroconf_setup(unsigned long, const char *);
void* ho_zeroconf_unregister(void);
void* ho_zeroconf_run(void);
static sw_result HOWL_API publish_reply(sw_discovery,
                                        sw_discovery_oid,
                                        sw_discovery_publish_status,
                                        sw_opaque);

#endif   /* _LIBWZD_HOWL_H */
