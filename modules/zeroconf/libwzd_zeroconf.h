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
#ifndef _LIBWZD_ZEROCONF_H
#define _LIBWZD_ZEROCONF_H

#ifdef USE_BONJOUR
#include <DNSServiceDiscovery/DNSServiceDiscovery.h>

/* function prototypes */
static void reg_reply(DNSServiceRegistrationReplyErrorType errorCode, void *context);
#endif
#ifdef USE_AVAHI
#include <stdlib.h>
#include <assert.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

/* function prototypes */
static void create_services(AvahiClient *c);

static void doderegistration(void);
static void client_callback(AvahiClient *c,
			AvahiClientState state, AVAHI_GCC_UNUSED void *userdata);
static void entry_group_callback(AvahiEntryGroup *g,
			AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata);

/* Globals needed by Avahi */
static AvahiEntryGroup *group = NULL;
static AvahiSimplePoll *simple_poll = NULL;
static AvahiClient *client = NULL;
static char *g_name = NULL;
static unsigned long g_port;
#endif
#ifdef USE_HOWL
#include <howl.h>

/* howl globals */
static sw_discovery discovery;

/* function prototypes */
static sw_result HOWL_API
my_service_reply(sw_discovery discovery,
                 sw_discovery_oid oid,
                 sw_discovery_publish_status status,
                 sw_opaque extra);
#endif

#endif   /* _LIBWZD_ZEROCONF_H */
