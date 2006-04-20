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
#ifndef _LIBWZD_AVAHI_H
#define _LIBWZD_AVAHI_H

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>

#ifndef HAVE_AVAHI_THREADED_POLL
#include <avahi-common/simple-watch.h>
#include <signal.h> /* SIG_BLOCK */
#else
#include <avahi-common/thread-watch.h>
#endif

#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

#define FTP_DNS_SERVICE_TYPE "_ftp._tcp"

struct context {
#ifdef ZEROCONF_USE_PROCESS
  pid_t pid_child;
#else
  int thread_running;
  pthread_t thread_id;
  pthread_mutex_t mutex;
#endif
  char *name;
  /* TXT keys */
  char *username;
  char *password;
  char *path;
#ifndef HAVE_AVAHI_THREADED_POLL
  AvahiSimplePoll   *simple_poll;
#else
  AvahiThreadedPoll *threaded_poll;
#endif
  AvahiClient       *client;
  AvahiEntryGroup   *group;
  unsigned long     port;
};

/* prototype definitions */
void* av_zeroconf_setup(unsigned long, /* port */
                        const char *,  /* mDNS name */
                        const char *,  /* username */
                        const char *,  /* password */
                        const char *); /* path */
int av_zeroconf_run(void*);
int av_zeroconf_unregister(void*);
void av_zeroconf_shutdown(void*);
void av_zeroconf_lock(void *);
void av_zeroconf_unlock(void *);

#endif   /* _LIBWZD_AVAHI_H */

