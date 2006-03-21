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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef USE_HOWL

#include "libwzd_howl.h"

sw_discovery discovery = NULL;

static sw_result HOWL_API publish_reply(sw_discovery discovery,
                                        sw_discovery_oid oid,
                                        sw_discovery_publish_status status,
                                        sw_opaque extra) {
  static sw_string
    status_text[] =
    {
      "Started",
      "Stopped",
      "Name Collision",
      "Invalid"
    };

  out_log(LEVEL_INFO, "publish reply: %s\n", status_text[status]);
  return SW_OKAY;
}

void* ho_zeroconf_setup(unsigned long port, const char *name) {
  sw_result result;
  sw_discovery_publish_id id;
  char service[256] = "WZDFTP Server on ";

  if (sw_discovery_init (&discovery) != SW_OKAY) {
    out_log(LEVEL_CRITICAL,
           "WZDFTPD could not be started. \nTry running mDNSResponder.");
    return;
  }

  /* Prepare service name */
  if (!name) {
    out_log(LEVEL_INFO, "Assigning default service name.\n");
    gethostname(service+17, sizeof(service)-18);
    service[sizeof(service)-1] = 0;

    name = strdup(service);
  }

  assert(name);

  if (!(result = sw_discovery_publish (discovery,
                                       0,
                                       name,
                                       FTP_DNS_SERVICE_TYPE,
                                       NULL,
                                       NULL,
                                       port,
                                       NULL,
                                       0,
                                       publish_reply,
                                       NULL,
                                       &id)) != SW_OKAY) {
    out_log(LEVEL_INFO, "Adding service '%s'\n", name);
  } else {
    out_log(LEVEL_CRITICAL, "Adding service '%s' failed\n", name);
    ho_zeroconf_unregister();
  }
}

void* ho_zeroconf_run(void) {
  out_log(LEVEL_INFO, "Starting discovery (Yields control of the CPU to Howl)...\n");
  sw_discovery_run(discovery);
  out_log(LEVEL_INFO, "Discovery started.");
}

void* ho_zeroconf_unregister(void) {
  out_log(LEVEL_INFO, "Trying to stop discovery and to de-allocated resources...\n");
  sw_discovery_stop_run(discovery);
  out_log(LEVEL_INFO, "Discovery stopped.");

}

#endif /* USE_HOWL */
