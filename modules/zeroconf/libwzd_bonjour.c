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

#ifdef USE_BONJOUR

#include <libwzd-core/wzd_types.h>
#include "libwzd_bonjour.h"

DNSServiceRef publish_session = NULL;

#ifdef WIN32
static void DNSSD_API
#else
static void
#endif
publish_reply (DNSServiceRef sdRef,
         const DNSServiceFlags flags,
         DNSServiceErrorType errorCode,
         const char *name,
         const char *regtype,
         const char *domain,
         void *context)
{
}

void* bo_zeroconf_setup(unsigned long port,
                        const char *name,
                        const char *username,
                        const char *password,
                        const char *path) {
  DNSServiceErrorType err;
#ifdef HAVE_OSX_TIGER
  TXTRecordRef txtRecord;
#endif
  char service[256] = "WZDFTP Server on ";

  /* Prepare service name */
  if (!name) {
    out_log(LEVEL_INFO, "Assigning default service name.\n");
    gethostname(service+17, sizeof(service)-18);
    service[sizeof(service)-1] = 0;

    name = strdup(service);
  }

  if (!name) return NULL;
  if (!port) return NULL;

#ifdef HAVE_OSX_TIGER
  /* prepare text records */
  TXTRecordCreate(&txtRecord, 0, 0);

  /* assign TXT keys if any */
  if (username) {
    if (TXTRecordSetValue(&text_record,
                          "u",
                          8,
                          username) != kDNSServiceErr_NoError) {
      out_log(LEVEL_CRITICAL, "Adding TXT record %s=%s failed\n", "u", username);

      TXTRecordDeallocate(&txt_record);
      bo_zeroconf_unregister();
    }
    else {
      txt_rec_len++;
    }
  }
  if (password) {
    if (TXTRecordSetValue(&text_record,
                          "p",
                          8,
                          password) != kDNSServiceErr_NoError) {
      out_log(LEVEL_CRITICAL, "Adding TXT record %s=%s failed\n", "p", password);

      TXTRecordDeallocate(&txt_record);
      bo_zeroconf_unregister();
    }
    else {
      txt_rec_len++;
    }
  }
  if (path) {
    if (TXTRecordSetValue(&text_record
                          "path",
                          4,
                          path) != kDNSServiceErr_NoError) {
      out_log(LEVEL_CRITICAL, "Adding TXT record %s=%s failed\n", "path", path);

      TXTRecordDeallocate(&txt_record);
      bo_zeroconf_unregister();
    }
    else {
      txt_rec_len++;
    }
  }
#else
  out_log(LEVEL_INFO,
          "You did provide certain TXT keys.\n"
          "Unfortunatly this particular OSX version is not able to publish TXT keys.\n");
#endif

  err = DNSServiceRegister (&publish_session,
                            0,                          /* flags */
                            0,                          /* interface; 0 for all */
                            name,                       /* name */
                            FTP_DNS_SERVICE_TYPE,       /* type */
                            NULL,                       /* domain */
                            NULL,                       /* hostname */
                            htons (port),               /* port in network byte order */
#ifdef HAVE_OSX_TIGER
                            TXTRecordGetLength(&txt),   /* text record length */
                            TXTRecordGetBytesPtr(&txt), /* text record */
#else
                            0,
                            NULL,
#endif
                            publish_reply,              /* callback */
                            NULL);                      /* context */

#ifdef HAVE_OSX_TIGER
  TXTRecordDeallocate(&txt_record);
#endif

  if (err == kDNSServiceErr_NoError) {
    out_log(LEVEL_INFO, "Adding service '%s'\n", name);
  } else {
    out_log(LEVEL_CRITICAL, "Adding service '%s' failed\n", name);
    bo_zeroconf_unregister();
  }
}

int bo_zeroconf_run(void) {
  fd_set set;
  fd_t fd;
  struct timeval timeout;

  /* Initialize the file descriptor set. */
  FD_ZERO (&set);
  FD_SET (fd, &set);

  /* Initialize the timeout data structure. */
  /* TODO: Should the value for sec be configurable? */
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  if (publish_session != NULL) {
    fd = DNSServiceRefSockFD(publish_session);

    if (select(FD_SETSIZE,
                  &set, NULL, NULL,
                  &timeout) > 0) {
      DNSServiceProcessResult(publish_session);
    }
  }

  return 0;
}

int bo_zeroconf_unregister(void) {
  if (publish_session != NULL) {
    DNSServiceRefDeallocate(publish_session);
    publish_session = NULL;
  }

  return 0;
}

#endif /* USE_BONJOUR */
