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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <wchar.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_events.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

/** \file wzd_events.c
 * \brief Connect events to callback functions
 *
 * A callback is implemented as a closure: when defining the callback, a list
 * of additional parameters is specified.
 * As we do not have a portable implementation for closures, we use a linked
 * list for parameters.
 *
 * Ideas:
 *  - the implementation could use a priority queue, so the users can specify
 *  a priority when adding a connection.
 *  - add a flag PARALLEL / SEQUENTIAL to specify if the job can be run in
 *  another thread or not
 *
 * \addtogroup libwzd_core
 * @{
 */


static void _event_free(wzd_event_t * event);


void event_mgr_init(wzd_event_manager_t * mgr)
{
  WZD_ASSERT_VOID( mgr != NULL);

  mgr->event_list = wzd_malloc( sizeof(List) );
  list_init(mgr->event_list, (void (*)(void*))_event_free);
}

void event_mgr_free(wzd_event_manager_t * mgr)
{
  WZD_ASSERT_VOID( mgr != NULL);

  list_destroy(mgr->event_list);
  wzd_free(mgr->event_list);

  memset(mgr, 0, sizeof(wzd_event_manager_t));
}

/*** these are candidate prototypes ... work in progress */

int event_connect_function(wzd_event_manager_t * mgr, u32_t event_id, event_function_t callback, wzd_string_t * params)
{
  wzd_event_t * event;

  WZD_ASSERT( mgr != NULL );

  event = wzd_malloc(sizeof(wzd_event_t));
  event->id = event_id;
  event->callback = callback;
  event->external_command = NULL;
  event->params = params;

  list_ins_next(mgr->event_list, list_tail(mgr->event_list), event);

  return 0;
}

int event_connect_external(wzd_event_manager_t * mgr, u32_t event_id, wzd_string_t * external_command, wzd_string_t * params)
{
  wzd_event_t * event;

  WZD_ASSERT( mgr != NULL );

  event = wzd_malloc(sizeof(wzd_event_t));
  event->id = event_id;
  event->callback = NULL;
  event->external_command = str_dup(external_command);
  event->params = params;

  list_ins_next(mgr->event_list, list_tail(mgr->event_list), event);

  return 0;
}

void event_send(wzd_event_manager_t * mgr, u32_t event_id, wzd_string_t * params, wzd_context_t * context)
{
  ListElmt * elmnt;
  wzd_event_t * event;
  int ret;

  WZD_ASSERT_VOID( mgr != NULL);

  out_log(LEVEL_FLOOD,"DEBUG Sending event 0x%lx\n",event_id);

  for (elmnt=list_head(mgr->event_list); elmnt; elmnt=list_next(elmnt)) {
    event = list_data(elmnt);
    WZD_ASSERT_VOID( event != NULL );
    if ( (event->id & event_id) ) {
      if (event->callback) {
        ret = (event->callback)(); /** \todo test result */
      } else {
        /** \todo implement call to external command */
        out_log(LEVEL_INFO,"INFO calling external command [%s]\n",str_tochar(event->external_command));
      }
    }
  }
}



static void _event_free(wzd_event_t * event)
{
  str_deallocate(event->external_command);
  str_deallocate(event->params);
  wzd_free(event);
}

/** @} */

