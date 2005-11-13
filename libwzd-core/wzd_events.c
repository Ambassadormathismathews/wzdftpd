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

#include "wzd_cache.h"
#include "wzd_events.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_mod.h"

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
static int _event_print_file(const char *filename, wzd_context_t * context);


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
  event->params = str_dup(params);

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
  event->params = str_dup(params);

  list_ins_next(mgr->event_list, list_tail(mgr->event_list), event);

  return 0;
}

void event_send(wzd_event_manager_t * mgr, u32_t event_id, wzd_string_t * params, wzd_context_t * context)
{
  ListElmt * elmnt;
  wzd_event_t * event;
  int ret;
  protocol_handler_t * proto;
  char fixed_args[4096];
  char buffer_args[4096];
  char * args;
  size_t length;
  wzd_user_t * user = GetUserByID(context->userid);
  wzd_group_t * group = NULL;

  WZD_ASSERT_VOID( mgr != NULL);

  if (user->group_num > 0) group = GetGroupByID(user->groups[0]);

  out_log(LEVEL_FLOOD,"DEBUG Sending event 0x%lx\n",event_id);

  /* prepare arguments */
  /*   add command line args to permanent args */
  buffer_args[0] = '\0';
  if (params) {
    cookie_parse_buffer(str_tochar(params), user, group, context, buffer_args, sizeof(buffer_args));
    chop(buffer_args);
  }

  for (elmnt=list_head(mgr->event_list); elmnt; elmnt=list_next(elmnt)) {
    event = list_data(elmnt);
    WZD_ASSERT_VOID( event != NULL );

    if ( (event->id & event_id) ) {

      args = fixed_args; args[0] = '\0';
      length = sizeof(fixed_args);

      if (event->external_command) {
        wzd_strncpy(args, str_tochar(event->external_command), length);
        strlcat(args," ",length);
        args += strlen(args);
        length -= strlen(args);
      }

      if (event->params) {
        cookie_parse_buffer(str_tochar(event->params), user, group, context, args, length);
        chop(args);

        if (params) {
          strlcat(fixed_args," ",sizeof(fixed_args));
          strlcat(fixed_args,buffer_args,sizeof(fixed_args));
        }
      } else {
        if (params) {
          strlcat(fixed_args," ",sizeof(fixed_args));
          strlcat(fixed_args,buffer_args,sizeof(fixed_args));
        }
      }
      args = fixed_args;

      if (event->callback) {
        ret = (event->callback)(args); /** \todo test result */
      } else {
        const char * command;

        command = str_tochar(event->external_command);

        /* if external_command begins with a ! , print the corresponding file */
        if (command[0] == '!') {
          ret = _event_print_file(command+1, context);
        } else {
          /* check for perl: like protocols */
          proto = hook_check_protocol(command);

          if (proto) {
            ret = (*proto->handler)(command+proto->siglen,args);
          } else {
            /* call external command */
            _cleanup_shell_command(fixed_args, sizeof(fixed_args));
            out_log(LEVEL_INFO,"INFO calling external command [%s]\n",args);
          }
        }
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

static int _event_print_file(const char *filename, wzd_context_t * context)
{
  wzd_cache_t * fp;
  char * file_buffer;
  unsigned int size, filesize;
  u64_t sz64;
  wzd_user_t * user = GetUserByID(context->userid);
  wzd_group_t * group = GetGroupByID(user->groups[0]);

  fp = wzd_cache_open(filename,O_RDONLY,0644);
  if (!fp) {
    send_message_raw("200-Inexistant file\r\n",context);
    return -1;
  }
  sz64 = wzd_cache_getsize(fp);
  if (sz64 > INT_MAX) {
    out_log(LEVEL_HIGH,"%s:%d couldn't allocate" PRIu64 "bytes for file %s\n",__FILE__,__LINE__,sz64,filename);
	wzd_cache_close(fp);
	return -1;
  }
  filesize = (unsigned int)sz64;
  file_buffer = malloc(filesize+1);
  if ( (size=(unsigned int)wzd_cache_read(fp,file_buffer,filesize))!=filesize )
  {
    out_log(LEVEL_HIGH,"Could not read file %s read %u instead of %u (%s:%d)\n",filename,size,filesize,__FILE__,__LINE__);
    free(file_buffer);
    wzd_cache_close(fp);
    return -1;
  }
  file_buffer[filesize]='\0';

  cookie_parse_buffer(file_buffer,user,group,context,NULL,0);

  wzd_cache_close(fp);

  free(file_buffer);

  return 0;
}

/** @} */

