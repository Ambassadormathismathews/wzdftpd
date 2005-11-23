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

#ifndef __WZD_EVENTS__
#define __WZD_EVENTS__

/** \file wzd_events.h
 * \brief Connect events to callback functions
 *
 * \addtogroup libwzd_core
 * @{
 */

#include <libwzd-base/list.h>

typedef struct wzd_event_t wzd_event_t;
typedef struct wzd_event_manager_t wzd_event_manager_t;

typedef enum event_reply_t event_reply_t;

enum event_reply_t {
  EVENT_OK    = 0,   /**< standard reply, continue processing events */
  EVENT_BREAK = 1,   /**< event is ok, but stop processing events */
  EVENT_DENY  = 2,   /**< event is ok, but stop processing events and refuse commands */

  EVENT_ERROR = 255, /**< error while processing event */
};

#ifndef WIN32

typedef struct wzd_popen_t wzd_popen_t;

struct wzd_popen_t {
  int child_pid;
  int fdr;
};

wzd_popen_t * my_popen(const char * command);
event_reply_t my_pclose(wzd_popen_t * p);

#endif /* WIN32 */

typedef event_reply_t (*event_function_t)(const char * args);

struct wzd_event_t {
  u32_t id;


  event_function_t callback;
  wzd_string_t * external_command;


  wzd_string_t * params;
};

struct wzd_event_manager_t {
  List * event_list;
};

/** \brief Initialize an allocated wzd_event_manager_t struct */
void event_mgr_init(wzd_event_manager_t * mgr);

/** \brief Free memory used by a wzd_event_manager_t struct (the struct itself is not freed) */
void event_mgr_free(wzd_event_manager_t * mgr);

/*** these are candidate prototypes ... work in progress */

int event_connect_function(wzd_event_manager_t * mgr, u32_t event_id, event_function_t callback, wzd_string_t * params);
int event_connect_external(wzd_event_manager_t * mgr, u32_t event_id, wzd_string_t * external_command, wzd_string_t * params);

int event_send(wzd_event_manager_t * mgr, u32_t event_id, unsigned int reply_code, wzd_string_t * params, wzd_context_t * context);

/** @} */

#endif /* __WZD_EVENTS__ */
