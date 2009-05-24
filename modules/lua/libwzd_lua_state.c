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

#include "libwzd_lua.h"

/**
 * \file libwzd_lua_state.c
 * \brief Lua module state handling functions
 * \addtogroup module_lua
 * @{
 */


/**
 * \brief Structure of an element in the state list.
 */
struct _state_elem_s {
  wzd_context_t *context;     /**< \brief The client's session context */
  lua_State *state;           /**< \brief Lua state */
  struct _state_elem_s *next; /**< \brief Next element or NULL */
};

/** \brief Lua's states list */
static struct _state_elem_s * _state_list = NULL;
/** \brief Mutex on _state_list */
static wzd_mutex_t * _state_list_mutex = NULL;

/** \brief Macro to lock the mutex of the state list. */
#define _STATE_LIST_LOCK() wzd_mutex_lock(_state_list_mutex)
/** \brief Macro to unlock the mutex of the state list. */
#define _STATE_LIST_UNLOCK() wzd_mutex_unlock(_state_list_mutex)

static struct _state_elem_s * _state_new(wzd_context_t *context, lua_State *state);

static void _state_add(struct _state_elem_s *elem);
static void _state_del(struct _state_elem_s *elem);
static struct _state_elem_s *_state_search(wzd_context_t *context);

/**
 * \brief Initialise the list of Lua's states.
 * \return 0 on success.
 */
int libwzd_lua_state_init()
{
  _state_list_mutex = wzd_mutex_create(0);
  return 0;
}

/**
 * \brief Finalize the list of Lua's state. 
 */
void libwzd_lua_state_finalize()
{
  wzd_mutex_destroy(_state_list_mutex);
}

/**
 * \brief Free Lua's state when a user logout. 
 * \param args not used.
 * \return EVENT_OK.
 *
 */
event_reply_t libwzd_lua_state_logout(UNUSED const char *args)
{
  struct _state_elem_s *elem;
  wzd_context_t *context = GetMyContext();

  elem = _state_search(context);
  if (elem == NULL) return EVENT_OK;

  out_log(LEVEL_INFO, "lua: user logout, free state !\n");
  
  /* free state */
  lua_close(elem->state);

  /* delete cached state */
  _state_del(elem);
  
  return EVENT_OK;
}

/**
 * \brief Get the Lua's state of an client session, or create one.
 * \param context The client's session context.
 * \param state Lua's state fill by this function.
 */
void libwzd_lua_state_get(wzd_context_t *context, lua_State **state)
{
  struct _state_elem_s *elem = _state_search(context);
  
  /* take cached state */
  if (elem != NULL) {
    *state = elem->state;
    return;
  }

  /* create a new state */
  out_log(LEVEL_INFO, "lua: create a new state.\n");

  *state = luaL_newstate();
  if (*state == NULL) {
    return;
  }

  /* open lua std libs */
  luaL_openlibs(*state);

  /* setup wzd functions */
  libwzd_lua_api_setup(*state);

  /* add state to cache */
  elem = _state_new(context, *state);
  _state_add(elem);
}

/**
 * \brief Create a new state.
 * \param context The client's session context.
 * \param state A new lua state.
 * \return A new state element.
 */
static struct _state_elem_s *_state_new(wzd_context_t *context,
                                 lua_State *state) {
  struct _state_elem_s *elem;

  elem = malloc(sizeof(struct _state_elem_s));
  elem->context = context;
  elem->state = state;
  elem->next = NULL;

  return elem;
}

/**
 * \brief Add a state element to the list.
 * \param elem The state element.
 */
static void _state_add(struct _state_elem_s *elem) {
  _STATE_LIST_LOCK();
  elem->next = _state_list;
  _state_list = elem;
  _STATE_LIST_UNLOCK();
}

/**
 * \brief Delete a state element from the list and free it.
 * \param elem the state element.
 */
static void _state_del(struct _state_elem_s *elem) {
  struct _state_elem_s *tmp = NULL;
  struct _state_elem_s *cur = NULL;
  struct _state_elem_s *prev = NULL;

  _STATE_LIST_LOCK();
  cur = _state_list;

  while(cur != NULL) {
    if (cur == elem) {
      if (prev == NULL) {
        _state_list = cur->next;
      } else {
        prev->next = cur->next;
      }
      
      tmp = cur;
      cur = cur->next;
      free(tmp);
      continue;
    }
    
    prev = cur;
    cur = cur->next;
  }
  _STATE_LIST_UNLOCK();
}

/**
 * \brief Search an element in the lua's state list
 * \param context The client's session context.
 * \return the state element found, or NULL.
 */
static struct _state_elem_s *_state_search(wzd_context_t *context) {
  struct _state_elem_s *cur = NULL;
  struct _state_elem_s *found = NULL;
  
  _STATE_LIST_LOCK();
  cur = _state_list;

  while(cur != NULL) {
    if (cur->context == context) {
      found = cur;
      break;
    }
    cur = cur->next;
  }
  _STATE_LIST_UNLOCK();

  return found;
}

/** @} */
