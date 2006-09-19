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

/** \file dlist.c
  * \brief Doubly-linked list implementation
  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "dlist.h"

void dlist_init(DList *list, void (*destroy)(void *data))
{
  list->size = 0;
  list->test = NULL;
  list->destroy = destroy;
  list->head = list->tail = NULL;
}

void dlist_destroy(DList *list)
{
  void *data;

  if (!list) return;

  while (dlist_size(list) > 0) {
    if (dlist_remove(list,dlist_tail(list),(void**)&data)==0 && list->destroy != NULL) {
      list->destroy(data);
    }
  }

  memset(list,0,sizeof(DList));
}

int dlist_ins_next(DList *list, DListElmt *element, const void *data)
{
  DListElmt	*new_elmt;

  /* do not accept NULL element except if list is empty */
  if (element == NULL && dlist_size(list) != 0) return -1;

  /* allocates memory for element */
  if ((new_elmt = (DListElmt*)malloc(sizeof(DListElmt)))==NULL)
    return -1;

  /* inserts element in list */
  new_elmt->data = (void*)data;

  /* empty list */
  if (dlist_size(list)==0) {
    list->head = new_elmt;
    list->head->prev = NULL;
    list->head->next = NULL;
    list->tail = new_elmt;
  }
  else {
    new_elmt->next = element->next;
    new_elmt->prev = element;

    if (element->next == NULL)
      list->tail = new_elmt;
    else
      element->next->prev = new_elmt;

    element->next = new_elmt;
  }

  /* adjusts list size */
  list->size++;

  return 0;
}

int dlist_ins_prev(DList *list, DListElmt *element, const void *data)
{
  DListElmt	*new_elmt;

  /* do not accept NULL element except if list is empty */
  if (element == NULL && dlist_size(list) != 0) return -1;

  /* allocates memory for element */
  if ((new_elmt = (DListElmt*)malloc(sizeof(DListElmt)))==NULL)
    return -1;

  /* inserts element in list */
  new_elmt->data = (void*)data;

  /* empty list */
  if (dlist_size(list)==0) {
    list->head = new_elmt;
    list->head->prev = NULL;
    list->head->next = NULL;
    list->tail = new_elmt;
  }
  else {
    new_elmt->next = element;
    new_elmt->prev = element->prev;

    if (element->prev == NULL)
      list->head = new_elmt;
    else
      element->prev->next = new_elmt;

    element->prev = new_elmt;
  }

  /* adjusts list size */
  list->size++;

  return 0;
}

int dlist_remove(DList *list, DListElmt *element, void **data)
{
  /* checks for empty list */
  if (element == NULL || dlist_size(list) == 0)
    return -1;

  *data = element->data;

  if (element == list->head) {
    /* head element suppressed */
    list->head = element->next;

    if (list->head == NULL)
      list->tail = NULL;
    else
      element->next->prev = NULL;
  } else {
    /* generic suppression */
    element->prev->next = element->next;

    if (element->next == NULL)
      list->tail = element->prev;
    else
      element->next->prev = element->prev;
  }

  /* frees memory used by element */
  free (element);

  /* adjusts size */
  list->size--;

  return 0;
}

DListElmt * dlist_lookup_node(DList *list, void *data)
{
  DListElmt * element = NULL, * it;

  if (!list || dlist_size(list)==0) return NULL;
  if (!list->test) return NULL;

  for (it = list->head; it; it = dlist_next(it)) {
    if (list->test(data,it->data)==0) {
      element = it;
      break;
    }
  }

  return element;
}

