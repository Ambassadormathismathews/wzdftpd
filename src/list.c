/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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

/** \file list.c
  * \brief Linked list implementation
  */

#include <stdlib.h>
#include <string.h>

#include "list.h"

void list_init(List *list, void (*destroy)(void *data))
{
  list->size = 0;
  list->test = NULL;
  list->destroy = destroy;
  list->head = list->tail = NULL;
}

void list_destroy(List *list)
{
  void *data;

  while (list_size(list) > 0) {
    if (list_rem_next(list,0,(void**)&data)==0 && list->destroy != NULL) {
      list->destroy(data);
    }
  }

  memset(list,0,sizeof(list));
}

int list_ins_next(List *list, ListElmt *element, const void *data)
{
  ListElmt	*new_elmt;

  /* allocates memory for element */
  if ((new_elmt = (ListElmt*)malloc(sizeof(ListElmt)))==NULL)
    return -1;

  /* inserts element in list */
  new_elmt->data = (void*)data;
  if (element==NULL) {
    /* head insertion */
    if (list_size(list)==0)
      list->tail = new_elmt;

    new_elmt->next = list->head;
    list->head = new_elmt;
  } else {
    /* insertion, not in head */
    if (element->next == NULL)
      list->tail = new_elmt;

    new_elmt->next = element->next;
    element->next = new_elmt;
  }

  /* adjusts list size */
  list->size++;

  return 0;
}

int list_rem_next(List *list, ListElmt *element, void **data)
{
  ListElmt	* old_elmt;

  /* checks for empty list */
  if (list_size(list) == 0)
    return -1;

  if (element == NULL) {
    /* head element suppressed */
    *data = list->head->data;
    old_elmt = list->head;
    list->head = list->head->next;

    if (list_size(list)==1)
      list->tail = NULL;
  } else {
    if (element->next == NULL)
      return -1;

    *data = element->next->data;
    old_elmt = element->next;
    element->next = element->next->next;

    if (element->next == NULL)
      list->tail = element;
  }

  /* frees memory used by element */
  free (old_elmt);

  /* adjusts size */
  list->size--;

  return 0;
}
