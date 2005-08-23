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

#ifndef __DLIST__
#define __DLIST__

/*! \addtogroup libwzd_base
 *  @{
 */

typedef struct DListElmt_ {
  void 			* data;
  struct DListElmt_	* prev;
  struct DListElmt_	* next;
} DListElmt;

typedef struct DList_ {
  int		size;

  int		(*test)(const void *val1, const void *val2);
  void		(*destroy)(void *data);

  DListElmt	*head;
  DListElmt	*tail;
} DList;

/* INTERFACE */
void dlist_init(DList *list, void (*destroy)(void *data));

void dlist_destroy(DList *list);

int dlist_ins_next(DList *list, DListElmt *element, const void *data);

int dlist_ins_prev(DList *list, DListElmt *element, const void *data);

int dlist_remove(DList *list, DListElmt *element, void **data);

DListElmt * dlist_lookup_node(DList *list, void *data);

#define dlist_size(list)	((list)->size)

#define dlist_head(list)	((list)->head)

#define dlist_tail(list)	((list)->tail)

#define dlist_is_head(list,element) \
		((element) == (list)->head ? 1 : 0)

#define dlist_is_tail(list,element) \
		((element) == (list)->tail ? 1 : 0)

#define dlist_data(element) ((element)->data)

#define dlist_next(element) ((element)->next)

#define dlist_prev(element) ((element)->prev)

/*! @} */

#endif /* __DLIST__ */
