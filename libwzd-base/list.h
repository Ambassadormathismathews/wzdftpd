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

#ifndef __LIST__
#define __LIST__

typedef struct ListElmt_ {
	void 			* data;
	struct ListElmt_	* next;
} ListElmt;

typedef struct List {
	int		size;

	int		(*test)(const void *val1, const void *val2);
	void		(*destroy)(void *data);

	ListElmt	*head;
	ListElmt	*tail;
} List;

/* INTERFACE */
void list_init(List *list, void (*destroy)(void *data));

void list_destroy(List *list);

int list_ins_next(List *list, ListElmt *element, const void *data);

int list_rem_next(List *list, ListElmt *element, void **data);

#define list_size(list)	((list)->size)

#define list_head(list)	((list)->head)

#define list_tail(list)	((list)->tail)

#define list_is_head(list,element) \
		((element) == (list)->head ? 1 : 0)

#define list_is_tail(list,element) \
		((element) == (list)->tail ? 1 : 0)

#define list_data(element) ((element)->data)

#define list_next(element) ((element)->next)

#endif /* __LIST__ */
