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

/** \file hash.h
  * \brief Chained hash tables implementation
  */

#ifndef __HASH__
#define __HASH__

/*! \addtogroup libwzd_base
 *  Base functions for wzdftpd
 *  @{
 */

#include "list.h"

typedef struct CHTBL_ {
  unsigned int   containers;
  unsigned int   (*h)(const void *key);
  int   (*match)(const void *key1, const void *key2);
  void  (*free)(void *data);

  int   size;
  List  *table;
} CHTBL;

typedef unsigned int (*hash_function)(const void*);
typedef int (*cmp_function)(const void *, const void*);
typedef int (*htrigger_function)(void *, void*);
typedef void (*hfree)(void *);


/** generic hash function for strings */
unsigned int hash_str(const char *key);

int chtbl_init(CHTBL *htab, unsigned int containers, unsigned int (*h)(const void*),
    int (*match)(const void*, const void*),
    void (*ffree)(void*));

void chtbl_destroy(CHTBL *htab);

int chtbl_insert(CHTBL *htab, const void *key, void *data, htrigger_function fcn, hfree free_key, hfree free_element);
int chtbl_change(const CHTBL *htab, const void *key, void *data);
int chtbl_insert_or_change(CHTBL *htab, const void *key, void *data, htrigger_function fcn, hfree free_key, hfree free_element);

int chtbl_remove(CHTBL *htab, const void *key);

int chtbl_lookup(const CHTBL *htab, const void *key, void **data);

int chtbl_search(const CHTBL *htab, int (*match)(const void *, const void*), const void *arg, void **data);

#define chtbl_size(htab) ((htab)->size)

/*! @} */

#endif /* __HASH__ */
