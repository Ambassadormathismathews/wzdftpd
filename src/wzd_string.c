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

#include <stdio.h>
#include <string.h>

#include "wzd_string.h"

#include "wzd_structs.h"
#include "wzd_log.h"


#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

struct wzd_string_t {
  char * buffer;
  size_t length;
  size_t allocated;
};

static inline void _str_set_min_size(wzd_string_t *str, size_t length);



wzd_string_t * str_allocate(void)
{
  wzd_string_t * str;

  str = wzd_malloc(sizeof(wzd_string_t));
  str->buffer = NULL;
  str->length = 0;
  str->allocated = 0;

  return str;
}

void str_deallocate(wzd_string_t *st)
{
  if (st) {
#ifdef DEBUG
    memset(st,0xab,sizeof(wzd_string_t));
#endif
    wzd_free(st);
  }
}

wzd_string_t * str_fromchar(const char *str)
{
  wzd_string_t * s;
  size_t length;

  s = str_allocate();

  if (s && str) {
    length = strlen(str);
    _str_set_min_size(s,length+1);
    memcpy(s->buffer,str,length);
    s->buffer[length] = '\0';
    s->length = length;
  }

  return s;
}

/* str_tochar
 * returns a pointer to the data contained in the string str.
 * These data must NOT be modified !
 */
const char * str_tochar(const wzd_string_t *str)
{
  return (str)?str->buffer:NULL;
}

wzd_string_t * str_dup(const wzd_string_t *src)
{
  wzd_string_t * dst;

  if (!src) return NULL;

#if DEBUG
  if ( (src->length >= src->allocated) ||
       (src->length != strlen(src->buffer)) )
  {
    out_err(LEVEL_CRITICAL,"invalid string (%s) at %s:%d\n",src->buffer,__FILE__,__LINE__);
    return NULL;
  }
#endif

  dst = str_allocate();
  _str_set_min_size(dst,src->allocated);
  if (src->buffer) {
    memcpy(dst->buffer,src->buffer,src->length);
    dst->buffer[src->length] = '\0';
  }

  return dst;
}

wzd_string_t * str_copy(wzd_string_t *dst, const wzd_string_t *src)
{
  if (!src || !dst) return NULL;

#if DEBUG
  if ( (src->length >= src->allocated) ||
       (src->length != strlen(src->buffer)) )
  {
    out_err(LEVEL_CRITICAL,"invalid string (%s) at %s:%d\n",src->buffer,__FILE__,__LINE__);
    return NULL;
  }
  if ( (dst->length >= dst->allocated) ||
       (dst->length != strlen(dst->buffer)) )
  {
    out_err(LEVEL_CRITICAL,"invalid string (%s) at %s:%d\n",dst->buffer,__FILE__,__LINE__);
    return NULL;
  }
#endif

  _str_set_min_size(dst,src->allocated);
  if (src->buffer) {
    memcpy(dst->buffer,src->buffer,src->length);
    dst->buffer[src->length] = '\0';
  }

  return dst;
}




static inline void _str_set_min_size(wzd_string_t *str, size_t length)
{
  if (str) {
    if (length > str->allocated) {
      str->buffer = wzd_realloc(str->buffer,length);
      str->allocated = length;
    }
  }
}

