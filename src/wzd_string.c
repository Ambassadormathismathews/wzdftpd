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

#include <ctype.h> /* isspace */

#include "wzd_string.h"

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h" /* ascii_lower */

#ifdef HAVE_UTF8
# include "wzd_utf8.h"
#endif


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
    wzd_free(st->buffer);
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
  if ( dst->buffer &&
      ((dst->length >= dst->allocated) ||
       (dst->length != strlen(dst->buffer))) )
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

/* str_append
 * append 'tail' to string pointed to by str
 */
wzd_string_t * str_append(wzd_string_t * str, const char *tail)
{
  size_t length;

  if (!str) return NULL;
  if (!tail) return str;

  length = strlen(tail);

  _str_set_min_size(str,str->length + length + 1);
  if (str->buffer) {
    memcpy(str->buffer + str->length, tail, length);
    str->length += length;
    str->buffer[str->length] = '\0';
  }

  return str;
}

/** \brief prepend 'head' to string pointed to by str
 */
wzd_string_t * str_prepend(wzd_string_t * str, const char *head)
{
  size_t length;
  char * buf;

  if (!str) return NULL;
  if (!head) return str;

  length = strlen(head);

  buf = wzd_malloc(str->length + length + 1);
  wzd_strncpy(buf, head, length);
  if (str->buffer) {
    memcpy(buf + length, str->buffer, str->length);
    length += str->length;
    wzd_free(str->buffer);
  }
  buf[length] = '\0';
  str->buffer = buf;
  str->length = length;

  return str;
}


/** \brief remove all leading and trailing spaces from input string
 */
wzd_string_t * str_trim(wzd_string_t * str)
{
  return str_trim_left(str_trim_right(str));
}

wzd_string_t * str_trim_left(wzd_string_t *str)
{
  unsigned int i=0;

  if (!str || !str->buffer)
    return NULL;

  while (isspace(str->buffer[i])) {
    ++i;
  }

  if (i==0) {
    unsigned int j=0;
    for (;i!=str->length;i++)
    {
      str->buffer[j++] = str->buffer[i];
    }
    str->length -= i;
  }

  return str;
}

wzd_string_t * str_trim_right(wzd_string_t *str)
{
  size_t len;

  if (!str || !str->buffer)
    return NULL;

  if (str->length == 0) return str;

  len = str->length;

  while ((--len >= 0) &&
      (isspace(str->buffer[len]) ||
       str->buffer[len] == '\n')) {
    str->buffer[len] = '\0';
    str->length--;
  }
  return str;
}

/** \brief Convert string to lower case
 * \note
 * This function modifies its input string
 */
wzd_string_t * str_tolower(wzd_string_t *str)
{
  if (str && str->buffer)
    ascii_lower(str->buffer, str->length);

  return str;
}


/** \brief Extract token from string str
 * \note
 * This function modifies its input string
 */
wzd_string_t * str_tok(wzd_string_t *str, const char *delim)
{
  wzd_string_t * token;
  char *ptr, *t;
  char * buffer;

  if (!str || !str->buffer || str->length == 0) return NULL;
  if (!delim) return NULL;

  buffer = wzd_strdup(str->buffer);
  t = strtok_r(buffer, delim, &ptr);

  token = STR(t);
  if (t) {
    str->length = strlen(ptr);
    wzd_strncpy(str->buffer, ptr, str->length+1);
  }
  wzd_free(buffer);

  return token;
}



/* str_sprintf
 * Produce output according to format and variable number of arguments,
 * and write output to str.
 */
int str_sprintf(wzd_string_t *str, const char *format, ...)
{
  va_list argptr;
  int result;

  if (!str) return -1;
  if (!format) return -1;

  if (!str->buffer)
    _str_set_min_size(str,strlen(format)+1);

  va_start(argptr,format); /* note: ansi compatible version of va_start */

  result = vsnprintf(str->buffer, str->allocated, format, argptr);
  if (result < 0) return result;
  if (result >= str->allocated)
  {
    _str_set_min_size(str, result+1);
    result = vsnprintf(str->buffer, str->allocated, format, argptr);
  }

  va_end (argptr);

  return result;
}

/** \brief Convert utf8 string to other charset
 * \note
 * Require unicode support
 */
#ifdef HAVE_UTF8
int str_utf8_to_local(wzd_string_t *str, const char * charset)
{
  char * utf_buf;
  size_t length;

  if (!utf8_valid(str->buffer, str->length)) {
    return -1;
  }

  length = strlen(str->buffer) + 10; /* we allocate more, small security */
  utf_buf = wzd_malloc(length);

  if (utf8_to_local_charset(str->buffer, utf_buf, length, charset))
  {
    /* error during conversion */
    wzd_free(utf_buf);
    return -1;
  }

  wzd_free(str->buffer);
  str->buffer = utf_buf;
  str->allocated = length;
  str->length = strlen(utf_buf);

  return 0;
}
#else
int str_utf8_to_local(wzd_string_t *str, const char * charset)
{
  return -1;
}
#endif /* HAVE_UTF8 */





static inline void _str_set_min_size(wzd_string_t *str, size_t length)
{
  if (str) {
    if (length > str->allocated) {
      str->buffer = wzd_realloc(str->buffer,length);
      str->allocated = length;
    }
  }
}

