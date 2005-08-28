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

#include "libwzd-base/list.h"

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

/** \brief Deallocates a NULL-terminated string list
 */
void str_deallocate_array(wzd_string_t **array)
{
  wzd_string_t ** iterator = array;

  if (!iterator) return;

  while ( (*iterator) ) {
    str_deallocate(*iterator);
    iterator++;
  }
  wzd_free(array);
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

/** returns 1 if string exists and length is inside min and max (included)
 */
unsigned int str_checklength(const wzd_string_t *str, size_t min, size_t max)
{
  if (!str || !str->buffer) return 0;
  if (strlen(str->buffer) < min || strlen(str->buffer) > max) return 0;
  return 1;
}

/** Get the length of the given string, or -1 if error
 */
size_t str_length(const wzd_string_t *str)
{
  if (!str || !str->buffer) return -1;
  return str->length;
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
    dst->length = src->length;
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

/** \brief append character \a c to string pointed to by str
 */
wzd_string_t * str_append_c(wzd_string_t * str, const char c)
{
  if (!str) return NULL;

  _str_set_min_size(str,str->length + 2);
  if (str->buffer) {
    str->buffer[str->length] = c;
    str->length ++;
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

  if (i!=0) {
    unsigned int j=0;
    for (;i!=str->length;i++)
    {
      str->buffer[j++] = str->buffer[i];
    }
    str->length = j;
    str->buffer[j] = '\0';
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

  while ((--len > 0) &&
      (isspace(str->buffer[len]) ||
       str->buffer[len] == '\n')) {
    str->buffer[len] = '\0';
    str->length--;
  }
  return str;
}

/** \brief Removes \a len characters from a wzd_string_t, starting at position \a pos.
 *
 * The rest of the wzd_string_t is shifted down to fill the gap.
 */
wzd_string_t * str_erase(wzd_string_t * str, size_t pos, int len)
{
  if (!str || !str->buffer) return NULL;
  if (pos > str->length) return NULL;

  if (len < 0)
    len = str->length - pos;
  else {
    if (pos + len > str->length) return NULL;

    if (pos + len < str->length)
      wzd_memmove (str->buffer + pos, str->buffer + pos + len, str->length - (pos + len));
  }

  str->length -= len;
  
  str->buffer[str->length] = 0;

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

#ifdef DEBUG
  if (!str)
    out_log(LEVEL_HIGH,"str_tok called with NULL argument !\n");
#endif

  if (!str || !str->buffer || str->length == 0) return NULL;
  if (!delim) return NULL;

  buffer = wzd_strdup(str->buffer);
  t = strtok_r(buffer, delim, &ptr);

  token = STR(t);
  if (t) {
    if (ptr) {
      str->length = strlen(ptr);
      wzd_strncpy(str->buffer, ptr, str->length+1);
    } else {
      str->length = 0;
      str->buffer[0] = '\0';
    }
  }
  wzd_free(buffer);

  return token;
}

/** \brief str_read next token
 * \return a pointer to the next token, or NULL if not found, or if there is \
 * only whitespaces, or if quotes are unbalanced
 * Read next token separated by a whitespace, except if string begins
 * with a ' or ", in this case it searches the matching character.
 * Note: input string is modified as a \\0 is written.
 */
wzd_string_t * str_read_token(wzd_string_t *str)
{
  char *tok, c;
  char sep[2];
  char *s;
  char *ptr, *endptr;
  wzd_string_t * str_ret=NULL;

  if (!str || !str->buffer || str->length == 0) return NULL;

  s = str->buffer;

  if (s == NULL)
  {
    return NULL;
  }

  /* skip leading spaces */
  while ( (c = *s) && isspace(c) ) s++;
  if (*s == '\0') /* only whitespaces */
  { return NULL; }

  /* search for any whitespace or quote */
  tok = strpbrk(s, " \t\r\n\"'");

  if (!tok) {
    str_ret = STR(str->buffer);
    /* nothing, we return string */
    str->length = 0;
    str->buffer[0] = '\0';
    return str_ret;
  }

  /* the first char is a quote ? */
  if (*tok == '"' || *tok == '\'') {
    sep[0] = *tok;
    sep[1] = '\0';
    if (!strchr(tok+1,*tok)) { /* unbalanced quotes */
      return NULL;
    }
    /** \bug we can't have escaped characters */
    ptr = strtok_r(tok, sep, &endptr);
    str_ret = STR(ptr);
    str->length = strlen(str->buffer);
    return str_ret;
  }

  /* normal case, we search a whitespace */
  return str_tok(str, " \t\r\n");
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
#ifndef WIN32
  if (result < 0) return result;
  if ((unsigned int)result >= str->allocated)
  {
    _str_set_min_size(str, result+1);
    va_end(argptr);
    va_start(argptr,format); /* note: ansi compatible version of va_start */
    result = vsnprintf(str->buffer, str->allocated, format, argptr);
  }
  str->length = result;
#else /* WIN32 */
  /* windows is crap, once again
   * vsnprintf does not return the number that should be been allocated,
   * it always return -1 if the buffer is not large enough
   */
   while (result < 0)
   {
     if (str->allocated >= 1024000) {
       return -1;
     }
     _str_set_min_size(str,str->allocated + (str->allocated >> 2) + 20);
     va_end(argptr);
     va_start(argptr,format); /* note: ansi compatible version of va_start */
     result = vsnprintf(str->buffer, str->allocated-1, format, argptr);
   }
   str->length = result;
   if ((u32_t)result == str->allocated) {
    _str_set_min_size(str, result+1);
    str->buffer[str->length] = '\0';
   }
#endif

  va_end (argptr);

  return result;
}

/** \brief Append formatted output to string
 */
int str_append_printf(wzd_string_t *str, const char *format, ...)
{
  va_list argptr;
  int result;
  char * buffer = NULL;
  size_t length = 0;

  if (!str) return -1;
  if (!format) return -1;

  if (!str->buffer)
    _str_set_min_size(str,str->length + strlen(format)+1);

  va_start(argptr,format); /* note: ansi compatible version of va_start */

  result = vsnprintf(buffer, 0, format, argptr);
#ifndef WIN32
  if (result < 0) return result;
  result++;
  if ((unsigned int)result >= length)
  {
    buffer = wzd_malloc( result + 1 );
    va_end(argptr);
    va_start(argptr,format); /* note: ansi compatible version of va_start */
    result = vsnprintf(buffer, result, format, argptr);
  }
  length = result;
#else /* WIN32 */
  /* windows is crap, once again
   * vsnprintf does not return the number that should be been allocated,
   * it always return -1 if the buffer is not large enough
   */
   while (result < 0)
   {
     if (length >= 1024000) {
       return -1;
     }
     wzd_free(buffer);
     result = result + (result >> 2) + 20;
     buffer = wzd_malloc(result);
     va_end(argptr);
     va_start(argptr,format); /* note: ansi compatible version of va_start */
     result = vsnprintf(buffer, result-1, format, argptr);
   }
   length = result;
   if ((u32_t)result == length) {
    _str_set_min_size(str, result+1);
    buffer[length] = '\0';
   }
#endif

  va_end (argptr);

  str_append(str, buffer);
  if (buffer) wzd_free(buffer);

  return str->length;
}

/** \brief Split \a str into a maximum of \a max_tokens pieces, separated by \a sep.
 *
 * If \a max_tokens is reached, the remainder of \a str is appended to the last token.
 *
 * \return a NULL-terminated string array, or NULL. The array must be freed using
 * str_deallocate_array().
 */
wzd_string_t ** str_split(wzd_string_t * str, const char * sep, int max_tokens)
{
  List string_list;
  ListElmt * elmnt;
  const char *remainder = NULL;
  char * s;
  wzd_string_t * token;
  wzd_string_t ** str_array;
  unsigned int i;

  if (!str || !sep || sep[0]=='\0') return NULL;

  if (max_tokens < 1) max_tokens = (unsigned int)-1;

  list_init(&string_list,NULL);

  remainder = str->buffer;
  s = strstr(remainder, sep);
  if (s) {
    size_t len;
    size_t delimiter_len = strlen(sep);

    while (--max_tokens && s) {
      len = s - remainder;
      token = str_allocate();
      _str_set_min_size(token, len + 1);
      strncpy(token->buffer, remainder, len);
      token->buffer[len] = '\0';
      token->length = len;

      list_ins_next(&string_list, list_tail(&string_list), token);

      remainder = s + delimiter_len;

      s = strstr(remainder, sep);
    }
  }

  if (remainder && remainder[0] != '\0')
    list_ins_next(&string_list, list_tail(&string_list), STR(remainder));

  str_array = wzd_malloc( (list_size(&string_list)+1) * sizeof(wzd_string_t*) );
  i = 0;
  for (elmnt = list_head(&string_list); elmnt; elmnt = list_next(elmnt)) {
    str_array[i++] = list_data(elmnt);
  }
  str_array[i] = NULL;

  list_destroy(&string_list);

  return str_array;
}

#ifdef HAVE_UTF8
/** \brief Convert utf8 string to other charset
 * \note
 * Require unicode support
 */
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

/** \brief Convert charset to utf8 string
 * \note
 * Require unicode support
 */
int str_local_to_utf8(wzd_string_t *str, const char * charset)
{
  char * utf_buf;
  size_t length;

  /** \bug testing if a strin to be converted to UTF-8 is already
  valid UTF-8 is a bit stupid */
/*  if (!utf8_valid(str->buffer, str->length)) {
    return -1;
  } */

  length = strlen(str->buffer) + 10; /* we allocate more, small security */
  utf_buf = wzd_malloc(length);

  if (local_charset_to_utf8(str->buffer, utf_buf, length, charset))
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

/** \brief test if string is valid utf8
 * \note
 * require unicode support
 */
int str_is_valid_utf8(wzd_string_t *str)
{
  return utf8_valid(str->buffer,str->length);
}

#else
int str_utf8_to_local(wzd_string_t *str, const char * charset)
{
  return -1;
}

int str_local_to_utf8(wzd_string_t *str, const char * charset)
{
  return -1;
}

int str_is_valid_utf8(wzd_string_t *str)
{
  return -1;
}

#endif /* HAVE_UTF8 */





static inline void _str_set_min_size(wzd_string_t *str, size_t length)
{
  void * ptr;

  if (str) {
    if (length > str->allocated) {
      /* allocate a bit more than requested */
      if (length < 200) length += 20;
      else length = (size_t)(length * 1.3);

      if (!str->buffer) {
        str->buffer = wzd_malloc(length);
      } else {
        if ( (ptr = wzd_realloc(str->buffer,length)) ) {
          str->buffer = ptr;
        } else {
          ptr = wzd_malloc(length);
          memcpy(ptr,str->buffer,str->length);
          wzd_free(str->buffer);
          str->buffer = ptr;
        }
      }
      str->allocated = length;
    }
  }
}

