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

#ifndef __WZD_STRING__
#define __WZD_STRING__

#include <stdarg.h> /* va_list */

typedef struct wzd_string_t wzd_string_t;

wzd_string_t * str_allocate(void);
void str_deallocate(wzd_string_t *st);

/** \brief Deallocates a NULL-terminated string list
 */
void str_deallocate_array(wzd_string_t **array);

/** returns a pointer to a new string which is a duplicate of the string str.
 */
wzd_string_t * str_fromchar(const char *str);

#define STR(x) str_fromchar((x))

/** returns a pointer to a new string pointing to \a str
 *
 * \note \a str must not be freed, you must use str_deallocate() on the result
 */
wzd_string_t * str_fromchar_raw(char *str);

#define STR_RAW(x) str_fromchar_raw((x))

/** returns a pointer to the data contained in the string str.
 * These data must NOT be modified !
 */
const char * str_tochar(const wzd_string_t *str);

/** returns 1 if string exists and length is inside min and max (included)
 */
unsigned int str_checklength(const wzd_string_t *str, size_t min, size_t max);

/** Get the length of the given string, or -1 if error
 */
size_t str_length(const wzd_string_t *str);

/** \brief Store a copy of the argument into \a str
 */
wzd_string_t * str_store(wzd_string_t * str, const char * s);

/** \brief returns a pointer to a new string which is a duplicate of the string src.
 */
wzd_string_t * str_dup(const wzd_string_t *src);

/** \brief copies the string pointed to by src (including the terminating `\\0'
 * character) to the array pointed to by  dest.
 */
wzd_string_t * str_copy(wzd_string_t *dst, const wzd_string_t *src);

/** \brief append \a tail to string pointed to by \a str
 */
wzd_string_t * str_append(wzd_string_t * str, const char *tail);

/** \brief append character \a c to string pointed to by str
 */
wzd_string_t * str_append_c(wzd_string_t * str, const char c);

/** \brief prepend 'head' to string pointed to by str
 */
wzd_string_t * str_prepend(wzd_string_t * str, const char *head);

/** \brief remove all leading and trailing spaces from input string
 */
wzd_string_t * str_trim(wzd_string_t * str);
wzd_string_t * str_trim_left(wzd_string_t *str);
wzd_string_t * str_trim_right(wzd_string_t *str);

/** \brief Removes \a len characters from a wzd_string_t, starting at position \a pos.
 *
 * The rest of the wzd_string_t is shifted down to fill the gap.
 */
wzd_string_t * str_erase(wzd_string_t * str, size_t pos, size_t len);

/** \brief Convert string to lower case
 * \note
 * This function modifies its input string
 */
wzd_string_t * str_tolower(wzd_string_t *str);

/** \brief Extract token from string str
 * \note
 * This function modifies its input string
 */
wzd_string_t * str_tok(wzd_string_t *str, const char *delim);

/** \brief str_read next token
 * \return a pointer to the next token, or NULL if not found, or if there is
 * only whitespaces, or if quotes are unbalanced
 *
 * Read next token separated by a whitespace, except if string begins
 * with a ' or ", in this case it searches the matching character.
 * Note: input string is modified as a \0 is written.
 */
wzd_string_t * str_read_token(wzd_string_t *str);

/** \brief Produce output according to format and variable number of arguments,
 * and write output to str.
 */
int str_sprintf(wzd_string_t *str, const char *format, ...);

/** \brief Produce output according to \a format and variable number of arguments,
 * and write output to \a str.
 */
int str_vsprintf(wzd_string_t *str, const char *format, va_list ap);

/** \brief Prepend formatted output to string
 */
size_t str_prepend_printf(wzd_string_t *str, const char *format, ...);

/** \brief Append formatted output to string
 */
size_t str_append_printf(wzd_string_t *str, const char *format, ...);

/** \brief Split \a str into a maximum of \a max_tokens pieces, separated by \a sep.
 *
 * If \a max_tokens is reached, the remainder of \a str is appended to the last token.
 *
 * \return a NULL-terminated string array, or NULL. The array must be freed using
 * str_deallocate_array().
 */
wzd_string_t ** str_split(wzd_string_t * str, const char * sep, int max_tokens);

/** \brief Convert utf8 string to other charset
 * \note
 * Require unicode support
 */
int str_utf8_to_local(wzd_string_t *str, const char * charset);

/** \brief Convert charset to utf8 string
 * \note
 * Require unicode support
 */
int str_local_to_utf8(wzd_string_t *str, const char * charset);

/** \brief test if string is valid utf8
 * \note
 * require unicode support
 */
int str_is_valid_utf8(wzd_string_t *str);

#endif /* __WZD_STRING__ */

