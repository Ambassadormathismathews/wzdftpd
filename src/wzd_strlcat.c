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

#include <string.h>

#ifndef HAVE_STRLCAT

/* sometimes strlen() is faster than using pointers ..
 * In this case, uncomment the following
 */
/*#define STRLEN_FASTER*/


/* append src to dst, guaranteeing a null terminator.
 * If dst+src is too big, truncate it.
 * Return strlen(old dst)+dstrlen(src).
 */
size_t strlcat(char *dst, const char *src, size_t size)
{
  size_t n=0;

  /* find the end of string in dst */
#ifdef STRLEN_FASTER
  if (!size)
    return strlen(src);
  n = strlen(dst);
  dst += n;
#else
  while (n < size && *dst++)
    ++n;

  if (n >= size)
    return size + strlen(src);
  /* back up over the '\0' */
  --dst;
#endif

  /* copy bytes from src to dst.
   * If there's no space left, stop copying
   * if we copy a '\0', stop copying
   */
  while (n < size) {
    if (!(*dst++ = *src++))
      return n;
    ++n;
  }

  if (n == size) {
    /* overflow, so truncate the string, and ... */
    if (size)
      dst[-1] = '\0';
    /* ... work out what the length would have been had there been
     * enough space in the buffer
     */
    n += strlen(dst);
  }
  
  return n;
}

#endif /* HAVE_STRLCAT */
