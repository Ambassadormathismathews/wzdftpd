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
/** \file
  * \brief strtok_r() replacement
  */

#include "wzd_all.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#ifndef HAVE_STRTOK_R

#include <stddef.h>
#include <string.h>

#include "wzd_strtok_r.h"

char * strtok_r(char *s, const char *delim, char **last)
{
  char *spanp;
  int c, sc;
  char *tok;

  if (s == NULL && (s = *last) == NULL)
  {
    return NULL;
  }

  /*
   * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
   */
cont:
  c = *s++;
  for (spanp = (char *)delim; (sc = *spanp++) != 0; )
  {
    if (c == sc)
    {
      goto cont;
    }
  }

  if (c == 0)  /* no non-delimiter characters */
  {
    *last = NULL;
    return NULL;
  }
  tok = s - 1;

  /*
   * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
   * Note that delim must have one NUL; we stop if we see that, too.
   */
  for (;;)
  {
    c = *s++;
    spanp = (char *)delim;
    do
    {
      if ((sc = *spanp++) == c)
      {
        if (c == 0)
        {
          s = NULL;
        }
        else
        {
          char *w = s - 1;
          *w = '\0';
        }
        *last = s;
        return tok;
      }
    }
    while (sc != 0);
  }
  /* NOTREACHED */
}

#endif
