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

#include <stdio.h>
#include <string.h>

#include "wzd_structs.h"

#if HAVE_LANGINFO_CODESET
# include <langinfo.h>
#endif

#include "wzd_utf8.h"

#include "wzd_debug.h"

const char * charset_detect_local(void)
{
  char * codeset = NULL;
#ifdef HAVE_UTF8

#if !(defined WIN32)

# if HAVE_LANGINFO_CODESET

  /* should be very common now */
  codeset = nl_langinfo (CODESET);

# else

  const char * locale = NULL;

  /* on old systems, use getenv */
  locale = getenv("LC_ALL");
  if (locale == NULL || locale[0] == '\0')
  {
    locale = getenv("LC_CTYPE");
    if (locale == NULL || locale[0] == '\0')
      locale = getenv("LANG");
  }
  codeset = locale; /* something like language_COUNTRY.charset */
  
  /* we need to try to translate that into an understandable
   * codeset for iconv (see `iconv --list`)
   */
  
# endif
 
#else /* !WIN32 */
  static char buf[2 + 10 + 1];

  /* win32 has a function returning the locale's codepage as a number */
  sprintf (buf, "CP%u", GetACP());
  codeset = buf;

#endif /* !WIN32 */

#endif /* HAVE_UTF8 */
  return codeset;
}
