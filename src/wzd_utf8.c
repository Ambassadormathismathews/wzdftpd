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

#include <wchar.h>

#ifdef WIN32
# include <windows.h>
#endif

#if HAVE_LANGINFO_CODESET
# include <langinfo.h>
#endif

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_utf8.h"

#include "wzd_debug.h"

#ifdef BSD
#define	DL_ARG	DL_LAZY
#else
#define	DL_ARG	RTLD_NOW
#endif

/* BSD exports symbols in .so files prefixed with a _ !! */
#ifdef BSD
#define	DL_PREFIX "_"
#else
#define	DL_PREFIX
#endif

typedef void *  iconv_t;
typedef size_t (*fn_iconv_t)(iconv_t, const char **, size_t *, char **, size_t *);
typedef iconv_t (*fn_iconv_open_t)(const char *, const char *);
typedef int (*fn_iconv_close_t)(iconv_t);

static void * _iconv_lib_handle = NULL;
static fn_iconv_t _iconv_fn_iconv = NULL;
static fn_iconv_open_t _iconv_fn_iconv_open = NULL;
static fn_iconv_close_t _iconv_fn_iconv_close = NULL;


static void _iconv_openlib(void)
{
#ifdef HAVE_UTF8

#ifdef HAVE_ICONV
  _iconv_fn_iconv = (fn_iconv_t)&iconv;
  _iconv_fn_iconv_open = (fn_iconv_open_t)&iconv_open;
  _iconv_fn_iconv_close = (fn_iconv_close_t)&iconv_close;
#else /* HAVE_ICONV */

#ifdef WIN32
  if (_iconv_lib_handle == NULL)
  {
    _iconv_lib_handle = dlopen("libiconv-2.dll", DL_ARG);
    if (_iconv_lib_handle == NULL) return;

    /** \bug I don't understant why this f*cking windows does not find 'libiconv' using
     * the name, I've checked with depends.exe: all API calls are good. Windows does
     * just not find it, except if I use the ordinal value, which is _very_ bad.
     * This clearly looks like a windows bug in GetProcAddress.
     * cd c:\HOMEDIR\wzdftpd\visual
     * c:\INSTALL\depends21_x86\depends.exe /pg:1 .\Debug\wzdftpd.exe -f wzd-win32.cfg
     */
    _iconv_fn_iconv =       (fn_iconv_t)dlsym(_iconv_lib_handle, DL_PREFIX "libiconv");
    if (!_iconv_fn_iconv) /* try by ordinal */
      _iconv_fn_iconv =     (fn_iconv_t)dlsym(_iconv_lib_handle, (char*)0x00000004);
    _iconv_fn_iconv_open =  (fn_iconv_open_t)dlsym(_iconv_lib_handle, DL_PREFIX "libiconv_open");
    _iconv_fn_iconv_close = (fn_iconv_close_t)dlsym(_iconv_lib_handle, DL_PREFIX "libiconv_close");

    if ( !_iconv_fn_iconv || !_iconv_fn_iconv || !_iconv_fn_iconv_close )
    {
      dlclose(_iconv_lib_handle);
      _iconv_lib_handle = NULL;
    }
  }

#endif /* WIN32 */

#endif /* HAVE_ICONV */

#endif /* HAVE_UTF8 */
}

static void _iconv_closelib(void)
{
#ifdef WIN32
  if (_iconv_lib_handle)
  {
    dlclose(_iconv_lib_handle);
    _iconv_lib_handle = NULL;
    _iconv_fn_iconv = NULL;
    _iconv_fn_iconv_open = NULL;
    _iconv_fn_iconv_close = NULL;
  }
#endif /* HAVE_ICONV */
}


static const char * _local_charset = NULL;

const char * local_charset(void)
{
  return _local_charset;
}


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

int local_charset_to_utf8(const char *src, char *dst_utf8, size_t max_len, const char *local_charset)
{
#ifdef HAVE_UTF8
  size_t nconv, size, avail;
  mbstate_t state;
  iconv_t cd;

  if ( !_iconv_fn_iconv || !_iconv_fn_iconv || !_iconv_fn_iconv_close ) return -1;
  cd = (*_iconv_fn_iconv_open)("UTF-8", local_charset);
  if (cd == (iconv_t)-1) {
    return -1;
  }

  size = strlen(src);
  avail = max_len;
  memset(&state, '\0', sizeof(state));

  /* conversion to multibyte */
  nconv = (*_iconv_fn_iconv)(cd, &src, &size, (char**)&dst_utf8, &avail);
  if (nconv == (size_t)-1) {
    /* error during conversion, see errno */
    (*_iconv_fn_iconv_close)(cd);
    return -1;
  }
  (*_iconv_fn_iconv_close)(cd);

  /* terminate output string */
  if (avail >= sizeof(wchar_t))
    *((wchar_t*)dst_utf8) = L'\0';

  return 0;
#else /* HAVE_UTF8 */
  return 1;
#endif /* HAVE_UTF8 */
}

int utf8_to_local_charset(const char *src_utf8, char *dst, size_t max_len, const char *local_charset)
{
#ifdef HAVE_UTF8
  size_t nconv, size, avail;
  mbstate_t state;
  iconv_t cd;

  if ( !_iconv_fn_iconv || !_iconv_fn_iconv || !_iconv_fn_iconv_close ) return -1;
  cd = (*_iconv_fn_iconv_open)(local_charset, "UTF-8");
  if (cd == (iconv_t)-1) {
    return -1;
  }

  size = strlen(src_utf8);
  avail = max_len;
  memset(&state, '\0', sizeof(state));

  /* conversion to multibyte */
  nconv = (*_iconv_fn_iconv)(cd, &src_utf8, &size, (char**)&dst, &avail);
  if (nconv == (size_t)-1) {
    /* error during conversion, see errno */
    (*_iconv_fn_iconv_close)(cd);
    return -1;
  }
  (*_iconv_fn_iconv_close)(cd);

  /* terminate output string */
  if (avail >= sizeof(char))
    *((char*)dst) = '\0';

  return 0;
#else /* HAVE_UTF8 */
  return 1;
#endif /* HAVE_UTF8 */
}


/** \brief Valid UTF-8 check
 *
 * taken from RFC2640
 * Checks if a bte sequence is valid UTF-8.
 *
 * \return 1 if input string is valid UTF-8, else 0
 */
int utf8_valid(const unsigned char *buf, unsigned int len)
{
  const unsigned char *endbuf = buf + len;
  unsigned char byte2mask=0x00, c;
  int trailing=0; // trailing (continuation) bytes to follow

  while (buf != endbuf)
  {
    c = *buf++;
    if (trailing)
      if ((c & 0xc0) == 0x80) // does trailing byte follow UTF-8 format ?
      {
        if (byte2mask) // need to check 2nd byte for proper range
          if (c & byte2mask) // are appropriate bits set ?
            byte2mask = 0x00;
          else
            return 0;
        trailing--;
      }
      else
        return 0;
    else
      if ((c & 0x80) == 0x00) continue; // valid 1-byte UTF-8
      else if ((c & 0xe0) == 0xc0)      // valid 2-byte UTF-8
        if (c & 0x1e) //is UTF-8 byte in proper range ?
          trailing = 1;
        else
          return 0;
      else if ((c & 0xf0) == 0xe0)      // valid 3-byte UTF-8
      {
        if (!(c & 0x0f))                // is UTF-8 byte in proper range ?
          byte2mask = 0x20;             // if not set mask
        trailing = 2;                   // to check next byte
      }
      else if ((c & 0xf8) == 0xf0)      // valid 4-byte UTF-8
      {
        if (!(c & 0x07))                // is UTF-8 byte in proper range ?
          byte2mask = 0x30;             // if not set mask
        trailing = 3;                   // to check next byte
      }
      else if ((c & 0xfc) == 0xf8)      // valid 5-byte UTF-8
      {
        if (!(c & 0x03))                // is UTF-8 byte in proper range ?
          byte2mask = 0x38;             // if not set mask
        trailing = 4;                   // to check next byte
      }
      else if ((c & 0xfe) == 0xfc)      // valid 6-byte UTF-8
      {
        if (!(c & 0x01))                // is UTF-8 byte in proper range ?
          byte2mask = 0x3c;             // if not set mask
        trailing = 5;                   // to check next byte
      }
      else
        return 0;
  }
  return trailing == 0;
}


void utf8_detect(wzd_config_t * config)
{
  _local_charset = charset_detect_local();
  _iconv_openlib();

  if ( _local_charset && _iconv_fn_iconv && _iconv_fn_iconv && _iconv_fn_iconv_close )
  {
    out_log(LEVEL_INFO, "UTF-8 detected and enabled\n");
    CFG_SET_OPTION(config,CFG_OPT_UTF8_CAPABLE);
  } else {
    CFG_CLR_OPTION(config,CFG_OPT_UTF8_CAPABLE);
  }
}

void utf8_end(wzd_config_t * config)
{
  _local_charset = NULL;
  _iconv_closelib();
  CFG_CLR_OPTION(config,CFG_OPT_UTF8_CAPABLE);
  out_log(LEVEL_INFO, "UTF-8 disabled\n");
}
