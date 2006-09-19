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

/** \file libwzd_err.c
 *  \brief Error handling routines
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "libwzd.h"
#include "libwzd_err.h"
#include "libwzd_pv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#else
# include <windows.h>
#endif

static char * _err_buf = NULL;
static int _err_offset = 0;
static int _err_max = 0;

static int _err_default_hook(const char *s);
static int _err_call_hook(void);

static int _err_set_minimum_size(int s);

static err_hook_t _err_hook = _err_default_hook;

int err_init(void)
{
  if (_err_buf) free(_err_buf);
  _err_max = 1024;
  _err_buf = malloc(_err_max);
  _err_offset = 0;

  return 0;
}

/** \brief Free error handling buffers
 */
void err_fini(void)
{
  if (_err_buf) free(_err_buf);
  _err_buf = NULL;
  _err_max = 0;
  _err_offset = 0;
}

/** \brief Store error message
 */
void err_store(const char *msg)
{
  size_t length;

  if (_err_buf == NULL) return;

  length = strlen(msg);
  if (_err_set_minimum_size(_err_offset+length+3)<0) return;

  strncpy(_err_buf+_err_offset,msg,length+2);
  _err_buf[_err_offset+length] = '\n';
  _err_offset += length+1;

  _err_call_hook();
}

/** \brief Change callback when an error message is stored
 */
void err_set_hook(err_hook_t new_hook)
{
  _err_hook = new_hook;
}

static int _err_set_minimum_size(int s)
{
  char * ptr;

  if (s >= _err_max) {
    ptr = realloc(_err_buf,s);
    if (ptr == NULL) return -1;
    _err_buf = ptr;
    _err_max = s;
  }
  return 0;
}

static int _err_call_hook(void)
{
  int ret;

  if (_err_hook == NULL) return -1;

  ret = (*_err_hook)(_err_buf);

  if (ret >= 0) {
    _err_offset = 0;

    return 0;
  }

  return -1;
}

static int _err_default_hook(const char *s)
{
  fprintf(stderr,"ERROR %s",s);
  fflush(stderr);

  return 0;
}
