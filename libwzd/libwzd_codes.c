/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

/** \file libwzd_codes.c
 *  \brief Definitions for FTP reply codes
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "libwzd_codes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Splits the FTP reply code in three parts, which can be interpreted using
 * the previous macros REPLY_DIGIT_... and REPLY_DIGIT2_...
 * \note The meaning of the last digit is very unclear in RFC959
 * \return 0 if ok, 1 if the code is not a valid FTP reply code
 */
int wzd_split_reply_code(int code, int * digit1, int * digit2, int * digit3)
{
  if ( ! REPLY_IS_VALID(code) ) return 1;

  if (digit3) *digit3 = (code % 10);
  code /= 10;
  if (digit2) *digit2 = (code % 10);
  code /= 10;
  if (digit1) *digit1 = (code % 10);
  code /= 10;

  return 0;
}

