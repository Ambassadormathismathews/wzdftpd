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

#ifndef __WZD_UTF8__
#define __WZD_UTF8__

/** Detect if system is UTF-8 capable
 */
void utf8_detect(wzd_config_t * config);

/** Disable UTF-8 support, and free all memory used for unicode.
 */
void utf8_end(wzd_config_t * config);

const char * charset_detect_local(void);

const char * local_charset(void);

int local_charset_to_utf8(const char *src, char *dst_utf8, size_t max_len, const char *local_charset);

int utf8_to_local_charset(const char *src_utf8, char *dst, size_t max_len, const char *local_charset);

#endif /* __WZD_UTF8__ */
