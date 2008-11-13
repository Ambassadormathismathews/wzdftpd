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

#ifndef __WZD_LIST__
#define __WZD_LIST__

int list(socket_t,wzd_context_t *,enum list_type_t,char *,char *,int callback(socket_t,wzd_context_t*,char *));
int old_list(int,wzd_context_t *,enum list_type_t,char *,char *,int callback(socket_t,wzd_context_t*,char *)) DEPRECATED;
int list_match(char *,char *);

/* filename must be an ABSOLUTE path
 * return a newly allocated string
 */
char * mlst_single_file(const char *filename, wzd_context_t * context);

int mlsd_directory(const char * dirname, socket_t sock, int callback(socket_t,wzd_context_t*,char *),
    wzd_context_t * context);

#endif /* __WZD_LIST__ */
