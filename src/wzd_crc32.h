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

#ifndef __WZD_CRC32__
#define __WZD_CRC32__

/* inits an sfv struct
 */
void sfv_init(wzd_sfv_file *sfv);

/* reads sfv file
 */
int sfv_read(const char *filename, wzd_sfv_file *sfv);

/* frees contents of a sfv structure
 * if sfv was allocated on heap you MUST free sfv struct after
 */
void sfv_free(wzd_sfv_file *sfv);

/* checks sfv file
 * returns 0 if all ok
 * 1 if error occurs
 * 2 if missing files
 * 3 if missing + error
 * -1 for other errors
 * !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_check(const char * sfv_file);


/***** EVENT HOOKS *****/
int sfv_hook_preupload(unsigned long event_id, const char * username, const char * filename);
int sfv_hook_postupload(unsigned long event_id, const char * username, const char * filename);


#endif /* __WZD_CRC32__ */
