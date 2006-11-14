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

#ifndef __WZD_PROTOCOL__
#define __WZD_PROTOCOL__

/** \file wzd_protocol.h
 * \brief FTP protocol routines
 *
 * \addtogroup libwzd_core
 * @{
 */

struct ftp_command_t {
  wzd_string_t * command_name;
  wzd_string_t * args;

  wzd_command_t * command;
};

/** \brief Free memory used by a \a ftp_command_t structure */
void free_ftp_command(struct ftp_command_t * command);

/** \brief Fast token identification function.
 *
 * Converts the string into an integer and return the corresponding
 * identifier. Luckily, all FTP commands are no more than 4 characters.
 */
int identify_token(const char *token);

/** \brief Parse and identify FTP command
 *
 * \note Input string is modified.
 */
struct ftp_command_t * parse_ftp_command(wzd_string_t * s);

/** @} */

#endif /* __WZD_PROTOCOL__ */

