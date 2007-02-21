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

#ifndef __WZD_RATIO_H__
#define __WZD_RATIO_H__

/** \brief Get credits for user
 *
 * \param[in] user user definition
 *
 * \return The ratio, as a 64 bits unsigned integer
 */
u64_t ratio_get_credits(wzd_user_t * user);

/** \brief Check if user is allowed to perform a download
 *
 * \param[in] path The file to be downloaded
 * \param[in] context The context of the client
 *
 * \return
 * - 0 if user if allowed to download the file
 * - 1 if user if not allowed to download the file
 * - -1 if an error occured
 */
int ratio_check_download(const char *path, wzd_context_t *context);

#endif /* __WZD_RATIO_H__ */
