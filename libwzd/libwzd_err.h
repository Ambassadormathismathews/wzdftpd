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

/** \file libwzd_err.h
 *  \brief Error handling routines
 */

#ifndef __LIBWZD_ERR__
#define __LIBWZD_ERR__

/*! \addtogroup libwzd
 *  @{
 */

#ifdef	__cplusplus
extern "C" {
#endif

/** \brief Initialise error handling routines and buffers.
 */
int err_init(void);

/** \brief Free error handling buffers
 */
void err_fini(void);

/** \brief Store error message
 */
void err_store(const char *msg);

typedef int (*err_hook_t)(const char *);

/** \brief Change callback when an error message is stored
 */
void err_set_hook(err_hook_t new_hook);

/** \todo write following functions:
 * Set hook when connection has been closed (on error or not)
 * Store error message (with format)
 * Get Error message(s)
 */

#ifdef	__cplusplus
} /* extern "C" */
#endif

/*! @} */

#endif /* __LIBWZD_ERR__ */

