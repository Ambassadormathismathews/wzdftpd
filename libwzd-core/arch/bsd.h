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
/** \file bsd.h
  * \brief BSD-specific definitions.
  */

#ifndef __ARCH_BSD__
#define __ARCH_BSD__

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#undef IN6_IS_ADDR_V4MAPPED
#define ULONG uint32_t

/* that's required for some old BSDs, e.g. FreeBSD 4.x */
#if !defined(PRIu64)
#define		PRIu64		"llu"
#endif /* PRIu64 */

#endif

#endif /* __ARCH_BSD__ */
