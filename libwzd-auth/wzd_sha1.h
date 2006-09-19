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

#ifndef __WZD_SHA1_H__
#define __WZD_SHA1_H__

/*! \addtogroup libwzd_auth
 *  @{
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifdef WIN32
# define uint32_t unsigned __int32
#endif

#define SHA1_DIGEST_SIZE        20
#define SHA1_BLOCK_SIZE         64

typedef uint32_t SHA1_WORD;

struct SHA1_CONTEXT {
  SHA1_WORD       H[5];

  unsigned char blk[SHA1_BLOCK_SIZE];
  unsigned blk_ptr;
};

typedef unsigned char SHA1_DIGEST[20];


const char *sha1_hash(const char *);

void sha1_digest(const void *, unsigned, SHA1_DIGEST);

/*! @} */

#endif /* __WZD_SHA1_H__ */

