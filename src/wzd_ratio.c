/* vi:ai:et:ts=8 sw=2
 */
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

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>	/* struct in_addr (wzd_misc.h) */
#endif

#include <stdio.h>
#include <sys/stat.h>

#include "wzd_structs.h"

#include "wzd_ratio.h"
#include "wzd_misc.h"

u64_t ratio_get_credits(wzd_user_t * user)
{
  if (!user->ratio) return (u64_t)-1;

  return user->credits;
}

int ratio_check_download(const char *path, wzd_context_t *context)
{
  wzd_user_t * me;
  u64_t credits;
  struct stat s;
  u64_t needed=0;

  me = GetUserByID(context->userid);

  if (!me->ratio) return 0;
  credits = ratio_get_credits(me);

  if (stat(path,&s)) {
    /* problem during stat() */
    return -1;
  }

  needed = s.st_size;

  if (needed <= credits)
    return 0;
  else
    return 1;
}
