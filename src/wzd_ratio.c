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

#include <sys/time.h>	/* time_t (wzd_structs.h) */
#include <arpa/inet.h>	/* struct in_addr (wzd_misc.h) */

#include <sys/stat.h>

/* speed up compilation */
#define SSL	void
#define SSL_CTX	void
#define FILE	void

#include "wzd_structs.h"

#include "wzd_ratio.h"
#include "wzd_misc.h"

unsigned long long ratio_get_credits(wzd_user_t * user)
{
  unsigned long long credits;

  if (!user->ratio) return (unsigned long long)-1;

  /* TODO XXX FIXME we should ensure here the multiplication will not overflow ... */
  credits = (user->bytes_ul_total) * (unsigned long long)user->ratio;
  credits -= user->bytes_dl_total;

  return credits;
}

int ratio_check_download(const char *path, wzd_context_t *context)
{
  wzd_user_t * me;
  unsigned long long credits;
  struct stat s;
  unsigned long needed=0;

  me = GetUserByID(context->userid);

  if (!me->ratio) return 0;
  credits = ratio_get_credits(me);

  if (!stat(path,&s)) {
    /* problem during stat() */
    return -1;
  }

  needed = s.st_size;

  if (needed <= credits)
    return 0;
  else
    return 1;
}
