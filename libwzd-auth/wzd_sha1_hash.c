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

#include <string.h>

#include "wzd_sha1.h"

static const char base64tab[]= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char *sha1_hash(const char *passw)
{
  SHA1_DIGEST sha1buf;
  static char hash_buffer[1+(sizeof(sha1buf)+2)/3*4];
  int   a=0,b=0,c=0;
  int   d, e, f, g;
  unsigned int i, j;

  sha1_digest(passw, strlen(passw), sha1buf);

  j=0;

  for (i=0; i<sizeof(sha1buf); i += 3)
  {
    a=sha1buf[i];
    b= i+1 < sizeof(sha1buf) ? sha1buf[i+1]:0;
    c= i+2 < sizeof(sha1buf) ? sha1buf[i+2]:0;

    d=base64tab[ a >> 2 ];
    e=base64tab[ ((a & 3 ) << 4) | (b >> 4)];
    f=base64tab[ ((b & 15) << 2) | (c >> 6)];
    g=base64tab[ c & 63 ];
    if (i + 1 >= sizeof(sha1buf))   f='=';
    if (i + 2 >= sizeof(sha1buf)) g='=';
    hash_buffer[j++]=d;
    hash_buffer[j++]=e;
    hash_buffer[j++]=f;
    hash_buffer[j++]=g;
  }

  hash_buffer[j]=0;
  return (hash_buffer);
}
