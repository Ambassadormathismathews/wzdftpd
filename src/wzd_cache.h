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

#ifndef __WZD_CACHE__
#define __WZD_CACHE__

struct wzd_cache_t;
typedef struct wzd_cache_t wzd_cache_t;

wzd_cache_t* wzd_cache_open(const char *file, int flags, unsigned int mode);
wzd_cache_t* wzd_cache_refresh(wzd_cache_t *c, const char *file, int flags, unsigned int mode);

unsigned int wzd_cache_getsize(wzd_cache_t *c);

int wzd_cache_read(wzd_cache_t * c, void *buf, unsigned int count);
int wzd_cache_write(wzd_cache_t * c, void *buf, unsigned int count);

char * wzd_cache_gets(wzd_cache_t * c, char *buf, unsigned int size);

void wzd_cache_close(wzd_cache_t * c);

/* purge all files in cache */
void wzd_cache_purge(void);

#endif /* __WZD_CACHE__ */

