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

#ifndef __WZD_SECTION_H__
#define __WZD_SECTION_H__

char * section_getname(wzd_section_t * section);

int section_add(wzd_section_t **section_list, unsigned char *name, unsigned char *mask, const char *filter);

int section_free(wzd_section_t **section_list);

/* returns 1 if in section, else 0 */
int section_check(wzd_section_t * section, const char *path);

/* \return 1 if in path matches filter or section has no filter, else 0 */
int section_check_filter(wzd_section_t * section, const char *path);

/** \return a pointer to the first matching section or NULL */
wzd_section_t * section_find(wzd_section_t *section_list, const char *path);

#endif /* __WZD_SECTION_H__ */
