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

#ifndef __WZD_VFS_H__
#define __WZD_VFS_H__

char *stripdir(char * dir, char *buf, int maxlen);
int checkpath(const char *wanted_path, char *path, wzd_context_t *context);
int checkabspath(const char *wanted_path, char *path, wzd_context_t *context);

/* free vfs list */
int vfs_free(wzd_vfs_t **vfs_list);

/* register a new vfs entry */
int vfs_add(wzd_vfs_t ** vfs_list, const char *vpath, const char *path);

/* if needed, replace the vfs in the path */
int vfs_replace(wzd_vfs_t *vfs_list, char *buffer, unsigned int maxlen, wzd_context_t *context);

/** register a new vfs entry, with a condition */
int vfs_add_restricted(wzd_vfs_t ** vfs_list, const char *vpath, const char *path, const char *target);

#endif /* __WZD_VFS_H__ */
