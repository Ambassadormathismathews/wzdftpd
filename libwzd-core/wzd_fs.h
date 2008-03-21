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

#ifndef __WZD_FS__
#define __WZD_FS__

/** \file wzd_fs.h
 * \brief Abstraction layer to functions accessing to the filesystem.
 */

typedef struct fs_dir_t fs_dir_t;
typedef struct fs_fileinfo_t fs_fileinfo_t;
typedef struct fs_filestat_t fs_filestat_t;

struct fs_filestat_t {
  u32_t mode;
  u64_t size;
  time_t mtime;
  time_t ctime;
  int nlink;
};

/** \brief Create a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to unicode.
 *
 * \return -1 on error, and set \a err to errno
 */
int fs_mkdir(const char * pathname, unsigned long mode, int * err);

/** \brief Open a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to unicode.
 */
int fs_dir_open(const char * pathname, fs_dir_t ** newdir);

/** \brief Close a directory
 */
int fs_dir_close(fs_dir_t * dir);

/** \brief Read a directory
 *
 * pathname should be UTF-8 encoded, or will be converted to unicode.
 */
int fs_dir_read(fs_dir_t * dir, fs_fileinfo_t ** fileinfo);

/** \brief Get informations on file
 *
 * pathname must be an absolute path
 * pathname should be UTF-8 encoded, or will be converted to unicode.
 */
int fs_file_stat(const char *pathname, fs_filestat_t * s);

/** \brief Get informations on file
 *
 * pathname must be an absolute path
 * pathname should be UTF-8 encoded, or will be converted to unicode.
 */
int fs_file_lstat(const char *pathname, fs_filestat_t * s);

/** \brief Get informations on file
 */
int fs_file_fstat(fd_t file, fs_filestat_t * s);


const char * fs_fileinfo_getname(fs_fileinfo_t * finfo);

#endif /* __WZD_FS__ */
