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
#ifndef __WZD_DIR__
#define __WZD_DIR__

/* struct wzd_file_t is defined in wzd_file.h */

/** @brief Directory Stream Descriptor */
struct wzd_dir_t {
  /* FIXME should be unicode */
  char * dirname; /**< @brief the directory name */
  struct wzd_file_t * first_entry; /**< @brief pointer to file list */
  struct wzd_file_t * current_entry; /**< @brief first _unread_ entry */
};

/** @name dir
 *  Directory management functions
 */
/*@{*/
/** Open directory and returns corresponding struct, or NULL.
 * name should be an absolute path
 */
struct wzd_dir_t * dir_open(const char *name, wzd_context_t * context);

/** Close the directory stream associated with dir and free all memory used by
 * this struct. The Directory stream descriptor is not available after this call.
 */
void dir_close(struct wzd_dir_t * dir);

/** Return a pointer to a wzd_file_t structure representing the next directory
 * entry in the directory stream pointed to by dir.
 * Return NULL if an error occured or if the last file was reached.
 */
struct wzd_file_t * dir_read(struct wzd_dir_t * dir, wzd_context_t * context);
/*@}*/


/** \brief strip non-directory suffix from file name
 *
 * Return file without its trailing /component removed, if name contains
 * no /'s, returns "." (meaning the current directory).
 * Caller MUST free memory !
 */
char * path_getdirname(const char *file);

/** \brief strip directory and suffix from filename
 *
 * Return file with any leading directory components removed. If specified,
 * also remove a trailing suffix.
 * Caller MUST free memory !
 */
char * path_getbasename(const char *file, const char *suffix);

/** \brief get the trailing n parts of a filename
 *
 * Return file with any leading directory components removed, until
 * it has n components.
 * Caller MUST free memory !
 */
char * path_gettrailingname(const char *file, unsigned int n);

#endif /* __WZD_DIR__ */
