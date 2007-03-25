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

#ifndef __WZD_FILE__
#define __WZD_FILE__

/** \file wzd_file.h
 * \brief Files and directories functions
 *
 * Permissions are stored in a file present in each directory on the server.
 * This allows portable function, and features like symbolic links on
 * systems which does not have links (like windows).
 *
 * \addtogroup libwzd_core
 * @{
 */

/* WARNING !!! filename MUST be ABSOLUTE path !!! */

typedef enum {
  FILE_NOTSET,
  FILE_REG,
  FILE_DIR,
  FILE_LNK,
  FILE_VFS,
} wzd_file_kind_t;

typedef struct _wzd_acl_rule_t {
  char user[256];
  char perms[3]; /* rwx */
  struct _wzd_acl_rule_t * next_acl; /* linked list */
} wzd_acl_line_t;

/** \brief File: name, owner, permissions, etc. */
struct wzd_file_t {
  /** \todo replace with (char*) */
  char	filename[256];
  /** \todo replace with uid */
  char	owner[256];
  /** \todo replace with uid */
  char	group[256];
  unsigned long permissions;	/**< @brief classic linux format */
  wzd_acl_line_t *acl;
  wzd_file_kind_t kind;
  void * data;
  struct wzd_file_t	*next_file;
};


int file_open(const char *filename, int mode, unsigned long wanted_right, wzd_context_t * context);

void file_close(int fd, wzd_context_t * context);

/* wrappers just to keep things in same memory zones */
ssize_t file_read(fd_t fd,void *data,size_t length);
ssize_t file_write(fd_t fd,const void *data,size_t length);

int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context);

int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context);
int file_remove(const char *filename, wzd_context_t * context);

int file_mkdir(const char *dirname, unsigned int mode, wzd_context_t * context);
int file_rmdir(const char *dirname, wzd_context_t * context);

fs_off_t file_seek(fd_t fd, fs_off_t offset, int whence);

wzd_user_t * file_getowner(const char *filename, wzd_context_t * context);

/** \brief Get all permissions on file for specific context */
unsigned long file_getperms(struct wzd_file_t * file, wzd_context_t * context);

/* symlink operations */
int symlink_create(const char *existing, const char *link);
int symlink_remove(const char *link);

/* returns 1 if file is currently locked, else 0 */
int file_lock(fd_t fd, short lock_mode);
int file_unlock(fd_t fd);
int file_islocked(fd_t fd, short lock_mode);
int file_force_unlock(const char *file);

/* low-level func */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t *user);

int _checkFileForPerm(const char *dir, const char * wanted_file, unsigned long wanted_right, wzd_user_t * user);

int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, unsigned long perms, wzd_context_t * context);

/** \brief Read the permission file and build linked list of files.
 */
int readPermFile(const char *permfile, struct wzd_file_t **pTabFiles);

void file_insert_sorted(struct wzd_file_t *entry, struct wzd_file_t **tab);

/** \brief Copy a wzd_file_t object and all its data.
 */
struct wzd_file_t * file_deep_copy(struct wzd_file_t *file_cur);

/** \brief Free file list recursively
 * \note locks SET_MUTEX_FILE_T
 */
void free_file_recursive(struct wzd_file_t * file);

/** \brief Get file status */
struct wzd_file_t * file_stat(const char *filename, wzd_context_t * context);

/** @} */

#endif /* __WZD_FILE__ */

