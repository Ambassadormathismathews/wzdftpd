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

#ifndef __WZD_FILE__
#define __WZD_FILE__

/* WARNING !!! filename MUST be ABSOLUTE path !!! */


/*FILE * file_open(const char *filename, const char *mode, unsigned long wanted_right, wzd_context_t * context);*/
int file_open(const char *filename, int mode, unsigned long wanted_right, wzd_context_t * context);

/*void file_close(FILE *fp, wzd_context_t * context);*/
void file_close(int fd, wzd_context_t * context);

/* wrappers just to keep things in same memory zones */
int file_read(int fd,void *data,unsigned int length);
int file_write(int fd,const void *data,unsigned int length);

int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context);

int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context);
int file_remove(const char *filename, wzd_context_t * context);

int file_mkdir(const char *dirname, unsigned int mode, wzd_context_t * context);
int file_rmdir(const char *dirname, wzd_context_t * context);

int file_seek(int fd, unsigned long offset, int whence);

wzd_user_t * file_getowner(const char *filename, wzd_context_t * context);

/* symlink operations */
int symlink_create(const char *existing, const char *link);
int symlink_remove(const char *link);

/* returns 1 if file is currently locked, else 0 */
int file_lock(int fd, short lock_mode);
int file_unlock(int fd);
int file_islocked(int fd, short lock_mode);
int file_force_unlock(const char *file);

/* low-level func */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t *user);
int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, unsigned long perms, wzd_context_t * context);

#endif /* __WZD_FILE__ */

