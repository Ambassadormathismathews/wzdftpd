#ifndef __WZD_FILE__
#define __WZD_FILE__

/* WARNING !!! filename MUST be ABSOLUTE path !!! */


/*FILE * file_open(const char *filename, const char *mode, unsigned long wanted_right, wzd_context_t * context);*/
int file_open(const char *filename, int mode, unsigned long wanted_right, wzd_context_t * context);

/*void file_close(FILE *fp, wzd_context_t * context);*/
void file_close(int fd, wzd_context_t * context);

int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context);

int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context);
int file_remove(const char *filename, wzd_context_t * context);

int file_mkdir(const char *dirname, unsigned int mode, wzd_context_t * context);
int file_rmdir(const char *dirname, wzd_context_t * context);

/* returns 1 if file is currently locked, else 0 */
int file_lock(int fd, short lock_mode);
int file_unlock(int fd);
int file_islocked(int fd, short lock_mode);

/* low-level func */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t *user);
int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, unsigned long perms, wzd_context_t * context);

#endif /* __WZD_FILE__ */

