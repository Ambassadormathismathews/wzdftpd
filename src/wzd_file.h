#ifndef __WZD_FILE__
#define __WZD_FILE__

/* WARNING !!! filename MUST be ABSOLUTE path !!! */


FILE * file_open(const char *filename, const char *mode, unsigned long wanted_right, wzd_context_t * context);

void file_close(FILE *fp, wzd_context_t * context);

int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context);

int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context);

/* low-level func */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t *user);
int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, wzd_context_t * context);

#endif /* __WZD_FILE__ */

