#ifndef __WZD_BACKEND__
#define __WZD_BACKEND__

#include <stdarg.h>
#include <sys/time.h>

#include "wzd_structs.h"

/* IMPORTANT:
 *
 * all validation functions have the following return code:
 *   0 = success
 *   !0 = failure
 *
 * the last parameter of all functions is a ptr to current user
 */


typedef struct {
  char name[1024];
  void * handle;
  int (*back_validate_login)(const char *, wzd_user_t *);
  int (*back_validate_pass) (const char *, const char *, wzd_user_t *);
  int (*back_find_user) (const char *, wzd_user_t *);
  int (*back_find_group) (int, wzd_group_t *);
  int (*back_chpass) (const char *, const char *);
  int (*back_mod_user) (const char *, wzd_user_t *);
  int (*back_mod_group) (int, wzd_group_t *);
  int (*back_commit_changes) (void);
} wzd_backend_t;

/* int FCN_INIT(void) */
#define	FCN_INIT		wzd_init
#define	STR_INIT		"wzd_init"

/* int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user) */
#define	FCN_VALIDATE_LOGIN	wzd_validate_login
#define	STR_VALIDATE_LOGIN	"wzd_validate_login"

/* int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user) */
#define	FCN_VALIDATE_PASS	wzd_validate_pass
#define	STR_VALIDATE_PASS	"wzd_validate_pass"

/* int FCN_FIND_USER(const char *name, wzd_user_t * user) */
#define	FCN_FIND_USER		wzd_find_user
#define	STR_FIND_USER	 	"wzd_find_user"

/* int FCN_FIND_GROUP(int num, wzd_group_t * group) */
#define	FCN_FIND_GROUP		wzd_find_group
#define	STR_FIND_GROUP	 	"wzd_find_group"

/* int FCN_CHPASS(const char *username, const char *new_pass) */
#define	FCN_CHPASS		wzd_chpass
#define	STR_CHPASS	 	"wzd_chpass"

/* int FCN_MOD_USER(const char *name, wzd_user_t * user) */
#define	FCN_MOD_USER		wzd_mod_user
#define	STR_MOD_USER	 	"wzd_mod_user"

/* int FCN_MOD_GROUP(int num, wzd_group_t * group) */
#define	FCN_MOD_GROUP		wzd_mod_group
#define	STR_MOD_GROUP	 	"wzd_mod_group"

/* int FCN_COMMIT_CHANGES(void) */
#define	FCN_COMMIT_CHANGES	wzd_commit_changes
#define	STR_COMMIT_CHANGES	"wzd_commit_changes"


int backend_validate(const char *backend);

int backend_init(const char *backend);

int backend_close(const char *backend);

int backend_reload(const char *backend);

int backend_find_user(const char *name, wzd_user_t * user);

int backend_find_group(int num, wzd_group_t * group);

int backend_validate_login(const char *name, wzd_user_t * user);

int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user);

int backend_chpass(const char *username, const char *new_pass);

int backend_commit_changes(const char *backend);

#endif /* __WZD_BACKEND__ */
