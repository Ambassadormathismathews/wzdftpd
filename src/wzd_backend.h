#ifndef __WZD_BACKEND__
#define __WZD_BACKEND__

#include <stdarg.h>
#include <sys/time.h>

/* IMPORTANT:
 *
 * all validation functions have the following return code:
 *   0 = success
 *   !0 = failure
 *
 * the last parameter of all functions is a ptr to current user
 */


typedef enum {
  USR_GUEST=0,
  USR_NORMAL,
  USR_ADMIN,
  USR_ROOT
} wzd_userlevel_t;

typedef struct {
  char			username[256];
  char			rootpath[1024];
  wzd_userlevel_t	userlevel;	/* not used yet */
  struct timeval	max_idle_time;	/* not used yet */
  unsigned long		perms;		/* not used yet */
  unsigned long		flags;		/* not used yet */
} wzd_user_t;


typedef struct {
  void * handle;
  int (*back_validate_login)(const char *, wzd_user_t *);
  int (*back_validate_pass) (const char *, const char *, wzd_user_t *);
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


int backend_validate(const char *backend);

int backend_init(const char *backend);

#endif /* __WZD_BACKEND__ */
