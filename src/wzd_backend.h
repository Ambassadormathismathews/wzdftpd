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


#define	RIGHT_NONE	0x00000000

#define	RIGHT_LIST	0x00000001
#define	RIGHT_RETR	0x00000002
#define	RIGHT_STOR	0x00000004

typedef unsigned long wzd_perm_t;

typedef struct {
  char			username[256];
  char			rootpath[1024];
  char			tagline[256];
  unsigned int		uid;
  struct timeval	max_idle_time;	/* not used yet */
  wzd_perm_t		perms;		/* not used yet */
  unsigned long		flags;		/* not used yet */
} wzd_user_t;


typedef struct {
  void * handle;
  int (*back_validate_login)(const char *, wzd_user_t *);
  int (*back_validate_pass) (const char *, const char *, wzd_user_t *);
  int (*back_validate_right) (wzd_user_t *, wzd_perm_t, void *);
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

/* int FCN_VALIDATE_RIGHT(wzd_user_t * user, wzd_perm_t wanted_perm, void * param) */
#define	FCN_VALIDATE_RIGHT	wzd_validate_right
#define	STR_VALIDATE_RIGHT	"wzd_validate_right"


int backend_validate(const char *backend);

int backend_init(const char *backend);

int backend_chek_perm(wzd_user_t * user, wzd_perm_t perm, void * param);

#endif /* __WZD_BACKEND__ */
