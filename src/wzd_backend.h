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


/* other rights - should not be used directly ! */
#define	RIGHT_CWD	0x00010000
#define	RIGHT_RNFR	0x00020000

typedef unsigned long wzd_perm_t;

typedef struct limiter
{
  int maxspeed;
  struct timeval current_time;
  int bytes_transfered;
} wzd_bw_limiter;

typedef struct {
  char			username[256];
  char			rootpath[1024];
  char			tagline[256];
  unsigned int		uid;
  unsigned int          group_num;
  unsigned int          groups[256];
  struct timeval	max_idle_time;	/* not used yet */
  wzd_perm_t		perms;		/* not used yet */
  unsigned long		flags;		/* not used yet */
  unsigned long		max_ul_speed;
  unsigned long		max_dl_speed;	/* bytes / sec */
} wzd_user_t;

typedef struct {
  char                  groupname[256];
  wzd_perm_t            groupperms;
  unsigned long         max_ul_speed;
  unsigned long         max_dl_speed;
} wzd_group_t;


typedef struct {
  void * handle;
  int (*back_validate_login)(const char *, wzd_user_t *);
  int (*back_validate_pass) (const char *, const char *, wzd_user_t *);
  int (*back_find_user) (const char *, wzd_user_t *);
  int (*back_find_group) (int, wzd_group_t *);
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

int backend_find_user(const char *name, wzd_user_t * user);

int backend_find_group(int num, wzd_group_t * group);

#endif /* __WZD_BACKEND__ */
