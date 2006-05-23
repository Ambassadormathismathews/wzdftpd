/* vi:ai:et:ts=8 sw=2
 */
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

#include <stdio.h>
#include <string.h>

#ifdef HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif

#include <security/pam_misc.h>

#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_debug.h>

#define	HARD_DEF_USER_MAX	64
#define	HARD_DEF_GROUP_MAX	64


/* module notes:
 *
 * If you use shadow file, you need to be root !
 */

#define PAM_BACKEND_VERSION     121

/* IMPORTANT needed to check version */
BACKEND_NAME(pam);
BACKEND_VERSION(PAM_BACKEND_VERSION);




static wzd_user_t *user_pool;
static int _user_count, _user_max;

static const char * pam_service_name = "ftp";

static int _pam_adduser(const char *name, int uid, const char *homedir);


static int su_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata)
{
  const struct pam_message *m = *msg;
  struct pam_response *r;

  if (!*resp) *resp = malloc(sizeof(struct pam_response));

  r = *resp;

  while ( num_msg-- )
  {
    switch(m->msg_style) {

      case PAM_PROMPT_ECHO_ON:
        fprintf(stdout, "%s", m->msg);
        r->resp = (char *)malloc(PAM_MAX_RESP_SIZE);
        fgets(r->resp, PAM_MAX_RESP_SIZE-1, stdin);
        m++; r++;
        break;

      case PAM_PROMPT_ECHO_OFF:
        r->resp = strdup(*(char**)appdata);
        m++; r++;
        break;

      case PAM_ERROR_MSG:
        fprintf(stderr, "%s\n", m->msg);
        m++; r++;
        break;

      case PAM_TEXT_INFO:
        fprintf(stdout, "%s\n", m->msg);
        m++; r++;
        break;

      default:
        break;
    }
  }
  return PAM_SUCCESS;
}





int FCN_INIT(const char *arg)
{
  int uid;

  /* preliminary checks */
  uid = getuid();
  if (uid != 0) {
    fprintf(stderr, "You need to be root to run PAM backend\n");
    return 1;
  }

  user_pool = malloc(HARD_DEF_USER_MAX * sizeof(wzd_user_t));
  memset(user_pool, 0, HARD_DEF_USER_MAX * sizeof(wzd_user_t));
  _user_count = 0;
  _user_max = HARD_DEF_USER_MAX;

  /* user nobody */
  strcpy(user_pool[0].username, "nobody");

  _user_count++;

  return 0;
}

int FCN_FINI()
{
  free(user_pool);
  return 0;
}

uid_t FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  pam_handle_t *pamh;
  struct pam_conv PAM_conversation = { su_conv, NULL };
  int ret;
  struct passwd * pwd;

  ret = pam_start( pam_service_name, login, &PAM_conversation, &pamh );

  if (ret == PAM_SUCCESS) {
    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS)
    {
      printf("pam error: %s\n",pam_strerror(pamh,ret));
      return (uid_t)-1;
    }
  }

  pwd = getpwnam(login);
  if (!pwd) return (uid_t)-1;

  _pam_adduser(login, pwd->pw_uid, pwd->pw_dir);

  pam_end(pamh, PAM_SUCCESS);

  return pwd->pw_uid;
}

/** \todo XXX FIXME is the mixed use of pam and getpwnam correct ? */
uid_t FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  pam_handle_t *pamh=NULL;
  int ret;
  struct pam_conv PAM_conversation = { su_conv, NULL };
  struct passwd * pwd;

  PAM_conversation.appdata_ptr = &pass;

  ret = pam_start( pam_service_name, login, &PAM_conversation, &pamh );

  if (ret == PAM_SUCCESS) {
    ret = pam_authenticate(pamh, 0); /* check pass */
    if (ret != PAM_SUCCESS)
    {
      printf("pam_authenticate error: %s\n",pam_strerror(pamh,ret));
      return (uid_t)-1;
    }
#if 0
    ret = pam_open_session(pamh, 0); /* open session */
    if (ret != PAM_SUCCESS)
    {
      printf("pam_open_session error: %s\n",pam_strerror(pamh,ret));
      return -1;
    }
#endif
  }

  pam_end(pamh, PAM_SUCCESS);

  pwd = getpwnam(login);
  if (!pwd) return (uid_t)-1;

  return pwd->pw_uid;
}

uid_t FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  int i;

  for (i=0; i<_user_count; i++)
  {
    if (strcmp(user_pool[i].username, name)==0)
      return user_pool[i].uid;
  }

  return (uid_t)-1;
}

gid_t FCN_FIND_GROUP(const char *name, wzd_group_t * group)
{
  return (gid_t)-1;
}

/* if user does not exist, add it */
int FCN_MOD_USER(const char *name, wzd_user_t * user, unsigned long mod_type)
{
  return 1;
}

int FCN_MOD_GROUP(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  return 1;
}

int  FCN_COMMIT_CHANGES(void)
{
  /* we return 0 (no error), we can't change anyting in the pam backend ?! */
  return 0;
}

wzd_user_t * FCN_GET_USER(uid_t uid)
{
  int i;
  wzd_user_t * user;

  for (i=0; i<_user_count; i++)
  {
    if (user_pool[i].uid == uid) {
      user = wzd_malloc(sizeof(wzd_user_t));
      if (!user) return NULL;
      memcpy(user, &user_pool[i], sizeof(wzd_user_t));
      return user;
    }
  }

  return NULL;
}

wzd_group_t * FCN_GET_GROUP(gid_t gid)
{
  return NULL;
}




static int _pam_adduser(const char *name, int uid, const char *homedir)
{
  struct group *gr = NULL;
  int isOp = 0;

  if (_user_count >= _user_max) return -1;

  strncpy(user_pool[_user_count].username, name, sizeof(user_pool[_user_count].username));
  user_pool[_user_count].uid = uid;
  ip_add_check(&user_pool[_user_count].ip_list,"*",1 /* is allowed */);
  strncpy(user_pool[_user_count].rootpath, homedir, sizeof(user_pool[_user_count].rootpath));
  user_pool[_user_count].userperms = 0xffffffff;
  /* root is always siteop .. */
  if (uid == 0) isOp = 1;
  /* .. as well as root/wheel group members */
  else if ( (gr = getgrgid(0)) ) {
    char *_name;
    int i = 0;

    while ( (_name = gr->gr_mem[i ++]) ) {
      if (strcmp (name,_name) == 0) {
        isOp = 1;
        break;
      }
    }
  } else /* an error occured */ {
    char *mem = malloc (4096);
    if (mem) {
      strerror_r (errno, mem, 4096);
      fprintf (stderr, "%s\n", mem);
      free (mem);
    } else { /* no mem here, there? */
      perror ("wzdftpd");
    }
  }
  if (isOp)
    strncpy(user_pool[_user_count].flags,"O",MAX_FLAGS_NUM);

  _user_count++;

  return 0;
}

int wzd_backend_init(wzd_backend_t * backend)
{
  if (!backend) return -1;

  backend->name = wzd_strdup("pam");
  backend->version = PAM_BACKEND_VERSION;

  backend->backend_init = FCN_INIT;
  backend->backend_exit = FCN_FINI;

  backend->backend_validate_login = FCN_VALIDATE_LOGIN;
  backend->backend_validate_pass = FCN_VALIDATE_PASS;

  backend->backend_get_user = FCN_GET_USER;
  backend->backend_get_group = FCN_GET_GROUP;

  backend->backend_find_user = FCN_FIND_USER;
  backend->backend_find_group = FCN_FIND_GROUP;

  backend->backend_mod_user = FCN_MOD_USER;
  backend->backend_mod_group = FCN_MOD_GROUP;

  backend->backend_chpass = NULL;
  backend->backend_commit_changes = FCN_COMMIT_CHANGES;

  return 0;
}

