/* vi:ai:et:ts=8 sw=2
 */
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

#include <stdio.h>

#ifdef HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif

#include <security/pam_misc.h>

#include <pwd.h>

#include "wzd_backend.h"



/* module notes:
 *
 * If you use shadow file, you need to be root !
 */



static wzd_user_t *user_pool;
static int users_count;

static const char * pam_service_name = "ftp";

int su_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata)
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





int FCN_INIT(int *backend_storage, void *arg)
{
  *backend_storage = 1;

  return 0;
}

int FCN_FINI()
{
  return 0;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  pam_handle_t *pamh;
  struct pam_conv PAM_conversation = { su_conv, NULL };
  int ret;

  if (!user) return -1;

  ret = pam_start( pam_service_name, login, &PAM_conversation, &pamh );

  if (ret == PAM_SUCCESS) {
    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS)
    {
      printf("pam error: %s\n",pam_strerror(pamh,ret));
      return -1;
    }
  }

  strncpy(user->username,login,HARD_USERNAME_LENGTH);
  strncpy(user->ip_allowed[0],"*",2);

  pam_end(pamh, PAM_SUCCESS);

  return 0;
}

/** \todo XXX FIXME is the mixed use of pam and getpwnam correct ? */
int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  pam_handle_t *pamh=NULL;
  int ret;
  struct pam_conv PAM_conversation = { su_conv, NULL };
  struct passwd * pwd;

  if (!user) return -1;

  PAM_conversation.appdata_ptr = &pass;

  ret = pam_start( pam_service_name, login, &PAM_conversation, &pamh );

  if (ret == PAM_SUCCESS) {
    ret = pam_authenticate(pamh, 0); /* check pass */
    if (ret != PAM_SUCCESS)
    {
      printf("pam_authenticate error: %s\n",pam_strerror(pamh,ret));
      return -1;
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

  strncpy(user->username,login,HARD_USERNAME_LENGTH);
  strncpy(user->ip_allowed[0],"*",2);

  pwd = getpwnam(login);
  if (!pwd) return -1;

  strncpy(user->rootpath,pwd->pw_dir,WZD_MAX_PATH);

  /* root is always siteop */
  if (pwd->pw_uid == 0) strncpy(user->flags,"O",MAX_FLAGS_NUM);

  user->userperms = 0xffffffff;

  return 0;
}

int FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  return -1;
}

int FCN_FIND_GROUP(int num, wzd_group_t * group)
{
  return -1;
}

int FCN_CHPASS(const char *username, const char *new_pass)
{
  return 1;
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
