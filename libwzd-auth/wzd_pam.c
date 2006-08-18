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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <sys/types.h>

#ifdef HAVE_PAM

#ifdef HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif

#ifdef HAVE_OPENPAM_H
# include <security/openpam.h>
#elif defined (HAVE_PAM_MISC_H)
# include <security/pam_misc.h>
#endif

#include "wzd_auth.h"

typedef struct
{
  const char    *oldpass;
  const char    *newpass;
} MY_CONV_DATA;

static int chpass_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *data);
static int su_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata);

static const char * pam_service_name = "ftp";



/* return 1 if password matches */
int checkpass_pam(const char *user, const char *pass)
{
  pam_handle_t *pamh=NULL;
  int ret;
  struct pam_conv PAM_conversation = {su_conv, NULL };

  PAM_conversation.appdata_ptr = &pass;

  ret = pam_start( pam_service_name, user, &PAM_conversation, &pamh );

  if (ret == PAM_SUCCESS) {
    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS)
    {
#ifdef DEBUG
      fprintf(stderr, "pam_authenticate error: %s\n", pam_strerror(pamh,ret));
#endif
      return -1;
    }
    pam_end(pamh, PAM_SUCCESS);
  }

  return 1;
}


/* return 0 if ok */
int changepass_pam(const char *user, const char *pass, char *buffer, size_t len)
{
  pam_handle_t *pamh=NULL;
  int ret;
  struct pam_conv PAM_conversation = {chpass_conv, NULL };
  MY_CONV_DATA convdata;
  char * oldpass;
  char * newpass;
  char * ptr;

  if (!user || !pass || !buffer || len<=0) return -1;

  if (*pass == '\0') {
    /* just use pam authentication, do no change pass */
    strncpy(buffer,AUTH_SIG_PAM,len);
    return 0;
  }

  PAM_conversation.appdata_ptr = &convdata;

  oldpass = strdup(pass);
  ptr = strchr(oldpass,'|');
  if (!ptr) {
    free(oldpass);
    return -1;
  }
  *ptr++ = '\0';
  newpass = ptr;

  convdata.oldpass = oldpass;
  convdata.newpass = newpass;

  ret = pam_start( pam_service_name, user, &PAM_conversation, &pamh );
  if (ret != PAM_SUCCESS) return -2;

  ret = pam_authenticate(pamh, PAM_UPDATE_AUTHTOK);
  switch (ret) {
    case PAM_SUCCESS:
      break;
    case PAM_USER_UNKNOWN:
      return -3;
    default:
      return -4;
  }

  if (pam_chauthtok(pamh, PAM_SILENT) != PAM_SUCCESS) {
    return -5;
  }

  if (pam_end(pamh, PAM_SUCCESS) != PAM_SUCCESS)
    return -6;

  strncpy(buffer,AUTH_SIG_PAM,len);
  return 0;
}


static int chpass_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response  *myresp;
  *resp = myresp = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));

  if (strstr(msg[0]->msg, "Password:") ||
      strstr(msg[0]->msg, "current")) {
    myresp->resp = (char*)strdup(((MY_CONV_DATA*)data)->oldpass);
  } else if (strstr(msg[0]->msg, "New") ||
      strstr(msg[0]->msg, "new")) {
    myresp->resp = (char*)strdup(((MY_CONV_DATA*)data)->newpass);
    myresp[1].resp = (char*)strdup(((MY_CONV_DATA*)data)->newpass);
  }

  myresp->resp_retcode = 0;

  return PAM_SUCCESS;
}

static int su_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata)
{
  const struct pam_message *m = *msg;
  struct pam_response *r;

  if (!*resp) *resp = malloc(sizeof(struct pam_response));

  r = *resp;

  while ( num_msg-- )
  {
    switch (m->msg_style) {

      case PAM_PROMPT_ECHO_ON:
#ifdef DEBUG
        fprintf(stdout, "%s", m->msg);
        r->resp = (char*)malloc(PAM_MAX_RESP_SIZE);
        fgets(r->resp, PAM_MAX_RESP_SIZE-1, stdin);
#endif
        m++; r++;
        break;

      case PAM_PROMPT_ECHO_OFF:
        r->resp = strdup(*(char**)appdata);
        m++; r++;
        break;

      case PAM_ERROR_MSG:
#ifdef DEBUG
        fprintf(stderr, "%s\n", m->msg);
#endif
        m++; r++;
        break;

      case PAM_TEXT_INFO:
#ifdef DEBUG
        fprintf(stderr, "%s\n", m->msg);
#endif
        m++; r++;
        break;

      default:
        break;
    }
  }

  return PAM_SUCCESS;
}

#else /* HAVE_PAM */

/* return 1 if password matches */
int checkpass_pam(const char *user, const char *pass)
{
  return -1;
}

/* return 0 if ok */
int changepass_pam(const char *user, const char *pass, char *buffer, size_t len)
{
  return -1;
}

#endif /* HAVE_PAM */
