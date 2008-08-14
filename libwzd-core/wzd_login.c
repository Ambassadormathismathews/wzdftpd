/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

/** \file wzd_login.c
 * \brief Login sequence
 */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  /* struct in_addr (wzd_misc.h) */

#include <netdb.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "wzd_structs.h"

#include "wzd_ClientThread.h"
#include "wzd_configfile.h"
#include "wzd_group.h"
#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_login.h"
#include "wzd_messages.h"
#include "wzd_misc.h"
#include "wzd_protocol.h"
#include "wzd_socket.h"
#include "wzd_tls.h"
#include "wzd_user.h"

#include <libwzd-auth/wzd_krb5.h>

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

#define BUFFER_LEN	4096

static int check_tls_forced(wzd_context_t * context);

#if defined (HAVE_KRB5)
static int do_login_gssapi(wzd_context_t * context);
#endif

/*************** do_user *****************************/
/** \brief Check username
 *
 * The following checks are performed:
 *  - check if a backlend validates the username
 *  - check if the user is not marked as deleted
 *  - check if site is not closed
 *  - check if maximum number of logins for user or
 *    his groups has been reached
 *  - check if TLS is enforced but not enabled
 *
 * \return E_OK if ok
 * E_USER_REJECTED if user name is rejected by backend
 * E_USER_DELETED if user has been deleted
 * E_USER_NUMLOGINS if user has reached num_logins
 * E_USER_LOGINSPERIP if user has reached user num_logins
 * E_USER_CLOSED if site is closed and user is not a siteop
 * E_USER_TLSFORCED if user must use SSL/TLS
 * E_USER_TOOMANYUSERS if maximum number of users connected to the server is reached
 * E_GROUP_NUMLOGINS if user has reached group num_logins
 */
int do_user(const char *username, wzd_context_t * context)
{
  int ret;
  wzd_user_t * me;

  me = NULL;

  ret = backend_validate_login(username,me,&context->userid);
  if (ret) return E_USER_REJECTED;

  me = GetUserByID(context->userid);
  if (!me) return E_USER_IDONTEXIST;

  /* check if user have been deleted */
  if (me->flags && strchr(me->flags,FLAG_DELETED))
    return E_USER_DELETED;

  /* check if site is closed */
  if (mainConfig->site_closed &&
      !(me->flags && strchr(me->flags,FLAG_SITEOP)))
    return E_USER_CLOSED;


  /* allow users with FLAG_ALWAYS_ALLOW_LOGIN set and siteop's to bypass user limits */
  if (!(me->flags && (strchr(me->flags,FLAG_ALWAYS_ALLOW_LOGIN) || strchr(me->flags,FLAG_SITEOP)))) {

    /* check if there are too many users connected to the server */
    if (context_list && mainConfig->max_users) {
      if (list_size(context_list) > mainConfig->max_users)
        return E_USER_TOOMANYUSERS;
    }

    /* count logins from user (as well as how many of those are from context->hostip) */
    {
      ListElmt * elmnt;
      wzd_context_t * loop_context;
      int count_logins = 0;
      int count_fromip = 0;
      for (elmnt = list_head(context_list); elmnt != NULL; elmnt = list_next(elmnt)) {
        loop_context = list_data(elmnt);
        /* only count if the userid's match... but don't count the context trying to login! */
        if (loop_context && loop_context->magic == CONTEXT_MAGIC && context->userid == loop_context->userid && context->control_socket != loop_context->control_socket) {
          count_logins++;
          /* check if IP of connecting user has already connected to the same user account with the same IP */
          if (memcmp(context->hostip, loop_context->hostip, sizeof(context->hostip)) == 0)
            count_fromip++;
        }
      } /* for all contexts */

      /* >= is used as a comparison because the connecting user is not included in the counts */
      if (me->num_logins && count_logins >= me->num_logins) return E_USER_NUMLOGINS;
      if (me->logins_per_ip && count_fromip >= me->logins_per_ip) return E_USER_LOGINSPERIP;
    }

  } /* \!(FLAG_ALWAYS_ALLOW_LOGIN || FLAG_SITEOP) */


  /* foreach group of user, check num_logins */
  {
    ListElmt * elmnt;
    wzd_context_t * loop_context;
    unsigned int i,j,k;
    wzd_group_t * group;
    wzd_user_t * user;
    unsigned int * num_logins;

    num_logins = malloc(me->group_num * sizeof(unsigned int));
    memset(num_logins,0,me->group_num*sizeof(int));
    /* try to do it in one pass only */
    /* we build the same tab as me->groups, containing the counters */
    for (elmnt=list_head(context_list); elmnt!=NULL; elmnt=list_next(elmnt))
    {
      loop_context = list_data(elmnt);
      if (loop_context && loop_context->magic == CONTEXT_MAGIC) {
        user = GetUserByID(loop_context->userid);
        if (!user) {
          /* this can happen if a user disconnects while iterating list */
          continue;
        }
        for (j=0; j<user->group_num; j++)
          for (k=0; k<me->group_num; k++)
            if (user->groups[j] == me->groups[k])
              num_logins[ k ]++;
      }
    }
    /* checks num_logins for all groups */
    for (i=0; i<me->group_num; i++)
    {
      group = GetGroupByID( me->groups[i] );
      if (group && group->num_logins
          && (num_logins[i]>group->num_logins))
        /* > and not >= because current login attempt is counted ! */
      {
        free(num_logins);
        return E_GROUP_NUMLOGINS; /* user has reached group max num_logins */
      }
    }
    free(num_logins);
  }

  /* Check for TLS enforce here, before pass was sent to server */
  if (check_tls_forced(context))
    return E_USER_TLSFORCED;

  return E_OK;
}


/*************** do_pass *****************************/
/** \brief Check password (or authentication method)
 *
 * The following checks are performed:
 * - user exists and has not been deleted
 * - the backend validates the password or authentication method
 * - home directory exists, and user can enter directory
 *
 * \return E_OK if ok
 * E_USER_REJECTED if user does not exist
 * E_PASS_REJECTED if wrong pass
 * E_USER_DELETED if user has been deleted
 * E_LOGIN_NO_HOME if ok but homedir does not exist */
int do_pass(const char *username, const char * pass, wzd_context_t * context)
{
/*  char buffer[4096];*/
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);
  if (user == NULL) return E_USER_REJECTED;

  /* check if user have been deleted */
  if (user->flags && strchr(user->flags,FLAG_DELETED))
    return E_USER_DELETED;

  ret = backend_validate_pass(username,pass,NULL,&context->userid);
  if (ret) {
    /* pass was not accepted */
    return E_PASS_REJECTED;
  }

  /* initial dir */
  strcpy(context->currentpath,"/");
#ifdef WIN32
  if (strchr(user->flags,FLAG_FULLPATH) ) strcat(context->currentpath,user->rootpath);
#endif
  if (do_chdir(context->currentpath,context))
  {
    /* could not chdir to home !!!! */
    out_log(LEVEL_CRITICAL,"Could not chdir to home '%s' (root: '%s'), user '%s'\n",context->currentpath,user->rootpath,user->username);
    return E_USER_NO_HOME;
  }

  /* XXX - now we can wait (or not) the ACCT */

  return E_OK;
}


/*************** do_user_ip **************************/
/** \brief Check if user is connecting from an authorized ip
 *
 * IP addresses are checked in user list first, then in all of
 * its groups.
 *
 * Checks are stopped at the first match.
 */
int do_user_ip(const char *username, wzd_context_t * context)
{
  char ip[INET6_ADDRSTRLEN];
  const char *userip = (const char*)context->hostip;
  wzd_user_t * user;
  wzd_group_t *group;
  unsigned int i;
  int ret;

  user = GetUserByID(context->userid);

  if (!user) {
    int reject_nonexistant = 0;
    if (CFG_GET_OPTION(mainConfig,CFG_OPT_REJECT_UNKNOWN_USERS))
      reject_nonexistant = 1;
    if (!reject_nonexistant) return E_OK;
    return E_USER_IDONTEXIST;
  }

#if defined(IPV6_SUPPORT)
  if (context->family == WZD_INET6) {
    inet_ntop(AF_INET6,userip,ip,INET6_ADDRSTRLEN);
  } else
#endif
  {
    inet_ntop(AF_INET,userip,ip,INET_ADDRSTRLEN);
  }

  ret = ip_list_check_ident(user->ip_list, ip, context->ident);
  if (ret > 0) return E_OK;

  /* user ip not found, try groups */
  for (i=0; i<user->group_num; i++) {
    group = GetGroupByID(user->groups[i]);
    if (group && ip_list_check_ident(group->ip_list, ip, context->ident)==1)
      return E_OK;
  }

  return E_USER_NOIP;
}


/*************** do_login_loop ***********************/
static int do_login_loop(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * token;
  char username[HARD_USERNAME_LENGTH];
  int ret;
  int user_ok=0, pass_ok=0;
  int reject_nonexistant=0;
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
  int tls_ok=0;
#endif
  int command;

  if (CFG_GET_OPTION(mainConfig,CFG_OPT_REJECT_UNKNOWN_USERS))
    reject_nonexistant = 1;

  *username = '\0';

  context->state = STATE_LOGGING;

  while (1) {
    /* wait response : read at most BUFFER_LEN - 1 characters, so we are sure we can add a \0  */
    ret = (context->read_fct)(context->control_socket,buffer,BUFFER_LEN-1,0,HARD_XFER_TIMEOUT,context);

    if (ret == 0) {
      out_err(LEVEL_FLOOD,"Connection closed or timeout (socket %d)\n",context->control_socket);
      return 1;
    }
    if (ret==-1) {
      out_err(LEVEL_FLOOD,"Error reading client response (socket %d)\n",context->control_socket);
      return 1;
    }

    buffer[ret] = '\0'; /* no overflow here since we read BUFFER_LEN - 1 characters at most */
    chop(buffer);

    if (buffer[0]=='\0') continue;

    set_action(context,buffer);

#ifdef DEBUG
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,buffer);
#endif

    ptr = buffer;
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    switch (command) {
    case TOK_HELP:
        send_message_with_args(530,context,"Login with USER and PASS");
        break;
    case TOK_USER:
      if (user_ok) { /* USER command issued 2 times */
        ret = send_message_with_args(421,context,"USER command issued twice");
        return 1;
      }
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token) {
        ret = send_message_with_args(421,context,"Give me a user name!");
        return 1;
      }
      ret = do_user(token,context);
      switch (ret) {
      case E_OK:
        break;
      case E_USER_REJECTED: /* user was not accepted */
        if (!reject_nonexistant)
          break;
        ret = send_message_with_args(421,context,"User rejected");
        return 1;
      case E_USER_DELETED: /* user exists but was deleted */
        if (!reject_nonexistant)
          break;
        ret = send_message_with_args(421,context,"User deleted");
        return 1;
      case E_USER_NUMLOGINS: /* too many logins from the same account */
        ret = send_message_with_args(421,context,"Too many connections with this login account");
        return 1;
      case E_USER_LOGINSPERIP: /* too many logins from the same IP */
        ret = send_message_with_args(421,context,"Too many connections with this IP address");
        return 1;
      case E_USER_CLOSED: /* site closed */
        ret = send_message_with_args(421,context,"Site is closed, try again later");
        return 1;
      case E_USER_IDONTEXIST: /* i don't exist, probably a problem with backend */
        ret = send_message_with_args(501,context,"Mama says I don't exist! (problem with backend?)");
        return 1;
      case E_USER_TLSFORCED: /* user must use SSL/TLS */
        ret = send_message_with_args(421,context,"User MUST connect in TLS/SSL mode");
        return 1;
      case E_GROUP_NUMLOGINS: /* too many logins for group */
        ret = send_message_with_args(421,context,"Too many connections for your group");
        return 1;
      case E_USER_TOOMANYUSERS: /* too many users connected to the server */
        ret = send_message_with_args(421,context,"Too many connections to the server");
        return 1;
      default:
        ret = send_message_with_args(421,context,"User rejected (unknown error)");
        return 1;
      }
      /* validate ip for user */
      ret = do_user_ip(token,context);
      if (ret) { /* user was not accepted */
        ret = send_message_with_args(421,context,"IP not allowed");
        return 1;
      }
      strncpy(username,token,HARD_USERNAME_LENGTH-1);
      ret = send_message_with_args(331,context,username);
      user_ok = 1;
      break;
    case TOK_PASS:
      if (!user_ok || pass_ok) {
        ret = send_message_with_args(421,context,"Incorrect login sequence");
        return 1;
      }
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token) {
        ret = send_message_with_args(421,context,"Give me a password!");
        return 1;
      }
      ret = do_pass(username,token,context);
      switch (ret) {
      case E_OK:
        break;
      case E_USER_REJECTED: /* user was not accepted */
        ret = send_message_with_args(421,context,"User rejected");
        return 1;
      case E_PASS_REJECTED:
        ret = send_message_with_args(421,context,"Password rejected");
        return 1;
      case E_USER_DELETED: /* user exists but was deleted */
        ret = send_message_with_args(421,context,"User deleted");
        return 1;
      case E_USER_NO_HOME: /* pass is ok, could not chdir */
        ret = send_message_with_args(421,context,"Could not go to my home directory!");
        return 1;
      default:
        ret = send_message_with_args(421,context,"User rejected (unknown error)");
        return 1;
      }
      /* IF SSL, we should check HERE if the connection has been switched to tls or not */
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
      if (mainConfig->tls_type == TLS_STRICT_EXPLICIT && !tls_ok) {
        ret = send_message_with_args(421,context,"TLS session MUST be engaged");
        return 1;
      }
#endif
      return 0; /* user + pass ok */
      break;
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    case TOK_AUTH:
      token = strtok_r(NULL,"\r\n",&ptr);
      if (!token || token[0]==0) {
        ret = send_message_with_args(421,context,"Invalid token in AUTH command\n");
        return 1;
      }
#if defined (HAVE_KRB5)
      if (strcasecmp(token,"GSSAPI")==0) {
        ret = do_login_gssapi(context);
        if (ret != 0) {
          out_log(LEVEL_INFO, "GSSAPI authentication failed");
        }
        /* continue authentication to handle login/password */
        break;
      }
#endif
      if (CFG_GET_OPTION(mainConfig,CFG_OPT_DISABLE_TLS)) {
        ret = send_message_with_args(502,context,"TLS Disabled by config");
        break;
      }
      if (strcasecmp(token,"SSL")==0 || mainConfig->tls_type == TLS_IMPLICIT)
        context->tls_data_mode = TLS_PRIV; /* SSL must have encrypted data connection */
      else
        context->tls_data_mode = TLS_CLEAR;
      if (mainConfig->tls_type != TLS_IMPLICIT) {
        ret = send_message_with_args(234, context, token);
      }
      ret = tls_auth(token,context);
      if (ret) { /* couldn't switch to ssl */
        /* XXX should we send a message ? - with ssl aborted we can't be sure there won't be problems */
        ret = send_message_with_args(431,context,"Failed TLS negotiation");
        return 1;
      }
      tls_ok = 1;
      context->connection_flags |= CONNECTION_TLS;
      break;
    case TOK_PBSZ:
      token = strtok_r(NULL,"\r\n",&ptr);
      /** \todo PBSZ: convert token to int, set the PBSZ size */
      ret = send_message_with_args(200,context,"Command okay");
      break;
    case TOK_PROT:
      /** \todo PROT: if user is NOT in TLS mode, insult him */
      token = strtok_r(NULL,"\r\n",&ptr);
      if (strcasecmp("P",token)==0)
        context->tls_data_mode = TLS_PRIV;
      else if (strcasecmp("C",token)==0)
        context->tls_data_mode = TLS_CLEAR;
      else {
        ret = send_message_with_args(550,context,"PROT","must be C or P");
        break;
      }
      ret = send_message_with_args(200,context,"PROT command okay");
      break;
#else /* HAVE_OPENSSL */
    case TOK_AUTH:
    case TOK_PBSZ:
    case TOK_PROT:
      ret = send_message_with_args(530,context,"TLS commands disabled");
      break;
#endif
    case TOK_FEAT:
      {
        wzd_string_t * str = STR("feat");
        ret = do_print_message(str,NULL,context);
        str_deallocate(str);
      }
      break;
    case TOK_OPTS:
      {
        wzd_string_t *s1, *s2;
        token = strtok_r(NULL,"\r\n",&ptr);
        s1 = STR("opts");
        s2 = STR(token);
        ret = do_opts(s1,s2,context);
        str_deallocate(s1);
        str_deallocate(s2);
      }
      break;
    case TOK_IDNT:
      {
        char * ident, * address;
        char ip[INET6_ADDRSTRLEN];

        if (context->idnt_address != NULL) {
          out_log(LEVEL_INFO,"WARNING mutiple IDNT commands\n");
          ret = send_message_with_args(530,context,"Multiple IDNT commands");
          return 1;
        }

#if defined(IPV6_SUPPORT)
        if (context->family == WZD_INET6) {
          inet_ntop(AF_INET6,context->hostip,ip,INET6_ADDRSTRLEN);
        } else
#endif
        {
          inet_ntop(AF_INET,context->hostip,ip,INET_ADDRSTRLEN);
        }

        if (ip_is_bnc(ip, mainConfig)!=1) {
          out_log(LEVEL_INFO,"WARNING IDNT command received from a non-BNC (%s)\n",ip);
          ret = send_message_with_args(530,context,"Permission denied");
          return 1;
        }

        ident = strtok_r(NULL,"@",&ptr);
        address = strtok_r(NULL,":",&ptr);

        if (!ident || !address || (ptr && strlen(ptr)==0) ) {
          ret = send_message_with_args(501,context,"Syntax error");
          return 1;
        }

        /* XXX optional: check if hostname is valid */
        ret = iptohostname(address,WZD_INET_NONE,NULL,NULL);
        if (ret != 0) {
          out_log(LEVEL_NORMAL,"WARNING Invalid hostname passed to IDNT (received %s)\n",address);
          ret = send_message_with_args(501,context,"IDNT failed");
          return 1;
        }

        context->ident = strdup(ident);
        context->idnt_address = strdup(address);

        /* bnc doesn't expect any reply */
      }
      break;
    default:
      out_log(LEVEL_INFO,"Invalid login sequence: '%s'\n",buffer);
      ret = send_message_with_args(530,context,"Invalid login sequence");
      return 1;
    } /* switch (command) */

  } /* while (1) */

  return ret;
}

#if defined (HAVE_KRB5)
static int do_login_gssapi(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * token;
  char * base64data;
  int command;
  int ret;

  /** \todo initialize GSSAPI only once */
  ret = auth_gssapi_init(&context->gssapi_data);
  if (ret) {
    ret = send_message_with_args(550,context,"GSSAPI","Initialisation failed");
    return 1;
  }

  ret = send_message_with_args(334, context, "Waiting for ", "ADAT");

  while (1) {
    /* wait response */
    ret = (context->read_fct)(context->control_socket,buffer,BUFFER_LEN,0,HARD_XFER_TIMEOUT,context);

    if (ret == 0) {
      out_err(LEVEL_FLOOD,"Connection closed or timeout (socket %d)\n",context->control_socket);
      return 1;
    }
    if (ret==-1) {
      out_err(LEVEL_FLOOD,"Error reading client response (socket %d)\n",context->control_socket);
      return 1;
    }

    /* this replace the memset (bzero ?) some lines before */
    buffer[ret] = '\0';

    if (buffer[0]=='\0') continue;

    {
      size_t length = strlen(buffer);
      while (length > 0 && (buffer[length-1]=='\r' || buffer[length-1]=='\n'))
        buffer[length-- -1] = '\0';
      set_action(context,buffer);
    }

#ifdef DEBUG
out_err(LEVEL_FLOOD,"<thread %ld> <- '%s'\n",(unsigned long)context->pid_child,buffer);
#endif

    /* strtok_r: to be reentrant ! */
    ptr = buffer;
    token = strtok_r(buffer," \t\r\n",&ptr);
    command = identify_token(token);

    switch (command) {
    case TOK_HELP:
        send_message_with_args(530,context,"Login with USER and PASS");
        break;
    case TOK_ADAT:
        {
          char * ptr_out = NULL;
          size_t length_out;

          base64data = strtok_r(NULL," \t\r\n",&ptr);
#ifdef WZD_DBG_KRB5
          out_log(LEVEL_FLOOD,"DEBUG: received ADAT [%s]\n",base64data);
#endif
          ret = auth_gssapi_accept_sec_context(context->gssapi_data, base64data, strlen(base64data), &ptr_out, &length_out);
          switch (ret) {
            case 1:
              ret = send_message_with_args(334, context, "ADAT=", ptr_out);
              break;
            case 0:
              ret = send_message_with_args(235,context,"ADAT=", ptr_out);
              /* authenticated, now switch read and write functions */
              context->read_fct = auth_gssapi_read;
              context->write_fct = auth_gssapi_write;
              return 0;
              break;
            default:
              ret = send_message_with_args(535,context,"GSSAPI authentication failed");
              return 1;
          }
        }
        break;
    default:
      out_log(LEVEL_INFO,"Invalid login sequence: '%s'\n",buffer);
      ret = send_message_with_args(530,context,"Invalid login sequence");
      return 1;
    } /* switch (command) */

  } /* while (1) */

  return 1; /* error */
}

int do_mic(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  out_err(LEVEL_FLOOD,"DEBUG: received MIC [%s]\n",str_tochar(param));

  return 0;
}
#else /* HAVE_KRB5 */
int do_mic(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;

  ret = send_message_with_args(501,context,"Command not supported");

  return 0;
}
#endif /* HAVE_KRB5 */

/*************** login sequence **********************/
/** \brief Execute login loop
 *
 * \return 0 if login is ok
 */
int do_login(wzd_context_t * context)
{
  int ret;

  /* welcome msg */
  ret = send_message(220,context);

  /* mini server loop, login */
  ret = do_login_loop(context);

  {
    struct hostent * h = NULL;
    char inet_str[256];
    int af = (context->family == WZD_INET6) ? AF_INET6 : AF_INET;
    wzd_user_t * user = NULL;
    wzd_group_t * group = NULL;

    user = GetUserByID(context->userid);
    if (user && user->group_num > 0) {
      group = GetGroupByID(user->groups[0]);
    }
    inet_str[0] = '\0';
    inet_ntop(af, context->hostip, inet_str, sizeof(inet_str));
    h = gethostbyaddr((char*)&context->hostip, sizeof(context->hostip), af);
    log_message(ret ? "LOGIN_FAILED" : "LOGIN",
        "%s (%s) \"%s\" \"%s\" \"%s\"",
        h && h->h_name ? h->h_name : "No hostname",
        *inet_str ? inet_str : "No IP address",
        user && *(user->username) ? user->username : "No username",
        group && *(group->groupname) ? group->groupname : "No groupname",
        user && *(user->tagline) ? user->tagline : "No tagline"
        );
  }

  return ret;
}







/*************** check_tls_forced ********************/
/** check if tls connection must be enforced for user
 * return E_OK if user is in tls mode or is not forced to user
 *        E_USER_TLSFORCED if user should be in tls but is not
 */
static int check_tls_forced(wzd_context_t * context)
{
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  if (user->flags && strchr(user->flags,FLAG_TLS)) {
    if ( !(context->connection_flags & CONNECTION_TLS) ) {
      return E_USER_TLSFORCED;
    }
  }

  return E_OK;
}

