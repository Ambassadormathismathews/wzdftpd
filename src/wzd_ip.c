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

/** \file wzd_ip.c
 * \brief IP address related routines
 */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#ifdef _MSC_VER
#include <winsock2.h>
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

#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_socket.h"

#endif /* WZD_USE_PCH */


/** \brief IP comparison
 *
 * ip1 must be a numeric ip
 * ip2 can be composed of wildcards
 * \return 1 if identical
 */
int ip_compare(const char * ip, const char * pattern)
{
  char buffer1[256], buffer2[256];
  const char *ptr;
  int has_wildcards1=0, has_wildcards2=0;
#ifndef IPV6_SUPPORT
  struct hostent * host;
#endif

  if (!ip || !pattern) return 0;

  /* simple case */
  if (strcmp(ip,pattern)==0) return 1;

  has_wildcards1 = ( strpbrk(ip,"*?") != NULL );
  has_wildcards2 = ( strpbrk(pattern,"*?") != NULL );

#ifndef IPV6_SUPPORT
  if (!has_wildcards1 && !has_wildcards2) { /* no wildcards */
    if (socket_getipbyname(ip, buffer1, sizeof(buffer1))) return 0;

    if (socket_getipbyname(pattern, buffer2, sizeof(buffer2))) return 0;

    if (memcmp(buffer1,buffer2,4)==0) /** and for IPv6 ?! */
      return 1;

    /* other aliases for host ?! */

    return 0;
  } /* no wildcards */

  if (has_wildcards1 && has_wildcards2) { /* wildcards in both strings ... I don't know what to do */
    return 0;
  }

  if (has_wildcards1 && !has_wildcards2) { /* swap ip to have only wildcards in ip2 */
    ptr = ip;
    pattern = ip;
    ip = ptr;
  }

  /* here, only ip2 contains wildcards */
  if (socket_getipbyname(ip, buffer1, sizeof(buffer1))) return 0;

  /* try direct match: 127.0.0.1 vs 127.0.0.* */
  if (my_str_compare(ip,pattern)==1)
    return 1;

  /* try reverse lookup */
  host = gethostbyaddr(buffer1,4,AF_INET); /** \todo will not work with IPv6 */
  if (!host) return 0;
  if (my_str_compare(host->h_name,pattern)==1)
    return 1;
#else /* IPV6_SUPPORT */
  {
    struct addrinfo aiHint;
    struct addrinfo * aiList = NULL, * aiListPattern = NULL;
    int retval;

    if (strncmp(ip,"::ffff:",strlen("::ffff:"))==0)
      ip += strlen("::ffff:");

    memset(&aiHint,0,sizeof(struct addrinfo));
    aiHint.ai_family = PF_UNSPEC;
    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
    memset(buffer1,0,sizeof(struct in6_addr));
    memset(buffer2,0,sizeof(struct in6_addr));

    if (!has_wildcards1 && !has_wildcards2) { /* no wildcards */
      retval = getaddrinfo(ip, NULL, &aiHint, &aiList);
      if (retval) return 0;
      memcpy(buffer1, aiList->ai_addr, aiList->ai_addrlen);

      freeaddrinfo(aiList);

      retval = getaddrinfo(pattern, NULL, &aiHint, &aiListPattern);
      if (retval) return 0;
      memcpy(buffer2, aiListPattern->ai_addr, aiListPattern->ai_addrlen);

      freeaddrinfo(aiListPattern);

      if (memcmp(buffer1,buffer2,sizeof(struct in6_addr))==0)
        return 1;

      /* other aliases for host ?! */

      return 0;
    } /* no wildcards */

    if (has_wildcards1 && has_wildcards2) { /* wildcards in both strings ... I don't know what to do */
      return 0;
    }

    if (has_wildcards1 && !has_wildcards2) { /* swap ip to have only wildcards in ip2 */
      ptr = ip;
      pattern = ip;
      ip = ptr;
    }

    /* here, only ip2 contains wildcards */
    retval = getaddrinfo(ip, NULL, &aiHint, &aiList);
    if (retval) return 0;
    memcpy(buffer1, aiList->ai_addr, aiList->ai_addrlen);

    freeaddrinfo(aiList);

    /* try direct match: 127.0.0.1 vs 127.0.0.* */
    if (my_str_compare(ip,pattern)==1)
      return 1;

    /* try reverse lookup */
    aiHint.ai_flags = AI_CANONNAME;
    retval = getaddrinfo(ip, NULL, &aiHint, &aiList);
    if (retval) return 0;
    memcpy(buffer1, aiList->ai_addr, aiList->ai_addrlen);

    freeaddrinfo(aiList);

    if (my_str_compare(aiList->ai_canonname,pattern)==1)
      return 1;
  }
#endif /* IPV6_SUPPORT */

  return 0;
}


/** IP allowing */
int ip_add(wzd_ip_t **list, const char *newip)
{
  wzd_ip_t * new_ip_t, *insert_point;

  /* of course this should never happen :) */
  if (list == NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  new_ip_t = malloc(sizeof(wzd_ip_t));
  new_ip_t->regexp = malloc(strlen(newip)+1);
  strncpy(new_ip_t->regexp,newip,strlen(newip)+1);
  new_ip_t->next_ip = NULL;

  /* tail insertion, be aware that order is important */
  insert_point = *list;
  if (insert_point == NULL) {
    *list = new_ip_t;
  } else {
    while (insert_point->next_ip != NULL)
      insert_point = insert_point->next_ip;

    insert_point->next_ip = new_ip_t;
  }

  return 0;
}

int ip_inlist(wzd_ip_t *list, const char *ip)
{
  wzd_ip_t * current_ip;
  const char * ptr_ip;
  char * ptr_test;

  current_ip = list;
  while (current_ip) {
    ptr_ip = ip;
    ptr_test = current_ip->regexp;
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */

    if (ip_compare(ptr_ip,ptr_test)==1) return 1;

    current_ip = current_ip->next_ip;
  } /* while current_ip */

  return 0;
}

void ip_free(wzd_ip_t *list)
{
  wzd_ip_t * current, *next;

  if (!list) return;
  current = list;

  while (current) {
    next = current->next_ip;

    free(current->regexp);
    free(current);

    current = next;
  }
}

int user_ip_add(wzd_user_t * user, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (user == NULL || newip==NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  /* tail insertion, be aware that order is important */
  for (i=0; i<HARD_IP_PER_USER; i++) {
    if (user->ip_allowed[i][0] == '\0') {
      strncpy(user->ip_allowed[i],newip,MAX_IP_LENGTH-1);
      return 0;
    }
  }
  return 1; /* full */
}

int user_ip_inlist(wzd_user_t * user, const char *ip, const char *ident)
{
  int i;
  const char * ptr_ip;
  char * ptr_test;
  const char * ptr;
  const char * ptr_ident;
  unsigned int ident_length=0;

  for (i=0; i<HARD_IP_PER_USER; i++) {
    if (user->ip_allowed[i][0] != '\0') {
      ptr_ip = ip;
      ptr_test = user->ip_allowed[i];
      if (*ptr_test == '\0') return 0; /* ip has length 0 ! */

      ptr = strchr(ptr_test,'@');
      if (ptr) { /* we have an ident to check */
        ptr_ident = ptr_test;
        ident_length = ptr - ptr_ident;
#ifdef WZD_DBG_IDENT
        out_log(LEVEL_CRITICAL,"user ip with ident: %s:%d\n",ptr_ident,ident_length);
#endif
        ptr_test = (char*)ptr+1;
        if ( !(*ptr_ident=='*' && ident_length==1) ) {
          if (!ident || ident[0] == '\0') {
            continue;
		  }
		  if (strncmp(ident,ptr_ident,ident_length) != 0) {
            /* ident does not match */
            continue;
		  }
        }
      }

      if (ip_compare(ptr_ip,ptr_test)==1) return 1;

    }
  } /* while ip */

  return 0;
}

int group_ip_add(wzd_group_t * group, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (group == NULL || newip==NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  /* tail insertion, be aware that order is important */
  for (i=0; i<HARD_IP_PER_GROUP; i++) {
    if (group->ip_allowed[i][0] == '\0') {
      strncpy(group->ip_allowed[i],newip,MAX_IP_LENGTH-1);
      return 0;
    }
  }
  return 1; /* full */
}

int group_ip_inlist(wzd_group_t * group, const char *ip, const char *ident)
{
  int i;
  const char * ptr_ip;
  char * ptr_test;
  const char * ptr;
  const char * ptr_ident;
  unsigned int ident_length=0;

  for (i=0; i<HARD_IP_PER_GROUP; i++) {
    if (group->ip_allowed[i][0] != '\0') {
      ptr_ip = ip;
      ptr_test = group->ip_allowed[i];
      if (*ptr_test == '\0') return 0; /* ip has length 0 ! */

      ptr = strchr(ptr_test,'@');
      if (ptr) { /* we have an ident to check */
        if (!ident) {
          continue;
        }
        ptr_ident = ptr_test;
        ident_length = ptr - ptr_ident;
        out_log(LEVEL_CRITICAL,"ident: %s:%d\n",ptr_ident,ident_length);
        ptr_test = (char*)ptr+1;
        if ( !(*ptr_ident=='*' && ident_length==1) &&
            strncmp(ident,ptr_ident,ident_length) != 0) {
          /* ident does not match */
          continue;
        }
      }

      if (ip_compare(ptr_ip,ptr_test)==1) return 1;

    }
  } /* while current_ip */

  return 0;
}
