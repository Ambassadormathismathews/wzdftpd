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

#include "wzd_group.h"
#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_socket.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

#define MAX_NUMERIC_IP_LEN 64

struct _wzd_ip_t {
  net_family_t family;

  char raw[MAX_NUMERIC_IP_LEN];
};

/** \brief Allocate and initialize a new \a wzd_ip_t struct
 */
wzd_ip_t * ip_create(void)
{
  wzd_ip_t * ip;

  ip = wzd_malloc(sizeof(*ip));
  memset(ip,0,sizeof(*ip));

  return ip;
}

/** \brief Frees a \wzd_ip_t struct
 */
void ip_free(wzd_ip_t * ip)
{
  WZD_ASSERT_VOID(ip != NULL);
  wzd_free(ip);
}


/** \brief IP comparison
 *
 * ip1 must be a numeric ip
 * ip2 can be composed of wildcards
 *
 * \note
 * The * wildcard will stop at the first match:
 *   1*0 will match 15.0 whereas 1*0 will not match 10.0
 *
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
    aiHint.ai_family = AF_UNSPEC;
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
    wzd_strncpy(buffer1, aiList->ai_canonname, sizeof(buffer1));

    freeaddrinfo(aiList);

    if (my_str_compare(buffer1,pattern)==1)
      return 1;
  }
#endif /* IPV6_SUPPORT */

  return 0;
}


/** IP allowing */
int ip_add(struct wzd_ip_list_t **list, const char *newip)
{
  struct wzd_ip_list_t * new_ip_t, *insert_point;

  /* of course this should never happen :) */
  if (list == NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  new_ip_t = malloc(sizeof(struct wzd_ip_list_t));
  new_ip_t->regexp = wzd_strndup(newip,MAX_IP_LENGTH);
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

/** \brief Add a new ip to be checked when user logs in
 */
int ip_add_check(struct wzd_ip_list_t **list, const char *newip, int is_allowed)
{
  struct wzd_ip_list_t * new_ip_t, *insert_point;

  WZD_ASSERT( list != NULL );

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  new_ip_t = malloc(sizeof(*new_ip_t));
  new_ip_t->regexp = wzd_strndup(newip,MAX_IP_LENGTH);
  new_ip_t->is_allowed = (is_allowed) ? 1 : 0;
  new_ip_t->next_ip = NULL;

  /* tail insertion, be aware that order is important */
  insert_point = *list;
  if (insert_point == NULL) {
    *list = new_ip_t;
  } else {
    /** \note using a circular list would be faster here */
    while (insert_point->next_ip != NULL)
      insert_point = insert_point->next_ip;

    insert_point->next_ip = new_ip_t;
  }

  return 0;
}

/** \brief Check if ip is allowed by list.
 *
 * \returns: 1 if allowed, 0 if denied, -1 on error or if not found
 */
int ip_list_check(struct wzd_ip_list_t *list, const char *ip)
{
  struct wzd_ip_list_t * current_ip;
  char * ptr_test;

  current_ip = list;
  while (current_ip) {
    ptr_test = current_ip->regexp;
    if (*ptr_test == '\0') return -1; /* ip has length 0 ! */

    if (ip_compare(ip,ptr_test)==1) return current_ip->is_allowed;

    current_ip = current_ip->next_ip;
  } /* while current_ip */

  return -1;
}

/** \brief Check if ip is allowed by list, comparing \a ident if present
 *
 * \returns: 1 if allowed, 0 if denied, -1 on error or if not found
 */
int ip_list_check_ident(struct wzd_ip_list_t *list, const char *ip, const char * ident)
{
  struct wzd_ip_list_t * current_ip;
  char * ptr_test;
  const char * ptr_ip;
  char buffer[1024];

  if (ident != NULL)
    snprintf(buffer,sizeof(buffer)-1,"%s@%s",ident,ip);
  else
    strncpy(buffer,ip,sizeof(buffer)-1);

  current_ip = list;
  while (current_ip) {
    ptr_ip = buffer;
    /* if we do not have an ident to check, then any is accepted */
    if (ident != NULL && strchr(current_ip->regexp,'@')==NULL)
      ptr_ip = ip;
    ptr_test = current_ip->regexp;
    if (*ptr_test == '\0') return -1; /* ip has length 0 ! */

    if (ip_compare(ptr_ip,ptr_test)==1) return current_ip->is_allowed;

    current_ip = current_ip->next_ip;
  } /* while current_ip */

  return -1;
}

/** \brief Remove \a ip from list
 * \return 0 if ok, -1 if not found
 */
int ip_remove(struct wzd_ip_list_t ** list, const char * ip)
{
  struct wzd_ip_list_t * current_ip, * free_ip;

  current_ip = *list;
  if (current_ip == NULL) return -1;

  /* first ? */
  if (strcmp(current_ip->regexp, ip)==0) {
    *list = (*list)->next_ip;
    wzd_free(current_ip->regexp);
    wzd_free(current_ip);
    return 0;
  }

  while (current_ip->next_ip && current_ip->next_ip->regexp) {
    if (strcmp(current_ip->next_ip->regexp,ip)==0) {
      free_ip = current_ip->next_ip;
      current_ip->next_ip = free_ip->next_ip;
      wzd_free(free_ip->regexp);
      wzd_free(free_ip);
      return 0;
    }
    current_ip = current_ip->next_ip;
  }

  return -1;
}

int ip_inlist(struct wzd_ip_list_t *list, const char *ip)
{
  struct wzd_ip_list_t * current_ip;
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

void ip_list_free(struct wzd_ip_list_t *list)
{
  struct wzd_ip_list_t * current, *next;

  if (!list) return;
  current = list;

  while (current) {
    next = current->next_ip;

    free(current->regexp);
    free(current);

    current = next;
  }
}


int hostnametoip(const char *hostname, char **ip, size_t *length, net_family_t *family)
{
#if defined(HAVE_GETADDRINFO)
  {
    struct addrinfo * result = NULL;
    int error;
    const char * ptr;
    char ip_buf[128];
    struct sockaddr_in * addr4;
    struct sockaddr_in6 * addr6;

    error = getaddrinfo(hostname,NULL,NULL,&result);
    if (error) {
      out_log(LEVEL_NORMAL,"Error using getaddrinfo: %s\n",gai_strerror(error));
      *ip = NULL;
      return -1;
    }
    out_err(LEVEL_FLOOD,"Family: %d\n",result->ai_family);
    switch (result->ai_family) {
      case PF_INET:
        if (family) *family = WZD_INET4;
        addr4 = (struct sockaddr_in*)result->ai_addr;
        ptr = inet_ntop(AF_INET,(void*)&addr4->sin_addr,ip_buf,sizeof(ip_buf));
        break;
      case PF_INET6:
        if (family) *family = WZD_INET6;
        addr6 = (struct sockaddr_in6*)result->ai_addr;
        ptr = inet_ntop(AF_INET6,addr6->sin6_addr.s6_addr,ip_buf,sizeof(ip_buf));
        break;
      default:
        out_log(LEVEL_NORMAL,"getaddrinfo: unsupported family %d\n",result->ai_family);
        freeaddrinfo(result);
        return -1;
    }
    if (ptr == NULL) {
      out_log(LEVEL_NORMAL,"Error converting address with inet_ntop\n");
      freeaddrinfo(result);
      return -1;
    }
    out_err(LEVEL_FLOOD,"Address: %s\n",ip_buf);
    if (ip) *ip = wzd_strdup(ip_buf);
    if (length) *length = strlen(ip_buf);

    freeaddrinfo(result);
    return 0;
  }
#else
  {
    struct hostent * hent;
    const char * ptr;
    char ip_buf[128];

    /** \bug FIXME gethostbyname is _not_ thread-safe */
    hent = gethostbyname(hostname);
    if (hent == NULL) {
      /* TODO: fix this. it currently breaks win32 compiles */
#ifndef WIN32
      out_log(LEVEL_NORMAL,"Error using gethostbyname: %s\n",hstrerror(h_errno));
#endif
      return -1;
    }

    switch (hent->h_addrtype) {
      case AF_INET:
        if (family) *family = WZD_INET4;
        ptr = inet_ntop(AF_INET,hent->h_addr,ip_buf,sizeof(ip_buf));
        break;
      case AF_INET6:
        if (family) *family = WZD_INET6;
        ptr = inet_ntop(AF_INET6,hent->h_addr,ip_buf,sizeof(ip_buf));
        break;
      default:
        out_log(LEVEL_NORMAL,"gethostbyname: unsupported family %d\n",hent->h_addrtype);
        return -1;
    }

    if (ptr == NULL) {
      out_log(LEVEL_NORMAL,"Error converting address with inet_ntop\n");
      return -1;
    }
    out_err(LEVEL_FLOOD,"Address: %s\n",ip_buf);
    if (ip) *ip = wzd_strdup(ip_buf);
    if (length) *length = strlen(ip_buf);

    return 0;
  }
#endif
  return -1;
}

int iptohostname(const char *ip, net_family_t family, char **hostname, size_t *length)
{
#if defined(HAVE_GETADDRINFO) && defined(HAVE_GETNAMEINFO)
  {
    char tmphost[NI_MAXHOST];
    struct addrinfo * result = NULL;
    struct addrinfo hints;
    int error;
    int ai_family;

    if (hostname) *hostname = NULL;

    switch (family) {
      case WZD_INET_NONE:
        ai_family = AF_UNSPEC;
        break;
      case WZD_INET4:
        ai_family = AF_INET;
        break;
      case WZD_INET6:
        ai_family = AF_INET6;
        break;
      default:
        out_log(LEVEL_NORMAL,"iptohostname: unsupported family %d\n",family);
        return -1;
    }

    memset(&hints,0,sizeof(hints));
    hints.ai_family = ai_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_CANONNAME;

    error = getaddrinfo(ip, NULL, &hints, &result);
    if (error) {
      out_log(LEVEL_NORMAL,"Error using getaddrinfo: %s\n",gai_strerror(error));
      return -1;
    }

    error = getnameinfo (result->ai_addr, result->ai_addrlen, tmphost, sizeof(tmphost), NULL, 0, 0);
    if (error) {
      out_log(LEVEL_NORMAL,"Error using getnameinfo: %s\n",gai_strerror(error));
      freeaddrinfo(result);
      return -1;
    }

    out_err(LEVEL_FLOOD,"AddressToIP: %s\n",tmphost);
    if (hostname) *hostname = wzd_strdup(tmphost);
    if (length) *length = strlen(tmphost);

    freeaddrinfo(result);
    return 0;
  }
#else
  {
    int ai_family;
    struct hostent * hent;
    char ip_buffer[128];

    if (hostname) *hostname = NULL;

    switch (family) {
      case WZD_INET_NONE:
        /* guess family */
        if (strchr(ip,':')!=NULL) {
          family = WZD_INET6;
          ai_family = AF_INET6;
        } else {
          family = WZD_INET4;
          ai_family = AF_INET;
        }
        break;
      case WZD_INET4:
        ai_family = AF_INET;
        break;
      case WZD_INET6:
        ai_family = AF_INET6;
        break;
      default:
        out_log(LEVEL_NORMAL,"iptohostname: unsupported family %d\n",family);
        return -1;
    }

    memset(ip_buffer,0,sizeof(ip_buffer));
    /* convert ip (string) to ip (numeric form) */
    hent = gethostbyname(ip);
    if (hent == NULL) {
      /* TODO: fix this it does not compile on win32 */
#ifndef WIN32
      out_log(LEVEL_NORMAL,"Error using gethostbyname: %s\n",hstrerror(h_errno));
#endif
      return -1;
    }
    memcpy(ip_buffer,hent->h_addr,(family==WZD_INET6) ? 16 : 4);


    hent = gethostbyaddr(ip_buffer,(family==WZD_INET6)?16:4,ai_family);

    if (hent == NULL) {
      /* TODO: fix this it does not compile on win32 */
#ifndef WIN32
      out_log(LEVEL_NORMAL,"Error using gethostbyaddr: %s\n",hstrerror(h_errno));
#endif
      return -1;
    }

    out_err(LEVEL_FLOOD,"AddressToIP: %s\n",hent->h_name);
    if (hostname) *hostname = wzd_strdup(hent->h_name);
    if (length) *length = strlen(hent->h_name);

    return 0;
  }
#endif
  return -1;
}

