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

/** \file wzd_ip.c
 * \brief IP address related routines
 */

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>	/* struct in_addr (wzd_misc.h) */

#include <netdb.h>  /* gethostbyname */
#endif

#include <stdio.h>
#include <sys/stat.h>

#include "wzd_structs.h"

#include "wzd_ip.h"
#include "wzd_log.h"
#include "wzd_misc.h"


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
  char c;
  int has_wildcards1=0, has_wildcards2=0;
  struct hostent * host;
  unsigned int i,j;

  if (!ip || !pattern) return 0;

  /* simple case */
  if (strcmp(ip,pattern)==0) return 1;

  has_wildcards1 = ( strpbrk(ip,"*?") != NULL );
  has_wildcards2 = ( strpbrk(pattern,"*?") != NULL );

#ifndef IPV6_SUPPORT
  if (!has_wildcards1 && !has_wildcards2) { /* no wildcards */
    /** \todo FIXME replace gethostbyname with getaddrinfo, but it is NOT supported on win32 ... */
    host = gethostbyname(ip);
    if (!host) return 0;
    memcpy(buffer1, host->h_addr, sizeof(buffer1));

    host = gethostbyname(pattern);
    if (!host) return 0;
    memcpy(buffer2, host->h_addr, sizeof(buffer2));

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
  host = gethostbyname(ip);
  if (!host) return 0;
  memcpy(buffer1, host->h_addr, sizeof(buffer1));

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
  struct hostent *host;

  current_ip = list;
  while (current_ip) {
    ptr_ip = ip;
    ptr_test = current_ip->regexp;
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */

    if (ip_compare(ptr_ip,ptr_test)==1) return 1;
#if 0
    if (*ptr_test == '+') {
      char buffer[30];
      unsigned char * host_ip;

      ptr_test++;
      host = gethostbyname(ptr_test);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        current_ip = current_ip->next_ip;
        continue;
      }

      host_ip = (unsigned char*)(host->h_addr);
      snprintf(buffer,29,"%d.%d.%d.%d",
        host_ip[0],host_ip[1],host_ip[2],host_ip[3]);
#if DEBUG
out_err(LEVEL_FLOOD,"HOST IP %s\n",buffer);
#endif
      if (my_str_compare(buffer,ip)==1)
        return 1;
    } else
    if (*ptr_test == '-') {
      unsigned char host_ip[5];
      int i1, i2, i3, i4;

      ptr_test++;
      if (sscanf(ptr_ip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4) {
        out_log(LEVEL_HIGH,"INVALID IP (%s:%d) %s\n",__FILE__,__LINE__,
          ptr_ip);
        return 0;
      }
      host_ip[0] = i1;
      host_ip[1] = i2;
      host_ip[2] = i3;
      host_ip[3] = i4;

      host = gethostbyaddr(host_ip,4,AF_INET);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        current_ip = current_ip->next_ip;
        continue;
      }

      /* XXX do not forget the alias list ! */
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST NAME %s\n",ptr_test);
#endif
      if (my_str_compare(host->h_name,ptr_test)==1)
        return 1;
    } else
    { /* ip does not begin with + or - */
#if DEBUG
out_err(LEVEL_CRITICAL,"IP %s\n",ptr_test);
#endif
      if (my_str_compare(ptr_ip,ptr_test)==1) return 1;
    } /* ip does not begin with + or - */
#endif /* 0 */
  
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
  if (user == NULL || newip==NULL);

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
  struct hostent *host;
  const char * ptr;
  const char * ptr_ident;
  unsigned int ident_length=0;

  i = 0;
  while (user->ip_allowed[i][0] != '\0') {
    ptr_ip = ip;
    ptr_test = user->ip_allowed[i];
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */

    ptr = strchr(ptr_test,'@');
    if (ptr) { /* we have an ident to check */
      if (!ident || ident[0] == '\0') {
        i++;
        continue;
      }
      ptr_ident = ptr_test;
      ident_length = ptr - ptr_ident;
#ifdef WZD_DBG_IDENT
      out_log(LEVEL_CRITICAL,"user ip with ident: %s:%d\n",ptr_ident,ident_length);
#endif
      ptr_test = (char*)ptr+1;
      if (strncmp(ident,ptr_ident,ident_length) != 0) {
        /* ident does not match */
        i++;
        continue;
      }
    }

    if (ip_compare(ptr_ip,ptr_test)==1) return 1;
#if 0
    if (*ptr_test == '+') {
      char buffer[30];
      unsigned char * host_ip;
      
      ptr_test++;
      host = gethostbyname(ptr_test);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        i++;
        continue;
      }
      
      host_ip = (unsigned char*)(host->h_addr);
      snprintf(buffer,29,"%d.%d.%d.%d",
        host_ip[0],host_ip[1],host_ip[2],host_ip[3]);
#if DEBUG
out_err(LEVEL_FLOOD,"HOST IP %s\n",buffer);
#endif
      if (my_str_compare(buffer,ip)==1)
        return 1;
    } else
    if (*ptr_test == '-') {
      unsigned char host_ip[5];
      int i1, i2, i3, i4;

      ptr_test++;
      if (sscanf(ptr_ip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4) {
        out_log(LEVEL_HIGH,"INVALID IP (%s:%d) %s\n",__FILE__,__LINE__,
          ptr_ip);
        return 0;
      }
      host_ip[0] = i1;
      host_ip[1] = i2;
      host_ip[2] = i3;
      host_ip[3] = i4;

      host = gethostbyaddr(host_ip,4,AF_INET);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        i++;
        continue;
      }

      /* XXX do not forget the alias list ! */
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST NAME %s\n",ptr_test);
#endif
      if (my_str_compare(host->h_name,ptr_test)==1)
        return 1;
    } else
    { /* ip does not begin with + or - */
#if DEBUG
out_err(LEVEL_CRITICAL,"IP %s\n",ptr_test);
#endif
      if (my_str_compare(ptr_ip,ptr_test)==1) return 1;
    } /* ip does not begin with + or - */
#endif /* 0 */

    i++;
  } /* while current_ip */

  return 0;
}

int group_ip_add(wzd_group_t * group, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (group == NULL || newip==NULL);

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
  struct hostent *host;
  const char * ptr;
  const char * ptr_ident;
  unsigned int ident_length=0;

  i = 0;
  while (group->ip_allowed[i][0] != '\0') {
    ptr_ip = ip;
    ptr_test = group->ip_allowed[i];
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */
    
    ptr = strchr(ptr_test,'@');
    if (ptr) { /* we have an ident to check */
      if (!ident) {
        i++;
        continue;
      }
      ptr_ident = ptr_test;
      ident_length = ptr - ptr_ident;
      out_log(LEVEL_CRITICAL,"ident: %s:%d\n",ptr_ident,ident_length);
      ptr_test = (char*)ptr+1;
      if (strncmp(ident,ptr_ident,ident_length) != 0) {
        /* ident does not match */
        i++;
        continue;
      }
    }

    if (ip_compare(ptr_ip,ptr_test)==1) return 1;
#if 0
    if (*ptr_test == '+') {
      char buffer[30];
      unsigned char * host_ip;
      
      ptr_test++;
      host = gethostbyname(ptr_test);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        i++;
        continue;
      }
      
      host_ip = (unsigned char*)(host->h_addr);
      snprintf(buffer,29,"%d.%d.%d.%d",
        host_ip[0],host_ip[1],host_ip[2],host_ip[3]);
#if DEBUG
out_err(LEVEL_FLOOD,"HOST IP %s\n",buffer);
#endif
      if (my_str_compare(buffer,ip)==1)
        return 1;
    } else
    if (*ptr_test == '-') {
      unsigned char host_ip[5];
      int i1, i2, i3, i4;

      ptr_test++;
      if (sscanf(ptr_ip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4) {
        out_log(LEVEL_HIGH,"INVALID IP (%s:%d) %s\n",__FILE__,__LINE__,
          ptr_ip);
        return 0;
      }
      host_ip[0] = i1;
      host_ip[1] = i2;
      host_ip[2] = i3;
      host_ip[3] = i4;

      host = gethostbyaddr(host_ip,4,AF_INET);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        i++;
        continue;
      }

      /* XXX do not forget the alias list ! */
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST NAME %s\n",ptr_test);
#endif
      if (my_str_compare(host->h_name,ptr_test)==1)
        return 1;
    } else
    { /* ip does not begin with + or - */
#if DEBUG
out_err(LEVEL_CRITICAL,"IP %s\n",ptr_test);
#endif
      if (my_str_compare(ptr_ip,ptr_test)==1) return 1;
    } /* ip does not begin with + or - */
#endif /* 0 */

    i++;
  } /* while current_ip */

  return 0;
}
