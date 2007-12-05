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
#include <ctype.h>

#include "wzd_structs.h"

#include "wzd_configfile.h"
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

  enum host_type_t type;
  unsigned int netmask;

  char raw[MAX_NUMERIC_IP_LEN];
};


static int string_is_hostname(const char * s);
static int string_is_ipv4(const char * s);
static int string_is_ipv6(const char * s);


/** \brief Allocate and initialize a new \a wzd_ip_t struct
 */
wzd_ip_t * ip_create(void)
{
  wzd_ip_t * ip;

  ip = wzd_malloc(sizeof(*ip));
  memset(ip,0,sizeof(*ip));

  return ip;
}

/** \brief Frees a \a wzd_ip_t struct
 */
void ip_free(wzd_ip_t * ip)
{
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
 * \returns 1 if allowed, 0 if denied, -1 on error or if not found
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
 * \returns 1 if allowed, 0 if denied, -1 on error or if not found
 */
int ip_list_check_ident(struct wzd_ip_list_t *list, const char *ip, const char * ident)
{
  struct wzd_ip_list_t * current_ip;
  char buffer[1024];
  const char * ptr;
  const char * ident_ref, * ip_ref;

  for (current_ip = list; current_ip != NULL; current_ip = current_ip->next_ip) {
    ip_ref = current_ip->regexp;

    if ( (ptr = strchr(current_ip->regexp,'@'))!=NULL ) {
      /* split regexp into ident_ref and ip_ref */
      ip_ref = ptr+1;
      strncpy(buffer,current_ip->regexp,(ptr-current_ip->regexp));
      buffer[ptr-current_ip->regexp] = '\0';
      ident_ref = buffer;
      /* Check ident and exit if different */
      if (ident == NULL) {
        /* if ident is NULL, we can still accept it if ident_ref is the wildcard * */
        if (strcmp(ident_ref,"*")!=0) continue;
      } else {
        if (my_str_compare(ident,ident_ref)!=1) continue;
      }
    }

    /* if the ident check is ok, check the ip */
    if (ip_compare(ip,ip_ref)==1) return current_ip->is_allowed;
  }

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

/** \brief Convert an ip address structure to a string
 *
 * \return 0 if ok
 */
int ip_numeric_to_string(const char *ip, net_family_t family, char *buf, size_t length)
{
#if defined(IPV6_SUPPORT)
  if (family == WZD_INET6) {
    inet_ntop(AF_INET6, ip, buf, length);
  } else
#endif
  {
    inet_ntop(AF_INET, ip, buf, length);
  }

  return 0;
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

/** \brief Test if remote peer is known as a BNC
 *
 * \return 1 if peer is a BNC
 */
int ip_is_bnc(const char * remote, wzd_config_t * config)
{
  wzd_string_t ** bnc_list;
  wzd_string_t * bnc;
  int errcode;
  int i;

  WZD_ASSERT(config != NULL);
  WZD_ASSERT(remote != NULL);

  if (!config || !remote) return 0;

  bnc_list = config_get_string_list (config->cfg_file, "GLOBAL", "bnc_list", &errcode);
  if (!bnc_list) return 0;

  for (i=0; bnc_list[i] != NULL; i++) {
    bnc = bnc_list[i];
    if (ip_compare(remote,str_tochar(bnc)) == 1) { /* found */
      str_deallocate_array(bnc_list);
      return 1;
    }
  }

  str_deallocate_array(bnc_list);
  return 0;
}

/** \brief Return our own ip
 *
 * \a buffer must be at least 16 bytes long
 */
unsigned char * getmyip(int sock, net_family_t family, unsigned char * buffer)
{
  struct sockaddr_in sa;
  unsigned int size;

#if defined(IPV6_SUPPORT)
  if (family == WZD_INET6) {
    struct sockaddr_in6 sa6;

    size = sizeof(struct sockaddr_in6);
    memset(buffer,0,16);
    if (getsockname(sock,(struct sockaddr *)&sa6,&size)!=-1)
    {
      memcpy(buffer,&sa6.sin6_addr,16);
    } else { /* failed, using localhost */
      out_log(LEVEL_CRITICAL,"getmyip: could not get my own ip !\n");
      return NULL;
    }

    return buffer;
  }
#endif /* IPV6_SUPPORT */
  size = sizeof(struct sockaddr_in);
  memset(buffer,0,16);
  if (getsockname(sock,(struct sockaddr *)&sa,&size)!=-1)
  {
    memcpy(buffer,&sa.sin_addr,4);
  } else { /* failed, using localhost */
    out_log(LEVEL_CRITICAL,"getmyip: could not get my own ip !\n");
    return NULL;
  }

  return buffer;
}

/** \brief Parse string and return host object or NULL
 */
wzd_ip_t * ip_parse_host(const char *host)
{
  wzd_ip_t * ip = NULL;
  char * ptr;
  char * slash;
  char * text = NULL, * start = NULL;
  enum host_type_t type = HT_UNKNOWN;
  unsigned int netmask = 0;

  if (host == NULL) return NULL;

  if (*host == '\0') return NULL;

  ptr = start = text = strdup(host);

  if ((slash=strchr(text,'/')) != NULL) {
    if (*(slash+1) == '\0') {
      out_log(LEVEL_NORMAL,"ERROR netmask can't be empty (input text: %s)\n",host);
      free(text); return NULL;
    }
    netmask = strtoul(slash+1,&ptr,10);
    if (*ptr != '\0') {
      out_log(LEVEL_NORMAL,"ERROR invalid netmask (input text: %s)\n",host);
      free(text); return NULL;
    }
    *slash = '\0';
    ptr = text;
  }

  if (*ptr == '[') { /* try IPv6 reference */
    while (*ptr && *ptr != ']') ptr++;
    if (*ptr == '\0') return NULL; /* malformed IPv6 reference */
    *ptr = '\0';
    start = text+1;

    if (!string_is_ipv6(ptr)) {
      out_log(LEVEL_NORMAL,"ERROR invalid IPv6 address (input text: %s)\n",host);
      free(text); return NULL;
    }

    type = HT_IPV6_REFERENCE;
  } else { /* hostname, or IPv4 address */
    if (string_is_ipv4(text)) {
      type = HT_IPV4_ADDRESS;
    }
    else if (string_is_hostname(text)) {
      type = HT_HOSTNAME;
      if (netmask != 0) {
        out_log(LEVEL_NORMAL,"ERROR netmask specified with a hostname ! (input text: %s)\n",host);
        free(text); return NULL;
      }
    }
    else {
      out_log(LEVEL_NORMAL,"ERROR invalid address (input text: %s)\n",host);
      free(text); return NULL;
    }
  }

  ip = ip_create();

  ip->type = type;
  wzd_strncpy(ip->raw,start,sizeof(ip->raw));
  ip->netmask = netmask;
  free(text);

  return ip;
}




/** \brief Check if string is a numeric IPv4 address
 * \return 1 if assertion is true
 *
 * \note actually, this is a very limited check
 */
static int string_is_ipv4(const char * s)
{
  while (*s != '\0') {
    if (*s != '.' && !isdigit(*s)) return 0;
    s++;
  }

  return 1;
}

/** \brief Check if string is a numeric IPv6 address
 * \return 1 if assertion is true
 *
 * \note actually, this is a very limited check
 */
static int string_is_ipv6(const char * s)
{
  while (*s != '\0') {
    if (*s != ':' && !isxdigit(*s)) return 0;
    s++;
  }

  return 1;
}

/** \brief Check if string is a host name
 * \return 1 if assertion is true
 *
 * Accepted host names are:
 * [:alnum:] ([alnum] | . | -)*
 */
static int string_is_hostname(const char * s)
{
  if (*s == '\0' || !isalnum(*s)) return 0;
  s++;

  while (*s != '\0') {
    if (!isalnum(*s) && *s != '-' && *s != '.') return 0;
    s++;
  }

  return 1;
}

