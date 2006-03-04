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

#ifndef __WZD_IP_H__
#define __WZD_IP_H__

typedef enum {
  WZD_INET_NONE = 0,
  WZD_INET4     = 2,  /* AF_INET */
  WZD_INET6     = 10, /* AF_INET6 */
} net_family_t;

typedef struct _wzd_ip_t wzd_ip_t;

/** \brief Allocate and initialize a new \a wzd_ip_t struct
 */
wzd_ip_t * ip_create(void);

/** \brief Frees a \a wzd_ip_t struct
 */
void ip_free(wzd_ip_t * ip);

/* IP comparison */
int ip_compare(const char * src, const char *dst);

/* IP allowing */
int ip_add(wzd_ip_list_t **list, const char *newip);

/** \brief Add a new ip to be checked when user logs in
 */
int ip_add_check(wzd_ip_list_t **list, const char *newip, int is_allowed);

/** \brief Check if ip is allowed by list.
 *
 * \returns: 1 if allowed, 0 if denied, -1 on error
 */
int ip_list_check(wzd_ip_list_t *list, const char *ip);

int ip_inlist(wzd_ip_list_t *list, const char *ip);
void ip_list_free(wzd_ip_list_t *list);

int user_ip_add(wzd_user_t * user, const char *newip);
int user_ip_inlist(wzd_user_t * user, const char *ip, const char *ident);

int group_ip_add(wzd_group_t * group, const char *newip);
int group_ip_inlist(wzd_group_t * group, const char *ip, const char *ident);

/** \brief Convert a host name to a numeric ip
 *
 * Caller must free \a ip with wzd_free()
 * \return 0 if ok
 */
int hostnametoip(const char *hostname, const char **ip, size_t *length, net_family_t *family);

/** \brief Convert a numeric ip to a hostname
 *
 * If \a family is \a WZD_INET_NONE, the family is guessed
 *
 * Caller must free \a hostname with wzd_free()
 * \return 0 if ok
 */
int iptohostname(const char *ip, net_family_t family, char **hostname, size_t *length);

#endif /* __WZD_IP_H__ */
