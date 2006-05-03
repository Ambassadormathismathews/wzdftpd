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

#ifndef __WZD_GROUP_H__
#define __WZD_GROUP_H__

/** @brief Group definition */
struct wzd_group_t {
  gid_t                 gid;
  u16_t                 backend_id;
  char                  groupname[HARD_GROUPNAME_LENGTH];
  char                  tagline[MAX_TAGLINE_LENGTH];
  wzd_perm_t            groupperms;
  u32_t                 max_idle_time;
  unsigned short        num_logins;     /**< number of simultaneous logins allowed */
  u32_t                 max_ul_speed;
  u32_t                 max_dl_speed;
  unsigned int          ratio;
  char                  ip_allowed[HARD_IP_PER_GROUP][MAX_IP_LENGTH];
  char                  defaultpath[WZD_MAX_PATH];
};

/** \brief Allocate a new empty structure for a group
 */
wzd_group_t * group_allocate(void);

/** \brief Free memory used by a \a group structure
 */
void group_free(wzd_group_t * group);

/** \brief Register a group to the main server
 * \return The gid of the registered group, or -1 on error
 */
gid_t group_register(wzd_group_t * group, u16_t backend_id);

/** \brief Unregister a group to the main server
 * The \a group struct must be freed using group_free()
 * \return The unregistered group structure, or NULL on error
 */
wzd_group_t * group_unregister(gid_t gid);

/** \brief Free memory used to register groups
 */
void group_free_registry(void);

#endif /* __WZD_GROUP_H__ */
