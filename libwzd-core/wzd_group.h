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

#ifndef __WZD_GROUP_H__
#define __WZD_GROUP_H__

/** @brief Group definition */
struct wzd_group_t {
  gid_t                  gid;
  u16_t                  backend_id;
  char                   groupname[HARD_GROUPNAME_LENGTH];
  char                   tagline[MAX_TAGLINE_LENGTH];
  wzd_perm_t             groupperms;
  char                   flags[MAX_FLAGS_NUM];
  u32_t                  max_idle_time;
  unsigned short         num_logins;     /**< number of simultaneous logins allowed */
  u32_t                  max_ul_speed;
  u32_t                  max_dl_speed;
  unsigned int           ratio;
  struct wzd_ip_list_t * ip_list;
  char                   defaultpath[WZD_MAX_PATH];
};

/** \brief Allocate a new empty structure for a group
 */
wzd_group_t * group_allocate(void);

/** \brief Initialize members of struct \a group
 */
void group_init_struct(wzd_group_t * group);

/** \brief Free memory used by a \a group structure
 */
void group_free(wzd_group_t * group);

/** \brief Create a new group, giving default parameters
 * \return The new group, or NULL. If \a err is provided, set it to
 * the error code.
 */
wzd_group_t * group_create(const char * groupname, wzd_context_t * context, wzd_config_t * config, int * err);

/** \brief Register a group to the main server
 * \return The gid of the registered group, or -1 on error
 */
gid_t group_register(wzd_group_t * group, u16_t backend_id);

/** \brief Update a registered group atomically. Datas are copied,
 * and old group is freed.
 * A pointer to the old group is still valid (change is done in-place)
 * If the gid had changed, the group will be moved
 * \return 0 if ok
 */
int group_update(gid_t gid, wzd_group_t * new_group);

/** \brief Unregister a group to the main server
 * The \a group struct must be freed using group_free()
 * \return The unregistered group structure, or NULL on error
 */
wzd_group_t * group_unregister(gid_t gid);

/** \brief Free memory used to register groups
 * \warning Also free ALL registered groups !
 */
void group_free_registry(void);

/** \brief Get registered group using the \a gid
 * \return The group, or NULL
 */
wzd_group_t * group_get_by_id(gid_t gid);

/** \brief Get registered group using the \a name
 * \return The group, or NULL
 */
wzd_group_t * group_get_by_name(const char * groupname);

/** \brief Get list or groups register for a specific backend
 * The returned list is terminated by -1, and must be freed with wzd_free()
 */
gid_t * group_get_list(u16_t backend_id);

/** \brief Find the first free gid, starting from \a start
 */
gid_t group_find_free_gid(gid_t start);

/** \brief Add an ip to the list of authorized/forbidden ips
 * \return 0 if ok
 */
int group_ip_add(wzd_group_t * group, const char * ip, int is_authorized);

#endif /* __WZD_GROUP_H__ */
