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

#ifndef __WZD_USER_H__
#define __WZD_USER_H__

/** @brief User definition
 */
struct wzd_user_t {
  uid_t                 uid;
  char                  username[HARD_USERNAME_LENGTH];
  char                  userpass[MAX_PASS_LENGTH];
  char                  rootpath[WZD_MAX_PATH];
  char                  tagline[MAX_TAGLINE_LENGTH];
  unsigned int          group_num;
  unsigned int          groups[MAX_GROUPS_PER_USER];
  u32_t                 max_idle_time;
  wzd_perm_t            userperms;      /**< @brief default permissions */
  char                  flags[MAX_FLAGS_NUM];
  u32_t                 max_ul_speed;
  u32_t                 max_dl_speed;   /**< @brief bytes / sec */
  unsigned short        num_logins;     /**< @brief number of simultaneous logins allowed */
  char                  ip_allowed[HARD_IP_PER_USER][MAX_IP_LENGTH];
  wzd_stats_t           stats;
  u64_t                 credits;
  unsigned int          ratio;
  unsigned short        user_slots;     /**< @brief user slots for gadmins */
  unsigned short        leech_slots;    /**< @brief leech slots for gadmins */
  time_t                last_login;
};

#endif /* __WZD_USER_H__ */
