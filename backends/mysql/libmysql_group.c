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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
# include <winsock2.h>
# include <windows.h>
#else
# include <unistd.h>
#endif

#include <mysql.h>

#include <libwzd-base/wzd_strlcat.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h> /* win_normalize */

#include <libwzd-core/wzd_debug.h>

#include "libmysql.h"

static int _group_update_ip(uid_t ref, wzd_group_t * group);

static unsigned int group_get_ref(gid_t gid, unsigned int ref);

static gid_t _mysql_get_next_gid();


#define APPEND_STRING_TO_QUERY(format, s, query, query_length, mod, modified) \
  do { \
    snprintf(mod, 512, format, s); \
    query = _append_safely_mod(query, &(query_length), mod, modified); \
    modified = 1; \
  } while (0);

int wmysql_mod_group(gid_t gid, wzd_group_t * group, unsigned long mod_type)
{
  char *query, *mod;
  MYSQL_RES   *res;
  int modified = 0, update_registry = 0;
  unsigned int query_length = 512;
  gid_t ref = 0;
  wzd_group_t * registered_group;
  gid_t reg_gid;
  struct wzd_ip_list_t * current_ip;

  if (!group) { /* delete user permanently */
    query = malloc(2048);
    /* we don't care about the results of the queries */
    ref = group_get_ref(gid, 0);
    if (ref) {
      _wzd_run_update_query(query, 2048, "DELETE FROM groupip WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE gref=%d", ref);
    }
    _wzd_run_update_query(query, 2048, "DELETE FROM groups WHERE gid='%d'", gid);
    free(query);

    /** \todo use group_get_id_by_name */
    registered_group = group_get_by_id(gid);
    if (registered_group != NULL) {
      registered_group = group_unregister(registered_group->gid);
      group_free(registered_group);
    }

    return 0;
  }

  /* search if group exists, if not, create it */
  ref = group_get_ref(gid,0);

  if (ref) { /* group exists, just modify fields */
    query = malloc(query_length);
    mod = malloc(512);
    snprintf(query, query_length, "UPDATE groups SET ");

    if (mod_type & _GROUP_GROUPNAME) {
      if (!wzd_mysql_check_name(group->groupname)) goto error_mod_group_free;
      APPEND_STRING_TO_QUERY("groupname='%s' ", group->groupname, query, query_length, mod, modified);
    }

    if (mod_type & _GROUP_DEFAULTPATH) {
      DIRNORM(group->defaultpath,strlen(group->defaultpath),0);
      if (!wzd_mysql_check_name(group->defaultpath)) goto error_mod_group_free;
      APPEND_STRING_TO_QUERY("defaultpath='%s' ", group->defaultpath, query, query_length, mod, modified);
    }

    if (mod_type & _GROUP_TAGLINE) {
      if (!wzd_mysql_check_name(group->tagline)) goto error_mod_group_free;
      APPEND_STRING_TO_QUERY("tagline='%s' ", group->tagline, query, query_length, mod, modified);
    }
    if (mod_type & _GROUP_GID)
      APPEND_STRING_TO_QUERY("gid='%u' ", group->gid, query, query_length, mod, modified);
    if (mod_type & _GROUP_IDLE)
      APPEND_STRING_TO_QUERY("max_idle_time='%u' ", group->max_idle_time, query, query_length, mod, modified);

    if (mod_type & _GROUP_GROUPPERMS)
      APPEND_STRING_TO_QUERY("groupperms='%lx' ", group->groupperms, query, query_length, mod, modified);
    if (mod_type & _GROUP_MAX_ULS)
      APPEND_STRING_TO_QUERY("max_ul_speed='%u' ", group->max_ul_speed, query, query_length, mod, modified);
    if (mod_type & _GROUP_MAX_DLS)
      APPEND_STRING_TO_QUERY("max_dl_speed='%u' ", group->max_dl_speed, query, query_length, mod, modified);
    if (mod_type & _GROUP_NUMLOGINS)
      APPEND_STRING_TO_QUERY("num_logins='%u' ", group->num_logins, query, query_length, mod, modified);

    /* IP requires some work */
    if (mod_type & _GROUP_IP) {
      _group_update_ip(ref,group); /** \todo FIXME use return ! */
      update_registry = 1;
    }

    if (mod_type & _GROUP_RATIO)
      APPEND_STRING_TO_QUERY("ratio='%u' ", group->ratio, query, query_length, mod, modified);


    if (modified)
    {
      snprintf(mod, 512, " WHERE gid='%d'", gid);
      query = _append_safely_mod(query, &query_length, mod, 0);

      if (mysql_query(&mysql, query) != 0) {
        _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
        goto error_mod_group_free;
      }

      res = mysql_store_result(&mysql);


      if (res) mysql_free_result(res);
      free(mod); free(query);

      update_registry = 1;
    }

    if (update_registry) {
      registered_group = group_get_by_id(group->gid);
      if (registered_group != NULL) {
        out_log(LEVEL_FLOOD,"MYSQL updating registered group %s\n",group->groupname);

        if (group_update(registered_group->gid,group)) {
          out_log(LEVEL_HIGH,"ERROR MYSQL Could not update group %s %d\n",group->groupname,group->gid);
          return -1;
        }
      } else {
        if (group->gid != (gid_t)-1) {
          reg_gid = group_register(group,1 /* XXX backend id */);
          if (reg_gid != group->gid) {
            out_log(LEVEL_HIGH,"ERROR MYSQL Could not register group %s %d\n",group->groupname,group->gid);
            return -1;
          }
        }
      }

      return 0;
    } /* if (update_registry) */

    free(mod); free(query);
    return -1;
  }

  /* create new group */

  /* Part 1, Group */
  mod = NULL;

  /* find a free gid */
  group->gid = _mysql_get_next_gid();
  if (group->gid == INVALID_GROUP) return -1;

  query = malloc(2048);

  if (_wzd_run_update_query(query, 2048, "INSERT INTO groups (groupname,gid,defaultpath,tagline,groupperms,max_idle_time,num_logins,max_ul_speed,max_dl_speed,ratio) VALUES ('%s',%u,'%s','%s',0x%lx,%u,%u,%lu,%lu,%u)",
      group->groupname, group->gid,
      group->defaultpath,
      group->tagline,
      group->groupperms,
      (unsigned int)group->max_idle_time, group->max_ul_speed, group->max_dl_speed,
      group->num_logins, group->ratio
      ))
    goto error_group_add;

  ref = group_get_ref(group->gid,0);
  if (!ref) goto error_group_add;

  /* Part 2, IP */
  for (current_ip=group->ip_list; current_ip != NULL; current_ip=current_ip->next_ip) {
    if (_wzd_run_update_query(query, 2048, "INSERT INTO groupip (ref,ip) VALUES (%u,'%s')",
          ref, current_ip->regexp))
        goto error_group_add;
  }

  /** \todo check values and register group */

  reg_gid = group_register(group,1 /* XXX backend id */);
  if (reg_gid != group->gid) {
    out_log(LEVEL_HIGH,"ERROR MYSQL Could not register group %s %d\n",group->groupname,group->gid);
    /** \todo free group and return INVALID_USER */
    goto error_group_add;
  }

  free(query);

  return 0;

error_group_add:
  /* we don't care about the results of the queries */
  ref = group_get_ref(group->gid,0);
  if (ref) {
    _wzd_run_update_query(query, 2048, "DELETE FROM groupip WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE gref=%d", ref);
  }
  _wzd_run_update_query(query, 2048, "DELETE FROM groups WHERE groupname='%s'", group->groupname);
  free(query);

  /** \todo use group_get_id_by_name */
  registered_group = group_get_by_id(gid);
  if (registered_group != NULL) {
    registered_group = group_unregister(registered_group->gid);
    group_free(registered_group);
  }

  return -1;

error_mod_group_free:
  free(mod);
  free(query);

  return -1;
}

static int _group_update_ip(uid_t ref, wzd_group_t * group)
{
  char query[512];
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  int g_stored;
  unsigned int i;
  int found;
  int ret;
  int gref;
  my_ulonglong num_rows;
  char ** stored_rows;
  unsigned long * stored_ref;
  struct wzd_ip_list_t * current_ip;

  if (!ref) return -1;

  /* extract ip list for user */
  snprintf(query,512,"SELECT groupip.ip,groupip.ref FROM groupip WHERE groupip.ref=%d",ref);

  if (mysql_query(&mysql, query) != 0) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (!(res = mysql_store_result(&mysql))) {
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  /* number of rows */
  num_rows = mysql_num_rows(res);

  stored_rows = malloc((int)num_rows * sizeof(*stored_rows));
  stored_ref = malloc((int)num_rows * sizeof(*stored_ref));
  for (i=0; i<num_rows; i++) {
    stored_rows[i] = malloc(MAX_IP_LENGTH+1);
    row = mysql_fetch_row(res);
    strncpy(stored_rows[i], row[0], MAX_IP_LENGTH);
    stored_ref[i] = strtoul(row[1], NULL, 0);
  }
  mysql_free_result(res);

  /* find NEW ip */
  for (current_ip=group->ip_list; current_ip != NULL; current_ip=current_ip->next_ip) {
    found = 0;
    for (g_stored = 0; g_stored < (int)num_rows; g_stored++) {
      if (strcmp(current_ip->regexp,stored_rows[g_stored])==0) {
        found = 1;
        break;
      }
    }
    if (found == 0) {
      ret = _wzd_run_insert_query(query,512,"INSERT INTO groupip (ref,ip) VALUES (%d,'%s')",ref,current_ip->regexp);
      if (ret) {
        _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
        return -1;
      }
    }
  }

  /* find DELETED ips */
  for (g_stored = 0; g_stored < (int)num_rows; g_stored++) {
    found = 0;
    for (current_ip=group->ip_list; current_ip != NULL; current_ip=current_ip->next_ip) {
      if (strcmp(current_ip->regexp,stored_rows[g_stored])==0) {
        found = 1;
        break;
      }
      if (found == 0) {
        gref = stored_ref[g_stored];
        ret = _wzd_run_delete_query(query,512,"DELETE FROM groupip WHERE groupip.ref=%d AND groupip.ip='%s'",ref,stored_rows[g_stored]);
        if (ret) {
          _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
          return -1;
        }
      }
    }
  }

  for (i=0; i<num_rows; i++) {
    free(stored_rows[i]);
  }
  free(stored_rows);
  free(stored_ref);
  return 0;
}


static unsigned int group_get_ref(gid_t gid, unsigned int ref)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  unsigned int ret_ref = 0;
  unsigned long ul;
  char *ptr;

  if (ref) return ref;

  query = malloc(512);
  snprintf(query, 512, "SELECT groups.ref FROM groups WHERE gid='%d'", gid);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  while ( (row = mysql_fetch_row(res)) ) {
    if (!row || row[0]==NULL) return 1;

    ul = strtoul(row[0], &ptr, 0);
    if (ptr && *ptr == '\0') {
      ret_ref = (unsigned int)ul;
    }

  }

  mysql_free_result(res);
  free(query);

  return ret_ref;
}

static gid_t _mysql_get_next_gid()
{
  gid_t gid=-1;
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  unsigned long ul;
  char *ptr;

  query = malloc(512);
  snprintf(query, 512, "SELECT LAST_INSERT_ID(gid+1) FROM groups");

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  mysql_free_result(res);


  snprintf(query, 512, "SELECT LAST_INSERT_ID()");

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (!(res = mysql_store_result(&mysql))) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if ( (row = mysql_fetch_row(res)) ) {
    if (row && row[0]!=NULL) {
      ul = strtoul(row[0], &ptr, 0);
      if (ptr && *ptr == '\0') {
        gid = (gid_t)ul;
      }
    }
  }

  mysql_free_result(res);

  free(query);

  return gid;
}

