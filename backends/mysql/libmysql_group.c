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
#include <mysql.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#include <wzd_backend.h>
#include <wzd_strlcat.h>

#include <wzd_debug.h>

#include "libmysql.h"

unsigned int group_get_ref(const char * name, unsigned int ref);


int FCN_FIND_GROUP(const char *name, wzd_group_t * group)
{
  char *query;
  int gid;

  if (!wzd_mysql_check_name(name)) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM groups WHERE groupname='%s'", name);

  if (mysql_query(&mysql, query) != 0) {
    free(query);
    _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  free(query);
  gid = -1;

  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    MYSQL_RES   *res;
    MYSQL_ROW    row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    if ( (int)mysql_num_rows(res) != 1 ) {
      /* 0 or more than 1 result */
      mysql_free_result(res);
      return -1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);

    gid = atoi(row[UCOL_UID]);

    mysql_free_result(res);

  }/* else  // no such user
    return -1;*/

  return gid;
}

#define APPEND_STRING_TO_QUERY(format, s, query, query_length, mod, modified) \
  do { \
    snprintf(mod, 512, format, s); \
    query = _append_safely_mod(query, &(query_length), mod, modified); \
    modified = 1; \
  } while (0);

int FCN_MOD_GROUP(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  char *query, *mod;
  MYSQL_RES   *res;
  int modified = 0;
  unsigned int query_length = 512;
  unsigned int ref = 0;
  unsigned int i;

  if (!group) { /* delete user permanently */
    query = malloc(2048);
    /* we don't care about the results of the queries */
    ref = group_get_ref(name, 0);
    if (ref) {
      _wzd_run_update_query(query, 2048, "DELETE FROM GroupIP WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM UGR WHERE gref=%d", ref);
    }
    _wzd_run_update_query(query, 2048, "DELETE FROM groups WHERE groupname='%s'", name);
    free(query);

    return 0;
  }

  /* search if group exists, if not, create it */
  ref = group_get_ref(name,0);

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
      APPEND_STRING_TO_QUERY("max_idle_time='%u' ", (unsigned int)group->max_idle_time, query, query_length, mod, modified);

    if (mod_type & _GROUP_GROUPPERMS)
      APPEND_STRING_TO_QUERY("groupperms='%lx' ", group->groupperms, query, query_length, mod, modified);
    if (mod_type & _GROUP_MAX_ULS)
      APPEND_STRING_TO_QUERY("max_ul_speed='%lu' ", group->max_ul_speed, query, query_length, mod, modified);
    if (mod_type & _GROUP_MAX_DLS)
      APPEND_STRING_TO_QUERY("max_dl_speed='%lu' ", group->max_dl_speed, query, query_length, mod, modified);
    if (mod_type & _GROUP_NUMLOGINS)
      APPEND_STRING_TO_QUERY("num_logins='%u' ", group->num_logins, query, query_length, mod, modified);

    /* XXX FIXME IP requires some work ... */

    if (mod_type & _GROUP_RATIO)
      APPEND_STRING_TO_QUERY("ratio='%u' ", group->ratio, query, query_length, mod, modified);


    if (modified)
    {
      snprintf(mod, 512, " WHERE groupname='%s'", name);
      query = _append_safely_mod(query, &query_length, mod, 0);

      if (mysql_query(&mysql, query) != 0) {
        _wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
        goto error_mod_group_free;
      }

      res = mysql_store_result(&mysql);


      if (res) mysql_free_result(res);
      free(mod); free(query);
      return 0;
    } /* if (modified) */

    free(mod); free(query);
    return -1;
  }

  /* create new group */

  /* Part 1, Group */
  query = malloc(2048);
  mod = NULL;

  /* XXX FIXME find a free gid !! */
  group->gid = 155;

  if (_wzd_run_update_query(query, 2048, "INSERT INTO groups (groupname,gid,defaultpath,tagline,groupperms,max_idle_time,num_logins,max_ul_speed,max_dl_speed,ratio) VALUES ('%s',%u,'%s','%s',0x%lx,%u,%u,%lu,%lu,%u)",
      group->groupname, group->gid,
      group->defaultpath,
      group->tagline,
      group->groupperms,
      (unsigned int)group->max_idle_time, group->max_ul_speed, group->max_dl_speed,
      group->num_logins, group->ratio
      ))
    goto error_group_add;

  ref = group_get_ref(group->groupname,0);
  if (!ref) goto error_group_add;

  /* Part 2, IP */
  for ( i=0; i<HARD_IP_PER_GROUP; i++ )
    if (group->ip_allowed[i][0] != '\0') {
      if (_wzd_run_update_query(query, 2048, "INSERT INTO GroupIP (ref,ip) VALUES (%u,'%s')",
            ref, group->ip_allowed[i]))
        goto error_group_add;
    }

  free(query);

  return 0;

error_group_add:
  /* we don't care about the results of the queries */
  ref = group_get_ref(group->groupname,0);
  if (ref) {
    _wzd_run_update_query(query, 2048, "DELETE FROM GroupIP WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM UGR WHERE gref=%d", ref);
  }
  _wzd_run_update_query(query, 2048, "DELETE FROM groups WHERE groupname='%s'", group->groupname);
  free(query);

  return -1;

error_mod_group_free:
  free(mod);
  free(query);

  return -1;

  return -1;
}


unsigned int group_get_ref(const char * name, unsigned int ref)
{
  char *query;
  MYSQL_RES   *res;
  MYSQL_ROW    row;
  unsigned int gid=0;
  unsigned long ul;
  char *ptr;

  if (!wzd_mysql_check_name(name)) return 0;

  if (ref) return ref;

  query = malloc(512);
  snprintf(query, 512, "SELECT groups.ref FROM groups WHERE groupname='%s'", name);

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
      gid = (unsigned int)ul;
    }

  }

  mysql_free_result(res);
  free(query);

  return gid;
}

