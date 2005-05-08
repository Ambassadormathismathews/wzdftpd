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

#ifdef _MSC_VER
# include <windows.h>
#else
# include <unistd.h>
#endif

#include <libpq-fe.h>

#include <wzd_backend.h>
#include <wzd_strlcat.h>

#include <wzd_misc.h> /* win_normalize */

#include <wzd_debug.h>

#include "libpgsql.h"

int _group_update_ip(uid_t ref, wzd_group_t * group);

gid_t group_get_ref(const char * name, unsigned int ref);


gid_t FCN_FIND_GROUP(const char *name, wzd_group_t * group)
{
  char *query;
  gid_t gid;
  PGresult * res;

  if (!wzd_pgsql_check_name(name)) return (gid_t)-1;

  query = malloc(512);
  snprintf(query, 512, "SELECT * FROM groups WHERE groupname='%s'", name);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return (gid_t)-1;
  }

  free(query);
  gid = (gid_t)-1;

  /** no !! this returns the number of COLUMNS (here, 14) */
/*  if (mysql_field_count(&mysql) == 1)*/
  {
    int num_fields;

    if ( PQntuples(res) != 1 ) {
      /* 0 or more than 1 result */
      PQclear(res);
      return (gid_t)-1;
    }

    num_fields = PQnfields(res);

    gid = atoi(PQgetvalue(res,0,GCOL_GID));

    PQclear(res);

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

int wpgsql_mod_group(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  char *query, *mod;
  PGresult * res;
  int modified = 0;
  unsigned int query_length = 512;
  gid_t ref = 0;
  unsigned int i;

  if (!group) { /* delete user permanently */
    query = malloc(2048);
    /* we don't care about the results of the queries */
    ref = group_get_ref(name, 0);
    if (ref) {
      _wzd_run_update_query(query, 2048, "DELETE FROM groupip WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE gref=%d", ref);
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
      if (!wzd_pgsql_check_name(group->groupname)) goto error_mod_group_free;
      APPEND_STRING_TO_QUERY("groupname='%s' ", group->groupname, query, query_length, mod, modified);
    }

    if (mod_type & _GROUP_DEFAULTPATH) {
      DIRNORM(group->defaultpath,strlen(group->defaultpath),0);
      if (!wzd_pgsql_check_name(group->defaultpath)) goto error_mod_group_free;
      APPEND_STRING_TO_QUERY("defaultpath='%s' ", group->defaultpath, query, query_length, mod, modified);
    }

    if (mod_type & _GROUP_TAGLINE) {
      if (!wzd_pgsql_check_name(group->tagline)) goto error_mod_group_free;
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

    /* XXX FIXME IP requires some work ... */
    if (mod_type & _GROUP_IP)
      _group_update_ip(ref,group);

    if (mod_type & _GROUP_RATIO)
      APPEND_STRING_TO_QUERY("ratio='%u' ", group->ratio, query, query_length, mod, modified);


    if (modified)
    {
      snprintf(mod, 512, " WHERE groupname='%s'", name);
      query = _append_safely_mod(query, &query_length, mod, 0);

	  res = PQexec(pgconn, query);

      if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
        goto error_mod_group_free;
      }

      PQclear(res);

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

  if (_wzd_run_update_query(query, 2048, "INSERT INTO groups (groupname,gid,defaultpath,tagline,groupperms,max_idle_time,num_logins,max_ul_speed,max_dl_speed,ratio) VALUES ('%s',nextval('groups_gid_seq'),'%s','%s',CAST (X'%lx' AS integer),%u,%u,%lu,%lu,%u)",
      group->groupname,
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
      if (_wzd_run_update_query(query, 2048, "INSERT INTO groupip (ref,ip) VALUES (%u,'%s')",
            ref, group->ip_allowed[i]))
        goto error_group_add;
    }

  free(query);

  return 0;

error_group_add:
  /* we don't care about the results of the queries */
  ref = group_get_ref(group->groupname,0);
  if (ref) {
    _wzd_run_update_query(query, 2048, "DELETE FROM groupip WHERE ref=%d", ref);
    _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE gref=%d", ref);
  }
  _wzd_run_update_query(query, 2048, "DELETE FROM groups WHERE groupname='%s'", group->groupname);
  free(query);

  return -1;

error_mod_group_free:
  free(mod);
  free(query);

  return -1;
}

int _group_update_ip(uid_t ref, wzd_group_t * group)
{
  char *query;
  PGresult * res;
  unsigned int i;
  int index;
  char ip_list[HARD_IP_PER_GROUP][MAX_IP_LENGTH];
  int ret;

  if (!ref) return -1;

  query = malloc(512);
  snprintf(query, 512, "SELECT groupip.ip FROM groupip WHERE ref=%d", ref);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  for (i=0; i<HARD_IP_PER_GROUP; i++)
    ip_list[i][0] = '\0';

  i = 0;
  for (index=0; index<PQntuples(res); index++) {
    strncpy(ip_list[i],PQgetvalue(res,0,0),MAX_IP_LENGTH);
    i++;
    if (i >= HARD_IP_PER_GROUP) {
      /** too many ip in db ?! - ignoring others */
      break;
    }
  }

  /* compare the two sets of ip */
  for (i=0; i<HARD_IP_PER_GROUP; i++) {
    ret = 1;
    if (strcmp(group->ip_allowed[i],ip_list[i])!=0) {
      /* check for injections in ip */
      if (!wzd_pgsql_check_name(ip_list[i]) || !wzd_pgsql_check_name(group->ip_allowed[i])) {
        /* print error message ? */
        break;
      }
      if (group->ip_allowed[i][0]=='\0')
        ret = _wzd_run_delete_query(query,512,"DELETE FROM groupip WHERE groupip.ref=%d AND groupip.ip='%s'",ref,ip_list[i]);
      else {
        if (ip_list[i][0]=='\0')
          ret = _wzd_run_insert_query(query,512,"INSERT INTO groupip (ref,ip) VALUES (%d,'%s')",ref,group->ip_allowed[i]);
        else
          ret = _wzd_run_update_query(query,512,"UPDATE groupip SET ip='%' WHERE groupip.ref=%d AND groupip.ip='%s'",ip_list[i],ref,group->ip_allowed[i]);
      }
    }
    else
      ret = 0;
    if (ret) {
      /* print error message ? */
      break;
    }
  }

  PQclear(res);
  free(query);

  return 0;
}


gid_t group_get_ref(const char * name, unsigned int ref)
{
  char *query;
  gid_t gid=0;
  unsigned long ul;
  int index;
  char *ptr;
  PGresult * res;

  if (!wzd_pgsql_check_name(name)) return 0;

  if (ref) return ref;

  query = malloc(512);
  snprintf(query, 512, "SELECT groups.ref FROM groups WHERE groupname='%s'", name);

  res = PQexec(pgconn, query);

  if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
    free(query);
    _wzd_pgsql_error(__FILE__, __FUNCTION__, __LINE__);
    return 0;
  }

  for (index=0; index<PQntuples(res); index++) {
    ul = strtoul(PQgetvalue(res,0,0), &ptr, 0);
    if (ptr && *ptr == '\0') {
      gid = (gid_t)ul;
    }

  }

  PQclear(res);
  free(query);

  return gid;
}

