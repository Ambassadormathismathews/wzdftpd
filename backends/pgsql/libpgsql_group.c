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
# include <winsock2.h>
# include <windows.h>
#else
# include <unistd.h>
#endif

#include <libpq-fe.h>

#include <libwzd-base/wzd_strlcat.h>

#include <libwzd-core/wzd_backend.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h> /* win_normalize */

#include <libwzd-core/wzd_debug.h>

#include "libpgsql.h"

static int _group_update_ip(uid_t ref, wzd_group_t * group);

static gid_t group_get_ref(const char * name, unsigned int ref);


#define APPEND_STRING_TO_QUERY(format, s, query, query_length, mod, modified) \
  do { \
    snprintf(mod, 512, format, s); \
    query = _append_safely_mod(query, &(query_length), mod, modified); \
    modified = 1; \
  } while (0);

int wpgsql_mod_group(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  char *query, *mod;
  int modified = 0, update_registry = 0;
  unsigned int query_length = 512;
  gid_t ref = 0;
  unsigned int i;
  wzd_group_t * registered_group;
  gid_t reg_gid;

  if (!group) { /* delete group permanently */
    query = malloc(2048);
    /* we don't care about the results of the queries */
    ref = group_get_ref(name, 0);
    if (ref) {
      _wzd_run_update_query(query, 2048, "DELETE FROM groupip WHERE ref=%d", ref);
      _wzd_run_update_query(query, 2048, "DELETE FROM ugr WHERE gref=%d", ref);
    }
    _wzd_run_update_query(query, 2048, "DELETE FROM groups WHERE groupname='%s'", name);
    free(query);

    /** \todo use group_get_id_by_name */
    registered_group = group_get_by_name(name);
    if (registered_group != NULL) {
      registered_group = group_unregister(registered_group->gid);
      group_free(registered_group);
    }

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

    if (mod_type & _GROUP_IP) {
      _group_update_ip(ref,group); /** \todo XXX test return ! */
      update_registry = 1;
    }

    if (mod_type & _GROUP_RATIO)
      APPEND_STRING_TO_QUERY("ratio='%u' ", group->ratio, query, query_length, mod, modified);


    if (modified)
    {
      snprintf(mod, 512, " WHERE groupname='%s'", name);
      query = _append_safely_mod(query, &query_length, mod, 0);

      if (_wzd_run_update_query(query,query_length,query) != 0)
        goto error_mod_group_free;

      free(mod); free(query);

      update_registry = 1;
    }

    if (update_registry) {
      registered_group = group_get_by_id(group->gid);
      if (registered_group != NULL) {
        out_log(LEVEL_FLOOD,"PGSQL updating registered group %s\n",group->groupname);

        if (group_update(registered_group->gid,group)) {
          out_log(LEVEL_HIGH,"ERROR PGSQL Could not update group %s %d\n",group->groupname,group->gid);
          return -1;
        }
      } else {
        if (group->gid != (gid_t)-1) {
          reg_gid = group_register(group,1 /* XXX backend id */);
          if (reg_gid != group->gid) {
            out_log(LEVEL_HIGH,"ERROR PGSQL Could not register group %s %d\n",group->groupname,group->gid);
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

  registered_group = group_get_by_name(name);
  if (registered_group) {
    out_log(LEVEL_INFO,"WARNING: group %s is not present in DB but already registered\n");
    return -1;
  }

  /* Part 1, Group */
  query = malloc(2048);
  mod = NULL;

  /* sequence will find a free uid */
  group->gid = INVALID_USER;

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

  /* get generated gid from DB */
  {
    PGresult * res;
    if ( (res = _wzd_run_select_query(query,2048,"SELECT groups.gid FROM groups WHERE ref='%d'",ref)) == NULL )
      goto error_group_add;
    if ( PQntuples(res) != 1 ) {
      PQclear(res);
      goto error_group_add;
    }
    if ( wzd_row_get_uint(&group->gid, res, 0 /* only 1 column */) ) {
      PQclear(res);
      goto error_group_add;
    }
    PQclear(res);
  }

  /** \todo check values and register group */

  reg_gid = group_register(group,1 /* XXX backend id */);
  if (reg_gid != group->gid) {
    out_log(LEVEL_HIGH,"ERROR PGSQL Could not register group %s %d\n",group->groupname,group->gid);
    /** \todo free group and return INVALID_USER */
    goto error_group_add;
  }

  free(query);

  /** \todo register group */

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

  /** \todo use group_get_id_by_name */
  registered_group = group_get_by_name(name);
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

/** Update ip for a specific group using the following:
 * get stored ip list For each ip of modified group, try to find it
 * for the stored group: if not present, add it. For each ip of the
 * stored group, try to find it in the modified group: if not present,
 * delete it.
 * \return O if ok
 */
static int _group_update_ip(gid_t ref, wzd_group_t * group)
{
  char query[512];
  PGresult * res;
  int i, i_stored;
  int found;
  int ret;
  const char *ip_stored;

  if (!ref) return -1;

  /* extract ip list for group */
  if ( (res = _wzd_run_select_query(query,512,"SELECT groupip.ip FROM groupip WHERE ref=%d",ref)) == NULL) return 0;

  /* find NEW ip */
  for (i=0; i<HARD_IP_PER_GROUP; i++) {
    if (strlen(group->ip_allowed[i]) <= 0) continue;
    found = 0;
    for (i_stored=0; i_stored<PQntuples(res); i_stored++) {
      ip_stored = PQgetvalue(res,i_stored,0);
      if (strcmp(group->ip_allowed[i],ip_stored)==0) {
        found = 1;
        break;
      }
    }
    if (found == 0) {
      ret = _wzd_run_insert_query(query,512,"INSERT INTO groupip (ref,ip) VALUES (%d,'%s')",ref,group->ip_allowed[i]);
      if (ret) {
        PQclear(res);
        return -1;
      }
    }
  }

  /* find DELETED ip */
  for (i_stored=0; i_stored<PQntuples(res); i_stored++) {
    ip_stored = PQgetvalue(res,i_stored,0);
    for (i=0; i<HARD_IP_PER_GROUP; i++) {
      found = 0;
      if (strcmp(group->ip_allowed[i],ip_stored)==0) {
        found = 1;
        break;
      }
    }
    if (found == 0) {
      ret = _wzd_run_delete_query(query,512,"DELETE FROM groupip WHERE groupip.ref=%d AND groupip.ip='%s'",ref,ip_stored);
      if (ret) {
        PQclear(res);
        return -1;
      }
    }
  }

  PQclear(res);
  return 0;
}


static gid_t group_get_ref(const char * name, unsigned int ref)
{
  char query[512];
  gid_t gid=0;
  unsigned long ul;
  int index;
  char *ptr;
  PGresult * res;

  /** \bug XXX FIXME 0 is a valid gid - should it be -1 ? */
  if (!wzd_pgsql_check_name(name)) return 0;

  if (ref) return ref;

  if ( (res = _wzd_run_select_query(query,512,"SELECT groups.ref FROM groups WHERE groupname='%s'",name)) == NULL) return 0;

  for (index=0; index<PQntuples(res); index++) {
    ul = strtoul(PQgetvalue(res,0,0), &ptr, 0);
    if (ptr && *ptr == '\0') {
      gid = (gid_t)ul;
    }

  }

  PQclear(res);

  return gid;
}

