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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dlfcn.h>
#endif


#if defined(BSD) && !(defined(__MACH__) && defined(__APPLE__))
#define	DL_ARG	DL_LAZY
#else
#define	DL_ARG	RTLD_NOW
#endif

#include "wzd_structs.h"

#include "wzd_backend.h"
#include "wzd_cache.h"
#include "wzd_configfile.h"
#include "wzd_fs.h"
#include "wzd_group.h"
#include "wzd_misc.h"
#include "wzd_libmain.h"
#include "wzd_log.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#ifdef NEED_UNDERSCORE
#define	DL_PREFIX "_"
#else
#define	DL_PREFIX
#endif

#endif /* WZD_USE_PCH */


static int _trigger_user_max_dl(wzd_user_t * user);
static int _trigger_user_max_ul(wzd_user_t * user);


char *backend_get_version(wzd_backend_def_t *backend)
{
  char ** version_found;

  if (backend->handle)
    version_found = (char**)dlsym(backend->handle,DL_PREFIX "wzd_backend_version");
  else
    return NULL;

  return (*version_found);
}

char *backend_get_name(wzd_backend_def_t *backend)
{
  char ** backend_name;

  if (backend->handle)
    backend_name = (char**)dlsym(backend->handle,DL_PREFIX "wzd_backend_name");
  else
    return NULL;

  return (*backend_name);
}

static void backend_clear_struct(wzd_backend_def_t *backend)
{
  if (backend->param) {
    wzd_free(backend->param);
    backend->param = NULL;
  }
  wzd_free(backend->filename);
  backend->filename = NULL;
  backend->handle = NULL;

  if (backend->b) {
    wzd_free(backend->b->name);
  }

  wzd_free(backend->b);
  backend->b = NULL;
}

wzd_backend_def_t * backend_validate(const char *backend, const char *pred, const char *version)
{
  fs_filestat_t st;
  int ret;
  wzd_backend_def_t * def;

  ret = fs_file_lstat(backend,&st);
  if (ret) {
    out_log(LEVEL_HIGH,"Could not stat backend '%s'\n",backend);
    out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    return NULL;
  }

  def = backend_register(backend, NULL /* dynamic backend */);
  if (def == NULL) {
    out_err(LEVEL_HIGH,"ERROR while registering backend '%s'\n",backend);
    return NULL;
  }

  return def;
}

/**
 * \brief Initialize backend
 * \param backend The backend name
 */
int backend_init(wzd_backend_def_t * backend)
{
  wzd_backend_t * b;
  int ret;

  WZD_ASSERT(backend != NULL);
  if (backend == NULL) return -1;

  b = backend->b;

  WZD_ASSERT(backend != NULL);
  if (backend == NULL) return -1;

  if (b->backend_init) {
    wzd_string_t * str;
    /* LOGFILE */
    str = config_get_string(mainConfig->cfg_file, b->name, "param", NULL);
    if (str) {
      wzd_free(backend->param);
      backend->param = wzd_strdup(str_tochar(str));
      str_deallocate(str);
    }

    ret = (b->backend_init)(backend->param);
    if (ret) {
      out_log(LEVEL_HIGH,"ERROR could not backend %s, init function returned %d\n",backend->filename,ret);
      return 1;
    }
  }

  return 0;
}

/** \brief Register backend
 * Use \a filename for dynamic modules (shared libraries)
 * \a fcn for static modules.
 * When loading a static module, \a filename is used as a comment
 */
struct wzd_backend_def_t * backend_register(const char * filename, backend_init_function_t fcn)
{
  wzd_backend_def_t * def = NULL;
  wzd_backend_t * b;
  void * handle = NULL;
  int ret;

  if (filename == NULL && fcn == NULL) return NULL;

  if (fcn == NULL) {
    /* test dlopen */
    handle = dlopen(filename,DL_ARG);
    if (!handle) {
      out_log(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
      out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
      out_log(LEVEL_HIGH,"dlerror: %s\n",dlerror());
      return NULL;
    }

    fcn = (backend_init_function_t)dlsym(handle, DL_PREFIX "wzd_backend_init");
    if (fcn == NULL) {
      out_err(LEVEL_HIGH,"%s does not seem to be a valid backend - function %s was not found\n",filename,"wzd_backend_init");
      dlclose(handle);
      return NULL;
    }
  }

  b = wzd_malloc(sizeof(wzd_backend_t));
  memset(b,0,sizeof(wzd_backend_t));
  b->struct_version = STRUCT_BACKEND_VERSION;
  b->backend_id = 1; /** \todo auto-increment */

  ret = (*fcn)(b);

  if (ret != 0) {
    out_log(LEVEL_HIGH,"ERROR could not backend %s, init function returned %d\n",filename,ret);
    wzd_free(b);
    if (handle != NULL) dlclose(handle);
    return NULL;
  }

  def = wzd_malloc(sizeof(wzd_backend_def_t));
  memset(def,0,sizeof(wzd_backend_def_t));
  if (handle != NULL) {
    def->handle = handle;
    def->filename = wzd_strdup(filename);
  }
  def->b = b;

  return def;
}

int backend_close(const char *backend)
{
  int (*fini_fcn)(void) = NULL;
  int ret;

  if (!backend || !mainConfig->backends) return 1;

  if (backend_inuse(backend) > 0) {
    out_log(LEVEL_NORMAL,"Attempting to close backend %s while in use\n",backend);
    return 1;
  }

  /* step 1: check that backend == mainConfig->backend.name */
  if (strcmp(backend,mainConfig->backends->filename)!=0) return 1;

  /* step 2: call end function */
  if (mainConfig->backends->b) {
    fini_fcn = mainConfig->backends->b->backend_exit;
  }
  if (fini_fcn) {
    ret = (*fini_fcn)();
    if (ret) {
      out_log(LEVEL_CRITICAL,"Backend %s reported errors on exit (handle %lu)\n",
          backend,mainConfig->backends->handle);
/*      return 1;*/
    }
  }

  /* close backend */
  ret = 0;
  if (mainConfig->backends->handle)
  {
    char * tempname = strdup(backend);
    ret = dlclose(mainConfig->backends->handle);
    if (ret) {
#ifdef WIN32
      ret = GetLastError();
      out_log(LEVEL_INFO," Could not close backend %s (handle %lu)\n Error %d %s\n",
          tempname,mainConfig->backends->handle, ret,strerror(ret));
#else
      out_log(LEVEL_INFO,"Could not close backend %s (handle %lu)\n",
          tempname,mainConfig->backends->handle);
      out_log(LEVEL_INFO," Error '%s'\n",dlerror());
#endif
      backend_clear_struct(mainConfig->backends);

      free(tempname);
      return 1;
    }
    free(tempname);
  }

  backend_clear_struct(mainConfig->backends);

  /** \todo XXX remove backend from list */

  return 0;
}

int backend_reload(const char *backend)
{
  int ret;

#if 0
  ret = backend_close(backend);
  if (ret) return 1;

  ret = backend_init(backend,0 /* max users */,0 /* max groups */);
  if (ret) return 1;
#endif
  out_log(LEVEL_HIGH,"backend_reload: not yet implemented\n");

  return 1;
}

wzd_user_t * backend_get_user(uid_t userid)
{
  wzd_backend_t * b;

  if (userid == (uid_t)-1) return NULL;

  if ( (b = mainConfig->backends->b) && b->backend_get_user)
    return b->backend_get_user(userid);

  if (b == NULL)
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
  else
    out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define get_user method\n",b->name);
  return NULL;
}


int backend_find_user(const char *name, wzd_user_t * user, int * userid)
{
  int ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backends->b) && b->backend_find_user)
    ret = b->backend_find_user(name,user);
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define find_user method\n",b->name);
    return -1;
  }

  if (ret >= 0) {
    if (user) {
      wzd_user_t * _tmp_user;
      _tmp_user = GetUserByID(ret);
      if (!_tmp_user) return -1;
      memcpy(user,_tmp_user,sizeof(wzd_user_t));
    }
    if (userid) *userid = ret;
    return 0;
  }
  return ret;
}

/** wrappers to user list */
wzd_user_t * GetUserByID(uid_t id)
{
  wzd_user_t *user;
  wzd_backend_t * b;

  if (!mainConfig) return NULL;

  if (id == (uid_t)-1) return NULL;

  if ( (b = mainConfig->backends->b) && b->backend_get_user) {
    WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);
    user = b->backend_get_user(id);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  }
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define get_user method\n",b->name);
    return NULL;
  }

  return user;
}

wzd_user_t * GetUserByName(const char *name)
{
  uid_t uid;
  wzd_user_t * user=NULL;
  wzd_backend_t * b;

  if (!mainConfig || !name || strlen(name)<=0) return NULL;
out_err(LEVEL_CRITICAL,"GetUserByName %s\n",name);

  if ( (b = mainConfig->backends->b) && b->backend_find_user) {
    WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);
    uid = b->backend_find_user(name,user);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  }
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define find_user method\n",b->name);
    return NULL;
  }

  if (uid != (uid_t)-1) {
    return GetUserByID( uid );
  }
  return NULL;
}

uid_t GetUserIDByName(const char *name)
{
  wzd_user_t * user;

  if ( (user=GetUserByName(name)) )
    return user->uid;

  return (uid_t)-1;
}





wzd_group_t * backend_get_group(gid_t groupid)
{
  wzd_backend_t * b;
  if ( (b = mainConfig->backends->b) && b->backend_get_group)
    return b->backend_get_group(groupid);

  if (b == NULL)
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
  else
    out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define get_group method\n",b->name);
  return NULL;
}

int backend_find_group(const char *name, wzd_group_t * group, int * groupid)
{
  int ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backends->b) && b->backend_find_group)
    ret = b->backend_find_group(name,group);
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define find_group method\n",b->name);
    return -1;
  }

  if (ret >= 0) {
    if (group) {
      wzd_group_t * _tmp_group;
      _tmp_group = GetGroupByID(ret);
      if (!_tmp_group) return -1;
      memcpy(group,_tmp_group,sizeof(wzd_group_t));
    }
    if (groupid) *groupid = ret;
    return 0;
  }
  return ret;
}


/** wrappers to Group list */
wzd_group_t * GetGroupByID(gid_t id)
{
  wzd_group_t * group = NULL;
  wzd_backend_t * b;

  if (!mainConfig) return NULL;

  if ( (b = mainConfig->backends->b) && b->backend_get_group) {
    WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);
    group = b->backend_get_group(id);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  }
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define get_group method\n",b->name);
    return NULL;
  }

  return group;
}

wzd_group_t * GetGroupByName(const char *name)
{
  gid_t gid;
  wzd_group_t * group = NULL;
  wzd_backend_t * b;

  if (!mainConfig || !name || strlen(name)<=0) return NULL;

  if ( (b = mainConfig->backends->b) && b->backend_find_group) {
    WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);
    gid = b->backend_find_group(name,group);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  }
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define find_group method\n",b->name);
    return NULL;
  }

  if (gid != (gid_t)-1) {
    return GetGroupByID( gid );
  }

  return NULL;
}

gid_t GetGroupIDByName(const char *name)
{
  wzd_group_t * group;

  if ( (group=GetGroupByName(name)) )
    return group->gid;

  return (gid_t)-1;
}


int backend_validate_login(const char *name, wzd_user_t * user, uid_t * userid)
{
  uid_t ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backends->b) && b->backend_validate_login) {
    WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);
    ret = b->backend_validate_login(name,user);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  }
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define validate_login method\n",b->name);
    return -1;
  }

  if (ret != (uid_t)-1) {
    if (user) {
      wzd_user_t * _tmp_user;
      _tmp_user = GetUserByID(ret);
      if (!_tmp_user) return -1;
      memcpy(user,_tmp_user,sizeof(wzd_user_t));
    }
    *userid = ret;
    return 0;
  }
  return -1;
}

int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user, uid_t * userid)
{
  uid_t ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backends->b) && b->backend_validate_pass) {
    WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);
    ret = b->backend_validate_pass(name,pass,user);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  }
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define validate_pass method\n",b->name);
    return -1;
  }

  if (ret != (uid_t)-1) {
    if (user) {
      wzd_user_t * _tmp_user;
      _tmp_user = GetUserByID(ret);
      if (!_tmp_user) return -1;
      memcpy(user,_tmp_user,sizeof(wzd_user_t));
    }
    *userid = ret;
    return 0;
  }
  return -1;
}

int backend_commit_changes(const char *backend)
{
  wzd_backend_t * b;

  if ( (b = mainConfig->backends->b) && b->backend_commit_changes)
    return b->backend_commit_changes();

  if (b == NULL)
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
  else
    out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define commit_changes method\n",b->name);
  return -1;
}

/** \brief Check if a backend is currently used
 * \return The number of users connected currently using this backend
 */
int backend_inuse(const char *backend)
{
  int count;
  ListElmt * elmnt;
  wzd_context_t * context;
  u16_t backend_id = 0;
  wzd_user_t * user;
  /* unusually, if backend is not loaded it is not in use ... so no error here */
  if (mainConfig->backends==NULL || mainConfig->backends->handle==NULL)
    return -1;

  /* find backend id */
  if (strcmp(backend,mainConfig->backends->b->name)==0)
    backend_id = mainConfig->backends->b->backend_id;

  if (backend_id == 0) return -1;

  /* count user logged in */
  count = 0;
  for (elmnt=list_head(context_list); elmnt != NULL; elmnt = list_next(elmnt)) {
    context = list_data(elmnt);
    if (context->magic == CONTEXT_MAGIC) {
      user = GetUserByID(context->userid);
      if (user->backend_id == backend_id)
        count++;
    }
  }

  return count;
}

/* if user does not exist, add it */
int backend_mod_user(const char *backend, uid_t uid, wzd_user_t * user, unsigned long mod_type)
{
  int ret;
  wzd_backend_t * b;
  wzd_user_t * new_user;

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backends->b) && b->backend_mod_user)
    ret = b->backend_mod_user(uid,user,mod_type);
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define mod_user method\n",b->name);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
    return -1;
  }

  if (ret == 0) {
    if (mod_type & _USER_MAX_ULS) _trigger_user_max_ul(user);
    if (mod_type & _USER_MAX_DLS) _trigger_user_max_dl(user);
  }

/*  usercache_invalidate( predicate_name, (void *)name );*/

  if (!ret && user) { /* modification ok, reload user */
    if ( (b = mainConfig->backends->b) && b->backend_get_user)
      new_user = b->backend_get_user(user->uid);
    else {
      if (b == NULL)
        out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      else
        out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define get_user method\n",b->name);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return -1;
    }

    if (new_user != user) {
      if (new_user) {
        *user = *new_user;
        wzd_free(new_user);
      } else {
        wzd_free(user);
      }
    }
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  return ret;
}

/* if group does not exist, add it */
int backend_mod_group(const char *backend, gid_t gid, wzd_group_t * group, unsigned long mod_type)
{
  int ret;
  wzd_backend_t * b;
  wzd_group_t * new_group;

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backends->b) && b->backend_mod_group)
    ret = b->backend_mod_group(gid,group,mod_type);
  else {
    if (b == NULL)
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    else
      out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define mod_group method\n",b->name);
    WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
    return -1;
  }

/*  groupcache_invalidate( predicate_groupname, (void *)name );*/

  if (!ret && group) { /* modification ok, reload group */
    if ( (b = mainConfig->backends->b) && b->backend_get_group)
      new_group = b->backend_get_group(group->gid);
    else {
      if (b == NULL)
        out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      else
        out_log(LEVEL_CRITICAL,"FATAL: backend %s does not define get_user method\n",b->name);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return -1;
    }

    if (new_group != group) {
      if (new_group) {
        *group = *new_group;
        wzd_free(new_group);
      } else {
        wzd_free(group);
      }
    }
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  return ret;
}






static int _trigger_user_max_dl(wzd_user_t * user)
{
  ListElmt * el;
  wzd_context_t * context;

  if (!user) return 0;
  for (el = list_head(context_list); el != NULL; el = list_next(el))
  {
    context = list_data(el);
    if (context->magic == CONTEXT_MAGIC &&
        context->userid == user->uid)
    {
      context->current_dl_limiter.maxspeed = user->max_dl_speed;
    }
  }

  return 0;
}

static int _trigger_user_max_ul(wzd_user_t * user)
{
  ListElmt * el;
  wzd_context_t * context;

  if (!user) return 0;
  for (el = list_head(context_list); el != NULL; el = list_next(el))
  {
    context = list_data(el);
    if (context->magic == CONTEXT_MAGIC &&
        context->userid == user->uid)
    {
      context->current_ul_limiter.maxspeed = user->max_ul_speed;
    }
  }

  return 0;
}

