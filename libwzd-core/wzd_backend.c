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
#include "wzd_fs.h"
#include "wzd_misc.h"
#include "wzd_libmain.h"
#include "wzd_log.h"

#include "wzd_debug.h"

#ifdef NEED_UNDERSCORE
#define	DL_PREFIX "_"
#else
#define	DL_PREFIX
#endif

#endif /* WZD_USE_PCH */

static int _backend_check_function(void * handle, const char *name, const char *backend_name);

static int _trigger_user_max_dl(wzd_user_t * user);
static int _trigger_user_max_ul(wzd_user_t * user);


char *backend_get_version(wzd_backend_def_t *backend)
{
  char ** version_found;

  if (backend->handle)
    version_found = (char**)dlsym(backend->handle,DL_PREFIX "wzd_backend_version");
  else
    return NULL;

  return strdup(*version_found);
}

char *backend_get_name(wzd_backend_def_t *backend)
{
  char ** backend_name;

  if (backend->handle)
    backend_name = (char**)dlsym(backend->handle,DL_PREFIX "wzd_backend_name");
  else
    return NULL;

  return strdup(*backend_name);
}

static void backend_clear_struct(wzd_backend_def_t *backend)
{
  if (backend->param) {
    wzd_free(backend->param);
    backend->param = NULL;
  }
  wzd_free(backend->name);
  backend->name = NULL;
  backend->handle = NULL;
  backend->back_validate_login = NULL;
  backend->back_validate_pass = NULL;
  backend->back_get_user = NULL;
  backend->back_get_group = NULL;
  backend->back_find_user = NULL;
  backend->back_find_group = NULL;
  backend->back_chpass = NULL;
  backend->back_mod_user = NULL;
  backend->back_mod_group = NULL;
  backend->back_commit_changes = NULL;
  wzd_free(backend->b);
  backend->b = NULL;
}

int backend_validate(const char *backend, const char *pred, const char *version)
{
  fs_filestat_t st;
  int ret;
  void * handle;
  char filename[1024];
  char path[1024];
  int length;

  /* default: current path */
  strcpy(path,".");
  length=(int)strlen(path); /* FIXME wtf are these 4 lines for ? */
  /* add a / at the end if not present - XXX will conflict if last char is \ ? */
  if (path[length-1]!='/') {
    path[length++] = '/';
    path[length]='\0';
  }

  DIRNORM((char*)backend,strlen(backend),0);
  /* TODO if backend name already contains .so, do not add .o */
  /* if backend name contains /, do not add path */
  if (strchr(backend,'/')==NULL)
#ifdef WIN32
    length = snprintf(filename,1024,"%slibwzd%s.dll",path,backend);
#else
    length = snprintf(filename,1024,"%slibwzd%s.so",path,backend);
#endif
  else
    length = snprintf(filename,1024,"%s",backend);
  if (length<0)
  {
    out_err(LEVEL_HIGH,"Backend name too long (%s:%d)\n",__FILE__,__LINE__);
    return 1;
  }
  ret = fs_file_lstat(filename,&st);
  if (ret) {
    out_err(LEVEL_HIGH,"Could not stat backend '%s'\n",filename);
    out_err(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    return 1;
  }

  /* test dlopen */
  handle = dlopen(filename,DL_ARG);
  if (!handle) {
    out_err(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
    out_err(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_err(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  /* search wzd_backend_init. If found, use the new interface */
  {
    typedef int (*backend_init_function)(wzd_backend_t*);

    backend_init_function fcn;

    fcn = (backend_init_function)dlsym(handle, DL_PREFIX "wzd_backend_init");
    if (fcn) {
      dlclose(handle);
      return 0;
    }
  }

  /* check functions */
  ret = 1;
  ret = (_backend_check_function(handle, STR_VALIDATE_LOGIN, backend)) && ret;
  ret = (_backend_check_function(handle, STR_VALIDATE_PASS, backend)) && ret;
  ret = (_backend_check_function(handle, STR_GET_USER, backend)) && ret;
  ret = (_backend_check_function(handle, STR_GET_GROUP, backend)) && ret;
  ret = (_backend_check_function(handle, STR_FIND_USER, backend)) && ret;
  ret = (_backend_check_function(handle, STR_FIND_GROUP, backend)) && ret;
  ret = (_backend_check_function(handle, STR_MOD_USER, backend)) && ret;
  ret = (_backend_check_function(handle, STR_MOD_GROUP, backend)) && ret;
  ret = (_backend_check_function(handle, STR_COMMIT_CHANGES, backend)) && ret;
  if (!ret) {
    out_err(LEVEL_HIGH,"%s does not seem to be a valid backend - there are missing functions\n",backend);
    dlclose(handle);
    return 1;
  }

  /* if predicate and/or version, do specific tests on backend */
  if (pred) {
    if (strcmp(pred,">")==0) { /* need a minimum version */
      char ** version_found;
      if (!version) {
        out_err(LEVEL_CRITICAL,"We need a version number to do this test !\n");
        dlclose(handle);
        return 1;
      }
      version_found = (char**)dlsym(handle,DL_PREFIX "wzd_backend_version");
#ifndef _MSC_VER
      if ( (dlerror()) != NULL )
#else
      if ( !version_found )
#endif
      {
        out_err(LEVEL_CRITICAL,"Backend does not contain any \"wzd_backend_version\" information\n");
        dlclose(handle);
        return 1;
      }
      if (strcmp(*version_found,version)<=0) {
        out_err(LEVEL_CRITICAL,"Backend version is NOT > %s\n",version);
        dlclose(handle);
        return 1;
      }
    } /* if (strcmp(pred,">")>0) */
  } /* if (pred) */

  dlclose(handle);

  return 0;
}

int backend_init(const char *backend, unsigned int user_max, unsigned int group_max)
{
  void * handle;
  char filename[1024];
  char path[1024];
  int length;
  void *ptr;
  int (*init_fcn)(const char *);
  int ret;

  /* default: current path */
  strcpy(path,".");
  length=(int)strlen(path); /* FIXME wtf are these 4 lines for ? */
  /* add a / at the end if not present - XXX will conflict if last char is \ ? */
  if (path[length-1]!='/') {
    path[length++] = '/';
    path[length]='\0';
  }

  DIRNORM((char*)backend,strlen(backend),0);
  /* TODO if backend name already contains .so, do not add .o */
  /* if backend name contains /, do not add path */
  if (strchr(backend,'/')==NULL)
#ifdef __CYGWIN__
    length = snprintf(filename,1024,"%slibwzd%s.dll",path,backend);
#else
    length = snprintf(filename,1024,"%slibwzd%s.so",path,backend);
#endif
  else
    length = snprintf(filename,1024,"%s",backend);
  if (length<0)
  {
    out_err(LEVEL_HIGH,"Backend name too long (%s:%d)\n",__FILE__,__LINE__);
    return 1;
  }

  /* test dlopen */
  handle = dlopen(filename,DL_ARG);
  if (!handle) {
    out_log(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
    out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_log(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  mainConfig->backend.handle = handle;

  /* search wzd_backend_init. If found, use the new interface */
  {
    typedef int (*backend_init_function)(wzd_backend_t*);

    backend_init_function fcn;
    wzd_backend_t * b;

    fcn = (backend_init_function)dlsym(handle, DL_PREFIX "wzd_backend_init");
    if (fcn) {

      b = mainConfig->backend.b = wzd_malloc(sizeof(wzd_backend_t));
      memset(b,0,sizeof(wzd_backend_t));
      b->struct_version = STRUCT_BACKEND_VERSION;

      if (backend != mainConfig->backend.name) /* strings must not overlap */
      {
        wzd_free(mainConfig->backend.name);
        mainConfig->backend.name = wzd_strdup(backend);
      }

      ret = (*fcn)(b);

      /* compatibility layer (to be removed)
       *   copy all fields from backend->b to backend
       */
      {
        mainConfig->backend.name = b->name;
        mainConfig->backend.back_validate_login= b->backend_validate_login;
        mainConfig->backend.back_validate_pass= b->backend_validate_pass;
        mainConfig->backend.back_get_user= b->backend_get_user;
        mainConfig->backend.back_get_group= b->backend_get_group;
        mainConfig->backend.back_find_user= b->backend_find_user;
        mainConfig->backend.back_find_group= b->backend_find_group;
        mainConfig->backend.back_chpass= b->backend_chpass;
        mainConfig->backend.back_mod_user= b->backend_mod_user;
        mainConfig->backend.back_mod_group= b->backend_mod_group;
        mainConfig->backend.back_commit_changes= b->backend_commit_changes;
      }

      if (b->backend_init) {
        ret = (b->backend_init)(mainConfig->backend.param);
        if (ret) { /* backend says NO */
          backend_clear_struct(&mainConfig->backend);
          dlclose(handle);
          return ret;
        }
      } else {
        /* if no init function is present, we consider the module is ok */
        ret = 0;
      }

      out_log(LEVEL_INFO,"Backend %s loaded (new interface)\n",backend);

      return ret;
    }
  }

  ptr = init_fcn = (int (*)(const char *))dlsym(handle,DL_PREFIX STR_INIT);
  mainConfig->backend.back_validate_login = (uid_t (*)(const char *, wzd_user_t *))dlsym(handle,DL_PREFIX STR_VALIDATE_LOGIN);
  mainConfig->backend.back_validate_pass  = (uid_t (*)(const char *, const char *, wzd_user_t *))dlsym(handle,DL_PREFIX STR_VALIDATE_PASS);
  mainConfig->backend.back_get_user  = (wzd_user_t * (*)(uid_t))dlsym(handle,DL_PREFIX STR_GET_USER);
  mainConfig->backend.back_get_group  = (wzd_group_t * (*)(gid_t))dlsym(handle,DL_PREFIX STR_GET_GROUP);
  mainConfig->backend.back_find_user  = (uid_t (*)(const char *, wzd_user_t *))dlsym(handle,DL_PREFIX STR_FIND_USER);
  mainConfig->backend.back_find_group  = (gid_t (*)(const char *, wzd_group_t *))dlsym(handle,DL_PREFIX STR_FIND_GROUP);
  mainConfig->backend.back_mod_user  = (int (*)(const char *, wzd_user_t *, unsigned long))dlsym(handle,DL_PREFIX STR_MOD_USER);
  mainConfig->backend.back_mod_group  = (int (*)(const char *, wzd_group_t *, unsigned long))dlsym(handle,DL_PREFIX STR_MOD_GROUP);
  mainConfig->backend.back_commit_changes  = (int (*)(void))dlsym(handle,DL_PREFIX STR_COMMIT_CHANGES);
  if (backend != mainConfig->backend.name) /* strings must not overlap */
  {
    wzd_free(mainConfig->backend.name);
    mainConfig->backend.name = wzd_strdup(backend);
  }

  if (ptr) {
    ret = (*init_fcn)(mainConfig->backend.param);
    if (ret) { /* backend says NO */
      backend_clear_struct(&mainConfig->backend);
      dlclose(handle);
      return ret;
    }
  } else {
    /* if no init function is present, we consider the module is ok */
    ret = 0;
  }

  out_log(LEVEL_INFO,"Backend %s loaded\n",backend);

  return ret;
}

int backend_close(const char *backend)
{
  int (*fini_fcn)(void);
  int ret;

  if (!backend || !mainConfig->backend.name) return 1;

  /* step 1: check that backend == mainConfig->backend.name */
  if (strcmp(backend,mainConfig->backend.name)!=0) return 1;

  /* step 2: call end function */
  if (mainConfig->backend.b) {
    fini_fcn = ((wzd_backend_t*)mainConfig->backend.b)->backend_exit;
  } else {
    fini_fcn = (int (*)(void))dlsym(mainConfig->backend.handle,DL_PREFIX STR_FINI);
  }
  if (fini_fcn) {
    ret = (*fini_fcn)();
    if (ret) {
      out_log(LEVEL_CRITICAL,"Backend %s reported errors on exit (handle %lu)\n",
          backend,mainConfig->backend.handle);
/*      return 1;*/
    }
  }

  /* close backend */
  ret = 0;
  if (mainConfig->backend.handle)
  {
    char * tempname = strdup(backend);
    ret = dlclose(mainConfig->backend.handle);
    if (ret) {
#ifdef WIN32
      ret = GetLastError();
      out_log(LEVEL_INFO," Could not close backend %s (handled %lu)\n Error %d %s\n",
          tempname,mainConfig->backend.handle, ret,strerror(ret));
      backend_clear_struct(&mainConfig->backend);
#else
      out_log(LEVEL_INFO,"Could not close backend %s (handle %lu)\n",
          tempname,mainConfig->backend.handle);
      out_log(LEVEL_INFO," Error '%s'\n",dlerror());
#endif
      free(tempname);
      return 1;
    }
    free(tempname);
  }

  backend_clear_struct(&mainConfig->backend);

  return 0;
}

int backend_reload(const char *backend)
{
  int ret;

  ret = backend_close(backend);
  if (ret) return 1;

  ret = backend_init(backend,0 /* max users */,0 /* max groups */);
  if (ret) return 1;

  return 0;
}

wzd_user_t * backend_get_user(uid_t userid)
{
  wzd_backend_t * b;
  if ( (b = mainConfig->backend.b) && b->backend_get_user)
    return b->backend_get_user(userid);

  if (!mainConfig->backend.handle || !mainConfig->backend.back_get_user) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return NULL;
  }
  return (*mainConfig->backend.back_get_user)(userid);
}


int backend_find_user(const char *name, wzd_user_t * user, int * userid)
{
  int ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backend.b) && b->backend_find_user)
    ret = b->backend_find_user(name,user);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_find_user) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      return -1;
    }
    ret = (*mainConfig->backend.back_find_user)(name,user);
  }

  if (ret >= 0 && user) {
    wzd_user_t * _tmp_user;
    _tmp_user = GetUserByID(ret);
    if (!_tmp_user) return -1;
    memcpy(user,_tmp_user,sizeof(wzd_user_t));
    if (userid) *userid = ret;
    return 0;
  }
  return ret;
}

/** wrappers to user list */
wzd_user_t * GetUserByID(uid_t id)
{
  wzd_user_t *user, *user_return;
  wzd_backend_t * b;

  if (!mainConfig) return NULL;

  /* try cache first */
  if ( (user = usercache_getbyuid( id )) )
    return user;

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backend.b) && b->backend_get_user)
    user = b->backend_get_user(id);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_get_user) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return NULL;
    }
    user = (*mainConfig->backend.back_get_user)( id );
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);

  if (!user) return NULL;
  user_return = usercache_add( user );
  wzd_free(user);
  return user_return;
}

wzd_user_t * GetUserByName(const char *name)
{
  uid_t uid;
  wzd_user_t * user=NULL;
  wzd_backend_t * b;

  if (!mainConfig || !name || strlen(name)<=0) return NULL;
out_err(LEVEL_CRITICAL,"GetUserByName %s\n",name);

  /* try cache first */
  if ( (user = usercache_getbyname( name )) )
    return user;

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backend.b) && b->backend_find_user)
    uid = b->backend_find_user(name,user);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_find_user) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return NULL;
    }
    uid = (*mainConfig->backend.back_find_user)(name,user);
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);

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
  if ( (b = mainConfig->backend.b) && b->backend_get_group)
    return b->backend_get_group(groupid);

  if (!mainConfig->backend.handle || !mainConfig->backend.back_get_group) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return NULL;
  }
  return (*mainConfig->backend.back_get_group)(groupid);
}

int backend_find_group(const char *name, wzd_group_t * group, int * groupid)
{
  int ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backend.b) && b->backend_find_group)
    ret = b->backend_find_group(name,group);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_find_group) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      return -1;
    }
    ret = (*mainConfig->backend.back_find_group)(name,group);
  }

  if (ret >= 0 && group) {
    wzd_group_t * _tmp_group;
    _tmp_group = GetGroupByID(ret);
    if (!_tmp_group) return -1;
    memcpy(group,_tmp_group,sizeof(wzd_group_t));
    if (groupid) *groupid = ret;
    return 0;
  }
  return ret;
}


/** wrappers to Group list */
wzd_group_t * GetGroupByID(gid_t id)
{
  wzd_group_t * group = NULL, * group_return;
  wzd_backend_t * b;

  if (!mainConfig) return NULL;

  /* try cache first */
  if ( (group = groupcache_getbygid( id )) )
    return group;

  if ( (b = mainConfig->backend.b) && b->backend_get_group)
    group = b->backend_get_group(id);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_get_group) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      return NULL;
    }
    group = (*mainConfig->backend.back_get_group)( id );
  }

  if (!group) return NULL;
  group_return = groupcache_add( group );
  wzd_free(group);
  return group_return;
}

wzd_group_t * GetGroupByName(const char *name)
{
  gid_t gid;
  wzd_group_t * group = NULL;
  wzd_backend_t * b;

  if (!mainConfig || !name || strlen(name)<=0) return NULL;

  /* try cache first */
  if ( (group = groupcache_getbyname( name )) )
    return group;

  if ( (b = mainConfig->backend.b) && b->backend_find_group)
    gid = b->backend_find_group(name,group);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_find_group) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      return NULL;
    }
    gid = (*mainConfig->backend.back_find_group)(name,group);
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

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backend.b) && b->backend_validate_login)
    ret = b->backend_validate_login(name,user);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_validate_login) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return -1;
    }
    ret = (*mainConfig->backend.back_validate_login)(name,user);
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);

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

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backend.b) && b->backend_validate_pass)
    ret = b->backend_validate_pass(name,pass,user);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_validate_pass) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return 1;
    }
    ret = (*mainConfig->backend.back_validate_pass)(name,pass,user);
  }
  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);

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
  int ret;
  wzd_backend_t * b;

  if ( (b = mainConfig->backend.b) && b->backend_commit_changes)
    return b->backend_commit_changes();

  if (!mainConfig->backend.handle || !mainConfig->backend.back_commit_changes) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  /* check that backend == mainConfig->backend.name */
/*  if (strcmp(backend,mainConfig->backend.name)!=0) return 1;*/

  ret = (*mainConfig->backend.back_commit_changes)();
  return ret;
}

int backend_inuse(const char *backend)
{
  int count;
  ListElmt * elmnt;
  wzd_context_t * context;
  /* unusually, if backend is not loaded it is not in use ... so no error here */
  if (!mainConfig->backend.handle) {
    return -1;
  }
  /* TODO we should check here that if someone is loggued he is using the
   * specific backend
   */

  /* count user logged */
  count = 0;
  for (elmnt=list_head(context_list); elmnt != NULL; elmnt = list_next(elmnt)) {
    context = list_data(elmnt);
    if (context->magic == CONTEXT_MAGIC) {
      count++;
    }
  }
  return count;
}

/* if user does not exist, add it */
int backend_mod_user(const char *backend, const char *name, wzd_user_t * user, unsigned long mod_type)
{
  int ret;
  wzd_backend_t * b;
  wzd_user_t * new_user;

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backend.b) && b->backend_mod_user)
    ret = b->backend_mod_user(name,user,mod_type);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_mod_user) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return 1;
    }
    ret = (*mainConfig->backend.back_mod_user)(name,user,mod_type);
  }

  if (ret == 0) {
    if (mod_type & _USER_MAX_ULS) _trigger_user_max_ul(user);
    if (mod_type & _USER_MAX_DLS) _trigger_user_max_dl(user);
  }

/*  usercache_invalidate( predicate_name, (void *)name );*/

  if (!ret && user) { /* modification ok, reload user */
    if ( (b = mainConfig->backend.b) && b->backend_get_user)
      new_user = b->backend_get_user(user->uid);
    else {
      if (!mainConfig->backend.handle || !mainConfig->backend.back_get_user) {
        out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
        WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
        return ret;
      }
      new_user = (*mainConfig->backend.back_get_user)( user->uid );
    }
    if (new_user) {
      wzd_user_t * _tmp_user = usercache_getbyuid( user->uid );
      if (_tmp_user) *_tmp_user = *new_user;
      *user = *new_user;
      wzd_free(new_user);
    } else {
      /* user was deleted */
      usercache_invalidate( predicate_name, (void *)name );
    }
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  return ret;
}

/* if group does not exist, add it */
int backend_mod_group(const char *backend, const char *name, wzd_group_t * group, unsigned long mod_type)
{
  int ret;
  wzd_backend_t * b;
  wzd_group_t * new_group;

  WZD_MUTEX_LOCK(SET_MUTEX_BACKEND);

  if ( (b = mainConfig->backend.b) && b->backend_mod_group)
    ret = b->backend_mod_group(name,group,mod_type);
  else {
    if (!mainConfig->backend.handle || !mainConfig->backend.back_mod_group) {
      out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
      WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
      return 1;
    }
    ret = (*mainConfig->backend.back_mod_group)(name,group,mod_type);
  }

/*  groupcache_invalidate( predicate_groupname, (void *)name );*/

  if (!ret && group) { /* modification ok, reload group */
    if ( (b = mainConfig->backend.b) && b->backend_get_group)
      new_group = b->backend_get_group(group->gid);
    else {
      if (!mainConfig->backend.handle || !mainConfig->backend.back_get_group) {
        out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
        WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
        return ret;
      }
      new_group = (*mainConfig->backend.back_get_group)( group->gid );
    }
    if (new_group) {
      wzd_group_t * _tmp_group = groupcache_getbygid( group->gid );
      if (_tmp_group) *_tmp_group = *new_group;
      *group = *new_group;
      wzd_free(new_group);
    }
    } else {
      /* group was deleted */
      groupcache_invalidate( predicate_groupname, (void *)name );
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_BACKEND);
  return ret;
}



static int _backend_check_function(void * handle, const char *name, const char *backend_name)
{
  void * ptr;
  ptr = dlsym(handle,DL_PREFIX name);
  if (ptr == NULL)
    out_err(LEVEL_HIGH,"Could not find function %s in backend %s\n",name,backend_name);
  return (ptr) ? 1 : 0;
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

