#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"

#include "wzd_backend.h"
#include "wzd_misc.h"
#include "wzd_log.h"


void backend_clear_struct(wzd_backend_t *backend)
{
  backend->name[0] = '\0';
  backend->handle = NULL;
  backend->back_validate_login = NULL;
  backend->back_validate_pass = NULL;
  backend->back_find_user = NULL;
  backend->back_find_group = NULL;
  backend->back_chpass = NULL;
  backend->back_mod_user = NULL;
  backend->back_mod_group = NULL;
  backend->back_commit_changes = NULL;
}

int backend_validate(const char *backend, const char *pred, const char *version)
{
  struct stat statbuf;
  int ret;
  void * handle;
  void * ptr;
  char filename[1024];
  char path[1024];
  int length;

  /* default: current path */
  strcpy(path,".");
  length=strlen(path); /* FIXME wtf are these 4 lines for ? */
  /* add a / at the end if not present - XXX will conflict if last char is \ ? */
  if (path[length-1]!='/') {
    path[length++] = '/';
    path[length]='\0';
  }
  /* TODO if backend name already contains .so, do not add .o */
  /* if backend name begins with / (or x:/ for win, do not add path */
  snprintf(filename,1024,"%slibwzd%s.so",path,backend);
  ret = lstat(filename,&statbuf);
  if (ret) {
    out_err(LEVEL_HIGH,"Could not stat backend '%s'\n",filename);
    out_err(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    return 1;
  }
  /* basic type check */
#ifdef DEBUG
  if (S_ISLNK(statbuf.st_mode))
    out_err(LEVEL_INFO,"%s is a symlink, ok\n",filename);
  if (S_ISREG(statbuf.st_mode))
      out_err(LEVEL_INFO,"%s is a regular file, ok\n",filename);
#endif

  /* test dlopen */
  handle = dlopen(filename,RTLD_NOW);
  if (!handle) {
    out_err(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
    out_err(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_err(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  /* check functions */
  ret = 1;
  ptr = dlsym(handle,STR_VALIDATE_LOGIN);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_VALIDATE_PASS);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_FIND_USER);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_FIND_GROUP);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_MOD_USER);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_CHPASS);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_MOD_GROUP);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_COMMIT_CHANGES);
  ret = ret & (ptr!=NULL);
  if (!ret) {
    out_err(LEVEL_HIGH,"%s does not seem to be a valid backend - there are missing functions\n");
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
      version_found = dlsym(handle,"module_version");
      if ( (dlerror()) != NULL ) {
	out_err(LEVEL_CRITICAL,"Backend does not contain any \"module_version\" information\n");
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
/*  strncpy(mainConfig->backend.name,backend,1023);*/
  
  return 0;
}

int backend_init(const char *backend, int *backend_storage, wzd_user_t * user_list, unsigned int user_max, wzd_group_t * group_list, unsigned int group_max)
{
  void * handle;
  char filename[1024];
  char path[1024];
  int length;
  void *ptr;
  int (*init_fcn)(int *, wzd_user_t *, unsigned int, wzd_group_t *, unsigned int);
  int ret;

  /* default: current path */
  strcpy(path,".");
  length=strlen(path); /* FIXME wtf are these 4 lines for ? */
  /* add a / at the end if not present - XXX will conflict if last char is \ ? */
  if (path[length-1]!='/') {
    path[length++] = '/';
    path[length]='\0';
  }
  /* TODO if backend name already contains .so, do not add .o */
  /* if backend name begins with / (or x:/ for win, do not add path */
  snprintf(filename,1024,"%slibwzd%s.so",path,backend);

  /* test dlopen */
  handle = dlopen(filename,RTLD_NOW);
  if (!handle) {
    out_log(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
    out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_log(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  mainConfig->backend.handle = handle;
  ptr = init_fcn = (int (*)(int *, wzd_user_t *, unsigned int, wzd_group_t *, unsigned int))dlsym(handle,STR_INIT);
  mainConfig->backend.back_validate_login = (int (*)(const char *, wzd_user_t *))dlsym(handle,STR_VALIDATE_LOGIN);
  mainConfig->backend.back_validate_pass  = (int (*)(const char *, const char *, wzd_user_t *))dlsym(handle,STR_VALIDATE_PASS);
  mainConfig->backend.back_find_user  = (int (*)(const char *, wzd_user_t *))dlsym(handle,STR_FIND_USER);
  mainConfig->backend.back_find_group  = (int (*)(int, wzd_group_t *))dlsym(handle,STR_FIND_GROUP);
  mainConfig->backend.back_chpass  = (int (*)(const char *, const char *))dlsym(handle,STR_CHPASS);
  mainConfig->backend.back_mod_user  = (int (*)(const char *, wzd_user_t *, unsigned long))dlsym(handle,STR_MOD_USER);
  mainConfig->backend.back_mod_group  = (int (*)(int, wzd_group_t *))dlsym(handle,STR_MOD_GROUP);
  mainConfig->backend.back_commit_changes  = (int (*)(void))dlsym(handle,STR_COMMIT_CHANGES);
  strncpy(mainConfig->backend.name,backend,1023);

  if (ptr) {
    ret = (*init_fcn)(backend_storage, user_list, user_max, group_list, group_max);
    if (ret) { /* backend says NO */
      backend_clear_struct(&mainConfig->backend);
      dlclose(handle);
      return ret;
    }
  } else {
    /* if no init function is present, we consider the module is ok */
    ret = 0;
  }

  mainConfig->backend.backend_storage = *backend_storage;
  out_log(LEVEL_NORMAL,"Backend %s loaded\n",backend);

  return ret;
}

int backend_close(const char *backend)
{
  int ret;

  /* step 1: check that backend == mainConfig->backend.name */
  if (strcmp(backend,mainConfig->backend.name)!=0) return 1;

  /* close backend */
  ret = dlclose(mainConfig->backend.handle);
  if (ret) {
    out_log(LEVEL_CRITICAL,"Could not close backend %s (handle %lu)\n",
      backend,mainConfig->backend.handle);
    out_log(LEVEL_CRITICAL," Error '%s'\n",dlerror());
    return 1;
  }

  backend_clear_struct(&mainConfig->backend);

  return 0;
}

int backend_reload(const char *backend)
{
  int ret;
  int backend_storage;

  ret = backend_close(backend);
  if (ret) return 1;

  ret = backend_init(backend,&backend_storage,mainConfig->user_list,HARD_DEF_USER_MAX,mainConfig->group_list,HARD_DEF_GROUP_MAX);
  if (ret) return 1;
  mainConfig->backend.backend_storage = backend_storage;

  return 0;
}

int backend_find_user(const char *name, wzd_user_t * user, int * userid)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_find_user)(name,user);
  if (mainConfig->backend.backend_storage == 0 && ret >= 0) {
    /*user = GetUserByID(ret);*/
    memcpy(user,GetUserByID(ret),sizeof(wzd_user_t));
    *userid = ret;
    return 0;
  }
  return ret;
}

int backend_find_group(int num, wzd_group_t * group, int * groupid)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_find_group)(num,group);
  if (mainConfig->backend.backend_storage == 0 && ret >= 0) {
    memcpy(group,GetGroupByID(ret),sizeof(wzd_group_t));
    *groupid = ret;
    return 0;
  }
  return ret;
}


int backend_validate_login(const char *name, wzd_user_t * user, unsigned int * userid)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_validate_login)(name,user);
  if (mainConfig->backend.backend_storage == 0 && ret >= 0) {
    /*user = GetUserByID(ret);*/
    if (user != NULL)
      memcpy(user,GetUserByID(ret),sizeof(wzd_user_t));
    *userid = ret;
    return 0;
  }
  return ret;
}

int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user, unsigned int * userid)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_validate_pass)(name,pass,user);
  if (mainConfig->backend.backend_storage == 0 && ret >= 0) {
    /*user = GetUserByID(ret);*/
    if (user != NULL)
      memcpy(user,GetUserByID(ret),sizeof(wzd_user_t));
    *userid = ret;
    return 0;
  }
  return ret;
}

int backend_commit_changes(const char *backend)
{
  int ret;

  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  /* check that backend == mainConfig->backend.name */
  if (strcmp(backend,mainConfig->backend.name)!=0) return 1;

  ret = (*mainConfig->backend.back_commit_changes)();
  return ret;
}

int backend_chpass(const char *username, const char *new_pass)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_chpass)(username,new_pass);
  return ret;
}

int backend_inuse(const char *backend)
{
  int count, i;
  /* unusually, if backend is not loaded it is not in use ... so no error here */
  if (!mainConfig->backend.handle) {
    return -1;
  }
  /* TODO we should check here that if someone is loggued he is using the
   * specific backend
   */

  /* count user logged */
  count = 0;
  for (i=0; i<HARD_USERLIMIT; i++) {
    if (context_list[i].magic == CONTEXT_MAGIC) {
      count++;
    }
  }
  return count;
}

/* if user does not exist, add it */
int backend_mod_user(const char *backend, const char *name, wzd_user_t * user, unsigned long mod_type)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_mod_user)(name,user,mod_type);
  return ret;
}
