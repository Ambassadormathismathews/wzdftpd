#include "wzd.h"

void backend_clear_struct(wzd_backend_t *backend)
{
  backend->name[0] = '\0';
  backend->handle = NULL;
  backend->back_validate_login = NULL;
  backend->back_validate_pass = NULL;
  backend->back_validate_ip = NULL;
  backend->back_find_user = NULL;
  backend->back_find_group = NULL;
  backend->back_chpass = NULL;
  backend->back_mod_user = NULL;
  backend->back_mod_group = NULL;
  backend->back_commit_changes = NULL;
}

int backend_validate(const char *backend)
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
    out_log(LEVEL_HIGH,"Could not stat backend '%s'\n",filename);
    out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    return 1;
  }
  /* basic type check */
  if (S_ISLNK(statbuf.st_mode))
    out_log(LEVEL_INFO,"%s is a symlink, ok\n",filename);
  if (S_ISREG(statbuf.st_mode))
      out_log(LEVEL_INFO,"%s is a regular file, ok\n",filename);

  /* test dlopen */
  handle = dlopen(filename,RTLD_NOW);
  if (!handle) {
    out_log(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
    out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_log(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  /* check functions */
  ret = 1;
  ptr = dlsym(handle,STR_VALIDATE_LOGIN);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_VALIDATE_PASS);
  ret = ret & (ptr!=NULL);
  ptr = dlsym(handle,STR_VALIDATE_IP);
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
    out_log(LEVEL_HIGH,"%s does not seem to be a valid backend - there are missing functions\n");
    return 1;
  }

  dlclose(handle);
  
  return 0;
}

int backend_init(const char *backend)
{
  void * handle;
  char filename[1024];
  char path[1024];
  int length;
  void *ptr;
  int (*init_fcn)(void);
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
  ptr = init_fcn = dlsym(handle,STR_INIT);
  mainConfig->backend.back_validate_login = dlsym(handle,STR_VALIDATE_LOGIN);
  mainConfig->backend.back_validate_pass  = dlsym(handle,STR_VALIDATE_PASS);
  mainConfig->backend.back_validate_ip  = dlsym(handle,STR_VALIDATE_IP);
  mainConfig->backend.back_find_user  = dlsym(handle,STR_FIND_USER);
  mainConfig->backend.back_find_group  = dlsym(handle,STR_FIND_GROUP);
  mainConfig->backend.back_chpass  = dlsym(handle,STR_CHPASS);
  mainConfig->backend.back_mod_user  = dlsym(handle,STR_MOD_USER);
  mainConfig->backend.back_mod_group  = dlsym(handle,STR_MOD_GROUP);
  mainConfig->backend.back_commit_changes  = dlsym(handle,STR_COMMIT_CHANGES);
  strncpy(mainConfig->backend.name,backend,1023);

  if (ptr) {
    ret = (*init_fcn)();
    if (ret) { /* backend says NO */
      backend_clear_struct(&mainConfig->backend);
      dlclose(handle);
    }
  } else {
    /* if no init function is present, we consider the module is ok */
    ret = 0;
  }

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

  ret = backend_close(backend);
  if (ret) return 1;

  ret = backend_init(backend);
  if (ret) return 1;

  return 0;
}

int backend_find_user(const char *name, wzd_user_t * user)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_find_user)(name,user);
  return ret;
}

int backend_find_group(int num, wzd_group_t * group)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_find_group)(num,group);
  return ret;
}


int backend_validate_login(const char *name, wzd_user_t * user)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_validate_login)(name,user);
  return ret;
}

int backend_validate_pass(const char *name, const char *pass, wzd_user_t *user)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_validate_pass)(name,pass,user);
  return ret;
}

int backend_validate_ip(const char *name, const char *ip)
{
  int ret;
  if (!mainConfig->backend.handle) {
    out_log(LEVEL_CRITICAL,"Attempt to call a backend function on %s:%d while there is no available backend !\n", __FILE__, __LINE__);
    return 1;
  }
  ret = (*mainConfig->backend.back_validate_ip)(name,ip);
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

