#include "wzd.h"

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
  length=strlen(path);
  /* add a / at the end if not present - XXX will conflict if last char is \ ? */
  if (path[length-1]!='/') {
    path[length++] = '/';
    path[length]='\0';
  }
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
  ptr = dlsym(handle,STR_VALIDATE_RIGHT);
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
  length=strlen(path);
  /* add a / at the end if not present - XXX will conflict if last char is \ ? */
  if (path[length-1]!='/') {
    path[length++] = '/';
    path[length]='\0';
  }
  snprintf(filename,1024,"%slibwzd%s.so",path,backend);

  /* test dlopen */
  handle = dlopen(filename,RTLD_NOW);
  if (!handle) {
    out_log(LEVEL_HIGH,"Could not dlopen backend '%s'\n",filename);
    out_log(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_log(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  mainConfig.backend.handle = handle;
  ptr = init_fcn = dlsym(handle,STR_INIT);
  mainConfig.backend.back_validate_login = dlsym(handle,STR_VALIDATE_LOGIN);
  mainConfig.backend.back_validate_pass  = dlsym(handle,STR_VALIDATE_PASS);
  mainConfig.backend.back_validate_right  = dlsym(handle,STR_VALIDATE_RIGHT);

  if (ptr) {
    ret = (*init_fcn)();
    if (ret) { /* backend says NO */
      mainConfig.backend.handle = NULL;
      mainConfig.backend.back_validate_login = NULL;
      mainConfig.backend.back_validate_pass = NULL;
      mainConfig.backend.back_validate_right = NULL;
      dlclose(handle);
    }
  } else {
    /* if no init function is present, we consider the module is ok */
    ret = 0;
  }

  out_log(LEVEL_NORMAL,"Backend %s loaded\n",backend);

  return ret;
}

int backend_chek_perm(wzd_user_t * user, wzd_perm_t perm, void * param)
{
  int ret;

  ret = (*mainConfig.backend.back_validate_right)(user,perm,param);

  return ret;
}
