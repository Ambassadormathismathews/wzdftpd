#include "wzd.h"

/* free hook list */
int hook_free(wzd_hook_t **hook_list)
{
  wzd_hook_t * current_hook, * next_hook;

  current_hook = *hook_list;

  while (current_hook) {
    next_hook = current_hook->next_hook;

#ifdef DEBUG
    current_hook->mask = 0;
    current_hook->hook = NULL;
    current_hook->next_hook = NULL;
#endif /* DEBUG */
    free(current_hook);

    current_hook = next_hook;
  }

  *hook_list = NULL;
  return 0;
}

/* register a new hook */
int hook_add(wzd_hook_t ** hook_list, unsigned long mask, void_fct hook)
{
  wzd_hook_t * current_hook, * new_hook;

  new_hook = malloc(sizeof(wzd_hook_t));
  if (!new_hook) return 1;

  new_hook->mask = mask;
  new_hook->hook = hook;
  new_hook->next_hook = NULL;

  current_hook = *hook_list;

  if (!current_hook) {
    *hook_list = new_hook;
    return 0;
  }

  while (current_hook->next_hook) {
    current_hook = current_hook->next_hook;
  }

  current_hook->next_hook = new_hook;

  return 0;
}

/* check a module file */
int module_check(const char *filename)
{
  char path[1024];
  void * handle;
  void * ptr;
  char * error;
  struct stat s;
  int ret;

  if (!filename || filename[0]=='\0') return -1;
  if (filename[0] == '/')
    strncpy(path,filename,1023);
  else
  { /* relative path */
    if (strlen(filename) >= 1022) return -1;
    path[0] = '.';
    path[1] = '/';
    strcpy(path+2,filename);
  }

  ret = lstat(path,&s);
  if (ret) {
    out_err(LEVEL_HIGH,"Could not stat module '%s'\n",filename);
    out_err(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    return -1;
  }

  /* basic type check */
#ifdef DEBUG
  if (S_ISLNK(s.st_mode))
    out_err(LEVEL_INFO,"%s is a symlink, ok\n",filename);
  if (S_ISREG(s.st_mode))
      out_err(LEVEL_INFO,"%s is a regular file, ok\n",filename);
#endif

  /* test dlopen */
  handle = dlopen(path,RTLD_NOW);
  if (!handle) {
    out_err(LEVEL_HIGH,"Could not dlopen module '%s'\n",filename);
    out_err(LEVEL_HIGH,"errno: %d error: %s\n",errno, strerror(errno));
    out_err(LEVEL_HIGH,"dlerror: %s\n",dlerror());
    return 1;
  }

  /* check basic functions */
  ptr = dlsym(handle,STR_MODULE_INIT);
  if ((error = dlerror()) != NULL) {
    out_err(LEVEL_HIGH,"Unable to find function WZD_MODULE_INIT in module %s\n%s\n",filename,error);
    dlclose(handle);
    return 1;
  }

/*
  ptr = dlsym(handle,"hook_table");
  if ((error = dlerror()) != NULL) {
    out_log(LEVEL_HIGH,"Unable to find structure 'hook_table' in module %s\n%s\n",filename,error);
    dlclose(handle);
    return 1;
  }

  {
    typedef void (*myfct)(void);
    myfct f;
    f = (myfct)dlsym(handle,"moduletest");
    fprintf(stderr,"main prog mainConfig: %lx\n",(unsigned long)getlib_mainConfig()->logfile);
    if (f)
      f();
    else
      out_err(LEVEL_HIGH,"Could not find moduletest\n");
  }
*/

  dlclose(handle);
  return 0;
}

/* add a module to the list */
int module_add(wzd_module_t ** module_list, const char *name)
{
  wzd_module_t * current_module, * new_module;

  new_module = malloc(sizeof(wzd_module_t));
  if (!new_module) return 1;

  new_module->name = strdup(name);
  new_module->next_module = NULL;

  current_module = *module_list;

  if (!current_module) {
    *module_list = new_module;
    return 0;
  }

  while (current_module->next_module) {
    current_module = current_module->next_module;
  }

  current_module->next_module = new_module;

  return 0;
}

/* load a module - module really should have been checked before ! */
int module_load(wzd_module_t *module)
{
  char path[1024];
  void * handle;
  int ret;
  char * filename;
  fcn_module_init f_init;
#ifdef DEBUG
  char * error;
#endif

  filename = module->name;

  if (filename[0] == '/')
    strncpy(path,filename,1023);
  else
  { /* relative path */
    if (strlen(filename) >= 1022) return -1;
    path[0] = '.';
    path[1] = '/';
    strcpy(path+2,filename);
  }

  handle = dlopen(path,RTLD_NOW);
  if (!handle) return -1;

  f_init = (fcn_module_init)dlsym(handle,STR_MODULE_INIT);
#ifdef DEBUG
  if ((error = dlerror()) != NULL) {
    out_log(LEVEL_CRITICAL,"Unable to find function WZD_MODULE_INIT in module %s\n%s\n",filename,error);
    out_log(LEVEL_CRITICAL,"THIS SHOULD HAVE BEEN CHECKED BEFORE !\n");
    dlclose(handle);
    return 1;
  }
#endif

  ret = (f_init)();

  return ret;
}
