/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <dlfcn.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"

#include "wzd_mod.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"

struct event_entry_t {
  unsigned long mask;
  const char *name;
};

struct event_entry_t event_tab[] = {
  { EVENT_LOGIN, "LOGIN" },
  { EVENT_LOGOUT, "LOGOUT" },
  { EVENT_PREUPLOAD, "PREUPLOAD" },
  { EVENT_POSTUPLOAD, "POSTUPLOAD" },
  { EVENT_POSTDOWNLOAD, "POSTDOWNLOAD" },
  { EVENT_MKDIR, "MKDIR" },
  { EVENT_RMDIR, "RMDIR" },
  { EVENT_SITE, "SITE" },
  { 0, NULL },
};

/** free hook list */
void hook_free(wzd_hook_t **hook_list)
{
  wzd_hook_t * current_hook, * next_hook;

  current_hook = *hook_list;

  while (current_hook) {
    next_hook = current_hook->next_hook;

    if (current_hook->external_command)
      free(current_hook->external_command);
    if (current_hook->opt) free(current_hook->opt);
#ifdef DEBUG
    current_hook->mask = 0;
    current_hook->hook = NULL;
    current_hook->external_command = NULL;
    current_hook->opt=NULL;
    current_hook->next_hook = NULL;
#endif /* DEBUG */
    free(current_hook);

    current_hook = next_hook;
  }

  *hook_list = NULL;
}

/** register a new hook */
int hook_add(wzd_hook_t ** hook_list, unsigned long mask, void_fct hook)
{
  wzd_hook_t * current_hook, * new_hook;

  new_hook = malloc(sizeof(wzd_hook_t));
  if (!new_hook) return 1;

  new_hook->mask = mask;
  new_hook->hook = hook;
  new_hook->opt = NULL;
  new_hook->external_command = NULL;
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

int hook_add_external(wzd_hook_t ** hook_list, unsigned long mask, const char *command)
{
  wzd_hook_t * current_hook, * new_hook;

  new_hook = malloc(sizeof(wzd_hook_t));
  if (!new_hook) return 1;

  new_hook->mask = mask;
  new_hook->hook = NULL;
  new_hook->opt = NULL;
  new_hook->external_command = strdup(command);
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

int hook_add_custom_command(wzd_hook_t ** hook_list, const char *name, const char *command)
{
  wzd_hook_t * current_hook, * new_hook;

  new_hook = malloc(sizeof(wzd_hook_t));
  if (!new_hook) return 1;

  new_hook->mask = EVENT_SITE;
  new_hook->hook = NULL;
  new_hook->opt = strdup(name);
  new_hook->external_command = strdup(command);
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

int hook_call_custom(wzd_context_t * context, wzd_hook_t *hook, const char *args)
{
  char buffer[1024];
  FILE *command_output;
  unsigned int l_command;

  if (!hook || !hook->external_command) return 1;
  l_command = strlen(hook->external_command);
  if (l_command+strlen(args)>=1022) return 1;
  strcpy(buffer,hook->external_command);
  *(buffer+l_command++) = ' ';
  strcpy(buffer+l_command,args);
  if ( (command_output = popen(buffer,"r")) == NULL ) {
    out_log(LEVEL_HIGH,"Hook '%s': unable to popen\n",hook->external_command);
    return 1;
  }
  while (fgets(buffer,1023,command_output) != NULL)
  {
    send_message_raw(buffer,context);
  }
  pclose(command_output);

  return 0;
}

int hook_call_external(wzd_hook_t *hook, const char *args)
{
  char buffer[1024];
  FILE *command_output;
  unsigned int l_command;

  if (!hook || !hook->external_command) return 1;
  l_command = strlen(hook->external_command);
  if (l_command+strlen(args)>=1022) return 1;
  strcpy(buffer,hook->external_command);
  *(buffer+l_command++) = ' ';
  strcpy(buffer+l_command,args);
  if ( (command_output = popen(buffer,"r")) == NULL ) {
    out_log(LEVEL_HIGH,"Hook '%s': unable to popen\n",hook->external_command);
    return 1;
  }
  while (fgets(buffer,1023,command_output) != NULL)
  {
    out_log(LEVEL_INFO,"hook: %s\n",buffer);
  }
  pclose(command_output);

  return 0;
}

unsigned long str2event(const char *s)
{
  int i=0;

  while (event_tab[i].mask != 0)
  {
    if (strcasecmp(s,event_tab[i].name)==0) return event_tab[i].mask;
    i++;
  }
  return 0;
}



/** check a module file */
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
#if 0
#ifdef DEBUG
  if (S_ISLNK(s.st_mode))
    out_err(LEVEL_INFO,"%s is a symlink, ok\n",filename);
  if (S_ISREG(s.st_mode))
      out_err(LEVEL_INFO,"%s is a regular file, ok\n",filename);
#endif
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

/** add a module to the list */
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

/** load a module - module really should have been checked before ! */
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

/** free module list */
void module_free(wzd_module_t ** module_list)
{
  wzd_module_t * current_module, * next_module;

  current_module = *module_list;

  while (current_module) {
    next_module = current_module->next_module;

    if (current_module->name)
      free(current_module->name);
#ifdef DEBUG
    current_module->name = NULL;
    current_module->next_module = NULL;
#endif /* DEBUG */
    free(current_module);

    current_module = next_module;
  }

  *module_list = NULL;
}
