#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"

#include "wzd_vfs.h"
#include "wzd_log.h"
#include "wzd_misc.h"

/* free vfs list */
int vfs_free(wzd_vfs_t **vfs_list)
{
  wzd_vfs_t * current_vfs, * next_vfs;

  current_vfs = *vfs_list;

  while (current_vfs) {
    next_vfs = current_vfs->next_vfs;

    free(current_vfs->virtual_dir);
    free(current_vfs->physical_dir);

#ifdef DEBUG
    current_vfs->virtual_dir = NULL;
    current_vfs->physical_dir = NULL;
    current_vfs->next_vfs = NULL;
#endif /* DEBUG */
    free(current_vfs);

    current_vfs = next_vfs;
  }

  *vfs_list = NULL;
  return 0;
}

/* register a new vfs entry */
int vfs_add(wzd_vfs_t ** vfs_list, const char *vpath, const char *path)
{
  wzd_vfs_t * current_vfs, * new_vfs;
  struct stat s;

  if (stat(path,&s)) {
    /* destination does not exist */
    return 1;
  }

  new_vfs = malloc(sizeof(wzd_vfs_t));
  if (!new_vfs) return 1;

  new_vfs->virtual_dir = strdup(vpath);
  new_vfs->physical_dir = strdup(path);
  new_vfs->next_vfs = NULL;

  current_vfs = *vfs_list;

  if (!current_vfs) {
    *vfs_list = new_vfs;
    return 0;
  }

  while (current_vfs->next_vfs) {
    current_vfs = current_vfs->next_vfs;
  }

  current_vfs->next_vfs = new_vfs;

  return 0;
}

/* if needed, replace the vfs in the path */
int vfs_replace(wzd_vfs_t *vfs_list, char *buffer, unsigned int maxlen)
{
  /* FIXME test length of strings */
  while (vfs_list)
  {
    if (strncmp(vfs_list->virtual_dir,buffer,strlen(vfs_list->virtual_dir))==0
	&&
	(buffer[strlen(vfs_list->virtual_dir)] == '/' || /* without this test, vfs will always match before vfs1 */
	strcmp(vfs_list->virtual_dir,buffer)==0) ) /* without this test, 'cd vfs' will not match */
    {
      char buf[4096];
#ifdef DEBUG
out_err(LEVEL_CRITICAL,"VPATH : %s / %s\n",buffer,vfs_list->virtual_dir);
#endif
      strcpy(buf,vfs_list->physical_dir);
      strcpy(buf+strlen(vfs_list->physical_dir),buffer+strlen(vfs_list->virtual_dir));
#ifdef DEBUG
out_err(LEVEL_CRITICAL,"converted to %s\n",buf);
#endif
      strcpy(buffer,buf);
    }
    vfs_list = vfs_list->next_vfs;
  }
  return 0;
}

/*************** checkpath ***************************/

char *stripdir(char * dir, char *buf, int maxlen)
{
  char * in, * out;
  char * last; 
  int ldots;
        
  in   = dir;
  out  = buf;
  last = buf + maxlen;
  ldots = 0; 
  *out  = 0;
        
  if (*in != '/') {
    if (getcwd(buf, maxlen - 2) ) {
      out = buf + strlen(buf) - 1;
      if (*out != '/') *(++out) = '/';
      out++;
    }       
    else
      return NULL;
  }               

  while (out < last) {
    *out = *in;

    if (*in == '/')
    {
      while (*(++in) == '/') ;
        in--;
    }

    if (*in == '/' || !*in)
    {
      if (ldots == 1 || ldots == 2) {
        while (ldots > 0 && --out > buf)
        {
          if (*out == '/')
            ldots--;
        }
        *(out+1) = 0;
      }
      ldots = 0;

    } else if (*in == '.') {
      ldots++;
    } else {
      ldots = 0;
    }

    out++;

    if (!*in)
      break;
                        
    in++;
  }       
        
  if (*in) {
    errno = ENOMEM;
    return NULL;
  }       
        
  while (--out != buf && (*out == '/' || !*out)) *out=0;
    return buf;
}       


int checkpath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char allowed[2048];
  char cmd[2048];
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0) {
    sprintf(allowed,"%s/",context->userinfo.rootpath);
    sprintf(cmd,"%s%s",context->userinfo.rootpath,context->currentpath);
  } else
#endif
  {
    sprintf(allowed,"%s/",GetUserByID(context->userid)->rootpath);
    if (strcmp(allowed,"//")==0) allowed[1]='\0';
    sprintf(cmd,"%s%s",GetUserByID(context->userid)->rootpath,context->currentpath);
  }
  if (cmd[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      strcat(cmd,wanted_path);
    } else {
      strcpy(cmd,allowed);
      strcat(cmd,wanted_path+1);
    } 
  } 
/*#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif*/
/*  if (!realpath(cmd,path)) return 1;*/
  if (!stripdir(cmd,path,2048)) return 1;
/*#ifdef DEBUG
printf("Converted to: '%s'\n",path);
#endif*/
  if (path[strlen(path)-1] != '/')
    strcat(path,"/");
  strcpy(cmd,path);
  cmd[strlen(allowed)]='\0';
  if (path[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  /* check if user is allowed to even see the path */
  if (strncmp(cmd,allowed,strlen(allowed))) return 1;
  /* in the case of VFS, we need to convert here to a realpath */
  vfs_replace(mainConfig->vfs,path,2048);
  if (path[strlen(path)-1] == '/') path[strlen(path)-1]='\0';
  return 0;
}

int checkabspath(const char *wanted_path, char *path, wzd_context_t *context)
{
  char allowed[2048];
  char cmd[2048];
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage == 0) {
    sprintf(allowed,"%s/",context->userinfo.rootpath);
    sprintf(cmd,"%s%s",context->userinfo.rootpath,context->currentpath);
  } else
#endif
  {
    sprintf(allowed,"%s/",GetUserByID(context->userid)->rootpath);
    if (strcmp(allowed,"//")==0) allowed[1]='\0';
    sprintf(cmd,"%s%s",GetUserByID(context->userid)->rootpath,context->currentpath);
  }
  if (cmd[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  if (wanted_path) {
    if (wanted_path[0]!='/') {
      return -1; /* we need absolute path, but it doesn't begin with / */
    } else {
      strcpy(cmd,wanted_path);
    } 
  } 
/*#ifdef DEBUG
printf("Checking path '%s' (cmd)\nallowed = '%s'\n",cmd,allowed);
#endif*/
/*  if (!realpath(cmd,path)) return 1;*/
  if (!stripdir(cmd,path,2048)) return 1;
/*#ifdef DEBUG
printf("Converted to: '%s'\n",path);
#endif*/
  if (path[strlen(path)-1] != '/')
    strcat(path,"/");
  strcpy(cmd,path);
  cmd[strlen(allowed)]='\0';
  if (path[strlen(cmd)-1] != '/')
    strcat(cmd,"/");
  /* check if user is allowed to even see the path */
  if (strncmp(cmd,allowed,strlen(allowed))) return 1;
  /* in the case of VFS, we need to convert here to a realpath */
  vfs_replace(mainConfig->vfs,path,2048);
  if (path[strlen(path)-1] == '/') path[strlen(path)-1]='\0';
  return 0;
}

