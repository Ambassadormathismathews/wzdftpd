#include "wzd.h"

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
	&& buffer[strlen(vfs_list->virtual_dir)] == '/')
    {
      char buf[4096];
#if DEBUG
out_err(LEVEL_CRITICAL,"VPATH : %s / %s\n",buffer,vfs_list->virtual_dir);
#endif
      strcpy(buf,vfs_list->physical_dir);
      strcpy(buf+strlen(vfs_list->physical_dir),buffer+strlen(vfs_list->virtual_dir));
#if DEBUG
out_err(LEVEL_CRITICAL,"converted to %s\n",buf);
#endif
      strcpy(buffer,buf);
    }
    vfs_list = vfs_list->next_vfs;
  }
  return 0;
}
