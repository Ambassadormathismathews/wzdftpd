#include "wzd.h"


#define BUFFER_LEN	4096

/************ PRIVATE FUNCTIONS **************/

typedef struct _wzd_acl_rule_t {
  char user[256];
  char perms[3]; /* rwx */
  struct _wzd_acl_rule_t * next_acl; /* linked list */
} wzd_acl_line_t;

typedef struct _wzd_file_t {
  char	filename[256];
  char	owner[256];
  char	group[256];
  wzd_acl_line_t *acl;
  struct _wzd_file_t	*next_file;
} wzd_file_t;

int _default_perm(unsigned long wanted_right, wzd_user_t * user)
{
  return (( wanted_right & user->userperms ) == 0);
}

void free_file_recursive(wzd_file_t * file)
{
  wzd_file_t * next_file;
  wzd_acl_line_t *acl_current,*acl_next;

  if (!file) return;
  do {
    next_file = file->next_file;
    acl_current = file->acl;
    if (acl_current) {
      do {
	acl_next = acl_current->next_acl;
	free(acl_current);
	acl_current = acl_next;
      } while (acl_current);
    }
    free (file);
    file = next_file;
  } while (file);
}

wzd_file_t * find_file(const char *name, wzd_file_t *first)
{
  wzd_file_t *current=first;

  while (current) {
    if (strcmp(name,current->filename)==0)
      return current;
    current = current->next_file;
  }
  return NULL;
}

wzd_file_t * remove_file(const char *name, wzd_file_t **first)
{
  wzd_file_t *current=*first,*prev,*removed;

  if (!current) return NULL;
  
  /* first to be removed ? */
  if (strcmp(name,current->filename)==0) {
    removed = current;
    *first = removed->next_file;
    removed->next_file = NULL;
    return removed;
  }
  
  prev = current;
  current = current->next_file;

  while (current) {
    if (strcmp(name,current->filename)==0) {
      removed = current;
      prev->next_file = current->next_file;
      current->next_file = NULL;
      return removed;
    }
    prev = current;
    current = current->next_file;
  } /* while current */
  return NULL;
}

wzd_acl_line_t * find_acl(const char * username, wzd_file_t * file)
{
  wzd_acl_line_t *current = file->acl;

  while (current) {
    if (strcmp(username,current->user)==0)
      return current;
    current = current->next_acl;
  }
  return NULL;
}

/* creation and tail insertion */
wzd_file_t * add_new_file(const char *name, const char *owner, const char *group, wzd_file_t **first)
{
  wzd_file_t *current, *new_file;

  new_file = malloc(sizeof(wzd_file_t));
  strncpy(new_file->filename,name,256);
  memset(new_file->owner,0,256);
  if (owner) strncpy(new_file->owner,owner,256);
  memset(new_file->group,0,256);
  if (group) strncpy(new_file->group,group,256);
  new_file->acl = NULL;
  new_file->next_file = NULL;
  if (*first == NULL) {
    *first = new_file;
  } else {
    current = *first;
    while (current->next_file)
      current = current->next_file;
    current->next_file = new_file;
  }
  return new_file;
}

/* replace or add acl rule */
void addAcl(const char *filename, const char *user, const char *rights, wzd_file_t * file)
{
  wzd_acl_line_t * acl_current, * acl_new;

  acl_new = malloc(sizeof(wzd_acl_line_t));
  strncpy(acl_new->user,user,256);
  strncpy(acl_new->perms,rights,3);
  
  /* head insertion */
  acl_current = file->acl;
  if (!acl_current) { /* simple case, first insertion */
    file->acl = acl_new;
    acl_new->next_acl = NULL;
    return;
  }

  while (acl_current) {
    if (strcmp(acl_current->user,user)==0) { /* found ! */
      strncpy(acl_current->perms,rights,3); /* replace old perms */
      free (acl_new);
    }
    acl_current = acl_current->next_acl;
  }

  /* new acl for this file */
  acl_new->next_acl = file->acl;
  file->acl = acl_new;
}

/* should be <<atomic>> */
int readPermFile(const char *permfile, wzd_file_t **pTabFiles)
{
  FILE *fp;
  char line_buffer[BUFFER_LEN];
  wzd_file_t *current_file, *ptr_file;
  char * token1, *token2, *token3, *token4;
  char *ptr;

  if ( !pTabFiles ) return 0;

  current_file = *pTabFiles;

  fp = fopen(permfile,"r");
  if (!fp) return 1;

  ptr = (char*)current_file;
  current_file = NULL;
  while ( fgets(line_buffer,BUFFER_LEN-1,fp) )
  {
    token1 = strtok_r(line_buffer," \t\r\n",&ptr);
    if (!token1) continue; /* malformed line */
    token2 = strtok_r(NULL," \t\r\n",&ptr);
    if (!token2) continue; /* malformed line */
    token3 = strtok_r(NULL," \t\r\n",&ptr);
    if (!token3) continue; /* malformed line */
    token4 = strtok_r(NULL," \t\r\n",&ptr);
    if (!token4) continue; /* malformed line */
    /* find file in  list */
    ptr_file = find_file(token2,*pTabFiles);
    if (!ptr_file) {
      ptr_file = add_new_file(token2,0,0,pTabFiles);
    }
    if (strcmp(token1,"owner")==0) {
      strncpy(ptr_file->owner,token3,256);
      strncpy(ptr_file->group,token4,256);
    }
    else if (strcmp(token1,"perm")==0) {
      addAcl(token2,token3,token4,ptr_file);
    }
  }

  fclose(fp);
  return 0;
}

/* should be <<atomic>> */
int writePermFile(const char *permfile, wzd_file_t **pTabFiles)
{
  char buffer[BUFFER_LEN];
  FILE *fp;
  wzd_file_t * file_cur;
  wzd_acl_line_t * acl_cur;

  file_cur = *pTabFiles;

  if ( !file_cur ) {
    /* delete permission file */
    return unlink(permfile);
  }

  fp = fopen(permfile,"w"); /* overwrite any existing file */

  while (file_cur) {
    /* first write owner if available */
    if (strlen(file_cur->owner)>0 && strlen(file_cur->group)>0) {
      snprintf(buffer,4096,"owner\t%s\t%s\t%s\n",
	  file_cur->filename,file_cur->owner,file_cur->group);
      fwrite(buffer,strlen(buffer),1,fp);
    }
    acl_cur = file_cur->acl;
    while (acl_cur) {
      snprintf(buffer,4096,"perm\t%s\t%s\t%c%c%c\n",
	  file_cur->filename,acl_cur->user,acl_cur->perms[0],acl_cur->perms[1],acl_cur->perms[2]);
      fwrite(buffer,strlen(buffer),1,fp);
      acl_cur = acl_cur->next_acl;
    }
    file_cur = file_cur->next_file;
  } /* ! while */

  fclose(fp);

  return 0;
}

/* dir MUST be / terminated */
/* wanted_file MUST be a single file name ! */
int _checkFileForPerm(char *dir, const char * wanted_file, unsigned long wanted_right, wzd_user_t * user)
{
  char perm_filename[BUFFER_LEN];
  unsigned int length, neededlength;
  wzd_file_t * file_list=NULL, * file_cur;
  wzd_acl_line_t * acl_cur;
  int ret;
  int is_dir;

  /* find the dir containing the perms file */
  strncpy(perm_filename,dir,BUFFER_LEN);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);

/*
fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,perm_filename,wanted_file);
*/

  ret = readPermFile(perm_filename,&file_list);
  if (ret) { /* no permissions file */
    return _default_perm(wanted_right,user);
  }

  file_cur = find_file(wanted_file,file_list);

  if (file_cur) { /* wanted_file is in list */
    /* now find corresponding acl */
    acl_cur = find_acl(user->username,file_cur);

    if (!acl_cur) { /* ! in acl list */
      /* TODO check if user is owner or group of file, and use perms */

      /* FIXME XXX search in parent dirs - group perm ???????? XXX FIXME */
      free_file_recursive(file_list);
      file_list = NULL;
      return _default_perm(wanted_right,user);
    }

    is_dir = ( strcmp(wanted_file,".")==0 );

    /* NOTE all results are inverted (!=) because we return 0 on success ! */
    switch (wanted_right) {
    case RIGHT_RETR:
      ret = (acl_cur->perms[0]!='r');
      break;
    case RIGHT_STOR:
      ret = (acl_cur->perms[1]!='w');
      break;
    case RIGHT_CWD:
      if (is_dir) ret = (acl_cur->perms[2]!='x');
      else ret = -1;
      break;
    case RIGHT_LIST:
      if (is_dir) ret = (acl_cur->perms[0]!='r');
      else ret = -1;
      break;
    case RIGHT_RNFR:
      ret = (acl_cur->perms[1]!='w');
      break;
    default:
      ret = -1; /* stupid right asked */
      break;
    }
    free_file_recursive(file_list);
    file_list = NULL;
    return ret; /* stupid right asked */
  } else { /* ! in file_list */
    /* FIXME XXX search in parent dirs ???????? XXX FIXME */
    free_file_recursive(file_list);
    file_list = NULL;
    return _default_perm(wanted_right,user);
  } /* ! in acl */

}

/* MUST NOT be / terminated (except /) */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t * user)
{
  char dir[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char *ptr;
  struct stat s;

  if (!filename || filename[0] == '\0')
    return -1;

  strncpy(dir,filename,BUFFER_LEN); 

  if (stat(filename,&s)==-1) {
    if (wanted_right != RIGHT_STOR)
      return -1; /* inexistant ? */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      *ptr = 0;
    }
  } else {
    if (S_ISDIR(s.st_mode)) { /* isdir */
      strcpy(stripped_filename,".");
    } else { /* ! isdir */
      ptr = strrchr(dir,'/');
      if (ptr) {
        strcpy(stripped_filename,ptr+1);
        *ptr = 0;
      }
    } /* ! isdir */
  } /* stat == -1 */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* check if file is in user's root path */
  if (strncmp(dir,user->rootpath,strlen(user->rootpath))!=0)
  {
    /* if the file is in a global vfs, it does not need to be in user's rootpath */
    wzd_vfs_t * vfs = mainConfig->vfs;
    while(vfs) {
      if (strncmp(dir,vfs->physical_dir,strlen(vfs->physical_dir))==0)
	return _checkFileForPerm(dir,stripped_filename,wanted_right,user);
      vfs = vfs->next_vfs;
    }
    /* if dir is not a vfs, we can have a vfile */
    vfs = mainConfig->vfs;
    while(vfs) {
      if (strcmp(filename,vfs->physical_dir)==0)
	return _checkFileForPerm(dir,stripped_filename,wanted_right,user);
      vfs = vfs->next_vfs;
    }
    return 1;
  }

  return _checkFileForPerm(dir,stripped_filename,wanted_right,user);
}

/* MUST NOT be / terminated (except /) */
int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, wzd_context_t * context)
{
  char dir[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char perm_filename[BUFFER_LEN];
  char *ptr;
  struct stat s;
  unsigned int length, neededlength;
  wzd_file_t * file_list=NULL, * file_cur;
  int ret;

  if (!filename || filename[0] == '\0')
    return -1;

  strncpy(dir,filename,BUFFER_LEN);

  if (stat(filename,&s)==-1) return -1; /* inexistant ? */
  if (S_ISDIR(s.st_mode)) { /* isdir */
    strcpy(stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* find the dir containing the perms file */
  strncpy(perm_filename,dir,BUFFER_LEN);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);


/*fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);*/
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,perm_filename,stripped_filename);


  ret = readPermFile(perm_filename,&file_list);
  if (ret) { /* no permissions file */
    file_cur = add_new_file(stripped_filename,0,0,&file_list);
  } else { /* permission file */
    file_cur = find_file(stripped_filename,file_list);
    if (!file_cur) { /* perm file exists, but does not contains acl concerning filename */
      file_cur = add_new_file(stripped_filename,0,0,&file_list);
    }
  }

  /* set the owner/group */
  if (owner || group)
  {
    if (owner) strncpy(file_cur->owner,owner,256);
    else strcpy(file_cur->owner,"nobody");
    if (group) strncpy(file_cur->group,group,256);
    else strcpy(file_cur->group,"nogroup");
  }

  /* add the new acl */
  /* remember addAcl REPLACE existing acl on user is already existing */
  if (rights)
    addAcl(stripped_filename,granted_user,rights,file_cur);

  /* finally writes perm file on disk */
  ret = writePermFile(perm_filename,&file_list);

  free_file_recursive(file_list);
  file_list = NULL;

  return 0;
}

/* MUST NOT be / terminated (except /) */
int _movePerm(const char *oldfilename, const char *newfilename, const char *owner, const char *group, wzd_context_t * context)
{
  char dir[BUFFER_LEN];
  char src_stripped_filename[BUFFER_LEN];
  char src_perm_filename[BUFFER_LEN];
  char dst_stripped_filename[BUFFER_LEN];
  char dst_perm_filename[BUFFER_LEN];
  char *ptr;
  struct stat s,s2;
  unsigned int length, neededlength;
  wzd_file_t * src_file_list=NULL, *dst_file_list=NULL,* file_cur, *file_dst;
  wzd_acl_line_t * acl;
  int ret;

  if (!oldfilename || oldfilename[0] == '\0') return -1;
  if (!newfilename || newfilename[0] == '\0') return -1;

  /* find src perm file name */
  strncpy(dir,oldfilename,BUFFER_LEN);

  if (stat(dir,&s)==-1) return -1; /* inexistant ? */
  if (S_ISDIR(s.st_mode)) { /* isdir */
    strcpy(src_stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(src_stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* find the dir containing the perms file */
  strncpy(src_perm_filename,dir,BUFFER_LEN);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(src_perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(src_perm_filename+length,HARD_PERMFILE,neededlength);

  /* find dst perm file name */
  strncpy(dir,newfilename,BUFFER_LEN);

  /* if dst file is a dir and exists, we can't make the operation */
  if (stat(dir,&s2)==0) { /* file exists ? */
    if (S_ISDIR(s.st_mode)) { /* isdir */
      return -1;
    }
  }


  if (S_ISDIR(s.st_mode)) { /* isdir */
    strcpy(dst_stripped_filename,".");
  } else { /* ! isdir */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(dst_stripped_filename,ptr+1);
      *ptr = 0;
    }
  } /* ! isdir */

  if (dir[strlen(dir)-1] != '/') {
    strcat(dir,"/");
  }

  /* find the dir containing the perms file */
  strncpy(dst_perm_filename,dir,BUFFER_LEN);
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(dst_perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(dst_perm_filename+length,HARD_PERMFILE,neededlength);


fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,src_perm_filename,src_stripped_filename);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,dst_perm_filename,dst_stripped_filename);

  ret = readPermFile(src_perm_filename,&src_file_list);
  if (ret) { /* no permissions file */
    file_dst = NULL;
  } else { /* permission file */
    file_dst = remove_file(src_stripped_filename,&src_file_list);
  } /* permission file */

  /* finally writes perm file on disk */
  ret = writePermFile(src_perm_filename,&src_file_list);
  free_file_recursive(src_file_list);
  src_file_list = NULL;

  ret = readPermFile(dst_perm_filename,&dst_file_list);

  if (!file_dst) { /* src_file had no acl, so we have to remove acl on dst_file if present, and set owner/group */
    file_cur = remove_file(dst_stripped_filename,&dst_file_list);
    free_file_recursive(file_cur);
  } else {
    
    if (ret) { /* no permissions file */
      file_cur = add_new_file(dst_stripped_filename,owner,group,&dst_file_list);
    } else { /* permission file */
      file_cur = find_file(dst_stripped_filename,dst_file_list);
      if (!file_cur) { /* perm file exists, but does not contains acl concerning filename */
        file_cur = add_new_file(dst_stripped_filename,owner,group,&dst_file_list);
      } else {
	if (owner) strncpy(file_cur->owner,owner,256);
	if (group) strncpy(file_cur->group,group,256);
      }
    }
  
    /* replace the new acl */
    acl = file_cur->acl;
    file_cur->acl = file_dst->acl;
    file_dst->acl = acl;

    free_file_recursive(file_dst);

  } /* if file_dst */

  /* finally writes perm file on disk */
  ret = writePermFile(dst_perm_filename,&dst_file_list);

  free_file_recursive(dst_file_list);
  dst_file_list = NULL;

  return 0;
}


/************ PUBLIC FUNCTIONS ***************/

int file_open(const char *filename, int mode, unsigned long wanted_right, wzd_context_t * context)
{
  int fd;
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  if (mode & O_RDONLY)
    ret = _checkPerm(filename,RIGHT_RETR,user);
  else
    ret = _checkPerm(filename,RIGHT_STOR,user);
  if (ret)
    return 0;
  
  fd = open(filename,mode,0666);

  return fd;
}

/*void file_close(FILE *fp, wzd_context_t * context)*/
void file_close(int fd, wzd_context_t * context)
{
/*  fclose(fp);*/
  close(fd);
}

/* NOTE:
 * one of username/groupname can be NULL
 * context is usefull to check is the user chan chown to other users
 */
int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context)
{
  return _setPerm(filename,0,username,groupname,0,context);
}

/* RENAME
 * old_filename and new_filename must be ABSOLUTE paths
 */
int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context)
{
  char path[2048];
  char * ptr;
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  strncpy(path,new_filename,2048);
  ptr = strrchr(path,'/');
  if (!ptr) return 1;
  *ptr = '\0';
  ret = _checkPerm(old_filename,RIGHT_RNFR,user);
  ret = ret || _checkPerm(path,RIGHT_STOR,user);
  if (ret)
    return 1;

  /* change file name in perm file !! */
  ret = _movePerm(old_filename,new_filename,0,0,context);
  
  ret = rename(old_filename,new_filename);
  if (ret==-1) {
#ifdef DEBUG
fprintf(stderr,"rename error %d (%s)\n", errno, strerror(errno));
#endif
    return 1;
  }

  return 0;
}
