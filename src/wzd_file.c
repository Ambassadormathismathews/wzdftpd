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

int _default_perm(unsigned long wanted_right, wzd_context_t * context)
{
  return (( wanted_right & context->userinfo.perms ) == 0);
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
  file->acl = acl_new->next_acl;
}

/* should be <<atomic>> */
int readPermFile(const char *permfile, wzd_file_t **pTabFiles)
{
  FILE *fp;
  char line_buffer[BUFFER_LEN];
  wzd_file_t *current_file, *ptr_file;
  char * token1, *token2, *token3, *token4;
  char *ptr;

  fp = fopen(permfile,"r");
  if (!fp) return 1;

  current_file = *pTabFiles;
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

  fp = fopen(permfile,"w"); /* overwrite any existing file */

  file_cur = *pTabFiles;

  while (file_cur) {
    /* first write owner if available */
    if (strlen(file_cur->owner)>0 && strlen(file_cur->group)>0) {
      snprintf(buffer,4096,"owner\t%s\t%s\t%s\n",
	  file_cur->filename,file_cur->owner,file_cur->group);
      fwrite(buffer,strlen(buffer),1,fp);
    }
    acl_cur = file_cur->acl;
    while (acl_cur) {
      snprintf(buffer,4096,"perm\t%s\t%s\t%s\n",
	  file_cur->filename,acl_cur->user,acl_cur->perms);
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
int _checkFileForPerm(char *dir, const char * wanted_file, unsigned long wanted_right, wzd_context_t *context)
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


fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,perm_filename,wanted_file);


  ret = readPermFile(perm_filename,&file_list);
  if (ret) { /* no permissions file */
    return _default_perm(wanted_right,context);
  }

  file_cur = find_file(wanted_file,file_list);

  if (file_cur) { /* wanted_file is in list */
    /* now find corresponding acl */
    acl_cur = find_acl(context->userinfo.username,file_cur);

    if (!acl_cur) { /* ! in acl list */
      /* TODO check if context->userinfo is owner or group of file, and use perms */

      /* FIXME XXX search in parent dirs ???????? XXX FIXME */
      free_file_recursive(file_list);
      file_list = NULL;
      return _default_perm(wanted_right,context);
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
    return _default_perm(wanted_right,context);
  } /* ! in acl */

}

/* MUST NOT be / terminated (except /) */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_context_t *context)
{
  char dir[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char *ptr;
  struct stat s;

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

  return _checkFileForPerm(dir,stripped_filename,wanted_right,context);
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


fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
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

/************ PUBLIC FUNCTIONS ***************/

FILE * file_open(const char *filename, const char *mode, unsigned long wanted_right, wzd_context_t * context)
{
  FILE *fp;
  int ret;

  ret = _checkPerm(filename,RIGHT_RETR,context);
  if (ret)
    return NULL;
  
  fp = fopen(filename,mode);

  return fp;
}

void file_close(FILE *fp, wzd_context_t * context)
{
  fclose(fp);
}

/* NOTE:
 * one of username/groupname can be NULL
 * context is usefull to check is the user chan chown to other users
 */
int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context)
{
  return 0;
}

/* RENAME
 * old_filename and new_filename must be ABSOLUTE paths
 */
int file_rename(const char *old_filename, const char *new_filename, wzd_context_t * context)
{
  char path[2048];
  char * ptr;
  int ret;

  strncpy(path,new_filename,2048);
  ptr = strrchr(path,'/');
  if (!ptr) return 1;
  *ptr = '\0';
  ret = _checkPerm(old_filename,RIGHT_RNFR,context);
  ret = ret || _checkPerm(path,RIGHT_STOR,context);
  if (ret)
    return 1;

  ret = rename(old_filename,new_filename);
  if (ret==-1) {
#ifdef DEBUG
fprintf(stderr,"rename error %d (%s)\n", errno, strerror(errno));
#endif
    return 1;
  }
  /* TODO change file name in perm file !! */
  
  return 0;
}
