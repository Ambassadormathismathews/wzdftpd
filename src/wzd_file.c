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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_file.h"
#include "wzd_cache.h"



#define _HAS_MMAP

#ifdef _HAS_MMAP
#include <sys/mman.h>
#endif


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
  unsigned long permissions;	/* classic linux format */
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

/** creation and tail insertion */
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
  new_file->permissions = 0755; /* TODO XXX FIXME hardcoded */
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

/** replace or add acl rule */
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

/** \todo should be "atomic" */
int readPermFile(const char *permfile, wzd_file_t **pTabFiles)
{
/*  FILE *fp;*/
  wzd_cache_t * fp;
  char line_buffer[BUFFER_LEN];
  wzd_file_t *current_file, *ptr_file;
  char * token1, *token2, *token3, *token4, *token5;
  char *ptr;

  if ( !pTabFiles ) return 0;

  current_file = *pTabFiles;

/*  fp = fopen(permfile,"r");*/
  fp = wzd_cache_open(permfile,O_RDONLY,0644);
  if (!fp) { wzd_cache_close(fp); return 1; }

  ptr = (char*)current_file;
  current_file = NULL;
/*  while ( fgets(line_buffer,BUFFER_LEN-1,fp) )*/
  while ( wzd_cache_gets(fp,line_buffer,BUFFER_LEN-1) )
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
      token5 = strtok_r(NULL," \t\r\n",&ptr);
/*      if (!token5) continue;*/ /* malformed line */
      strncpy(ptr_file->owner,token3,256);
      strncpy(ptr_file->group,token4,256);
      if (token5) {
	unsigned long ul;
	ul = strtoul(token5,&ptr,8);
	if (ptr==token5) continue;
	ptr_file->permissions = ul;
      } else { /* default user/group permission */
	ptr_file->permissions = 0755; /* TODO XXX FIXME */
      }
    }
    else if (strcmp(token1,"perm")==0) {
      addAcl(token2,token3,token4,ptr_file);
    }
  }

/*  fclose(fp);*/
  wzd_cache_close(fp);
  return 0;
}

/** \todo should be "atomic" */
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
  if (!fp) return -1;

  while (file_cur) {
    /* first write owner if available */
    if (strlen(file_cur->owner)>0 || strlen(file_cur->group)>0) {
      snprintf(buffer,4096,"owner\t%s\t%s\t%s\t%lo\n",
	  file_cur->filename,file_cur->owner,file_cur->group,file_cur->permissions);
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

  /* force cache update */
  wzd_cache_update(permfile);

  return 0;
}

/** dir MUST be / terminated
 * wanted_file MUST be a single file name !
 */
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

  /* siteop always hav all permissions */
  if (user->flags && strchr(user->flags,FLAG_SITEOP))
    return 0;
  
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

    is_dir = ( strcmp(wanted_file,".")==0 );

    if (!acl_cur) { /* ! in acl list */
      /* TODO check if user is owner or group of file, and use perms */
      {
	int i;
	wzd_group_t * group;
/*	out_err(LEVEL_HIGH,"owner %s\n",file_cur->owner);*/
/*	out_err(LEVEL_HIGH,"group %s\n",file_cur->group);*/
/*	out_err(LEVEL_HIGH,"group %lo\n",file_cur->permissions);*/
	if (strcmp(user->username,file_cur->owner)==0) {
	  /* NOTE all results are inverted (!=) because we return 0 on success ! */
	  switch (wanted_right) {
	    case RIGHT_LIST:
	    case RIGHT_RETR:
	      ret = (file_cur->permissions & 0400);
	      break;
	    case RIGHT_STOR:
	    case RIGHT_MKDIR:
	    case RIGHT_RMDIR:
	    case RIGHT_RNFR:
	      ret = (file_cur->permissions & 0200);
	      break;
	    case RIGHT_CWD:
	      ret = (file_cur->permissions & 0100);
	      break;
	    default:
	      ret = 0;
	  }
/*	  out_err(LEVEL_HIGH,"user is file owner : %d !\n",ret);*/
	  free_file_recursive(file_list);
	  file_list = NULL;
	  return !ret;
	}
	for (i=0; i<user->group_num; i++) {
	  group = GetGroupByID(user->groups[i]);
	  if (group && strcmp(group->groupname,file_cur->group)==0) {
	    /* NOTE all results are inverted (!=) because we return 0 on success ! */
  	    switch (wanted_right) {
	      case RIGHT_LIST:
	      case RIGHT_RETR:
		ret = (file_cur->permissions & 0040);
		break;
	      case RIGHT_STOR:
	      case RIGHT_MKDIR:
	      case RIGHT_RMDIR:
	      case RIGHT_RNFR:
		ret = (file_cur->permissions & 0020);
		break;
	      case RIGHT_CWD:
		ret = (file_cur->permissions & 0010);
		break;
	      default:
		ret = 0;
	    }
/*	    out_err(LEVEL_HIGH,"user is in group : %d !\n",ret);*/
	    free_file_recursive(file_list);
	    file_list = NULL;
	    return !ret;
	  }
	}
      }

      /* NOTE all results are inverted (!=) because we return 0 on success ! */
      switch (wanted_right) {
	case RIGHT_LIST:
	case RIGHT_RETR:
	  ret = (file_cur->permissions & 0004);
	  break;
	case RIGHT_STOR:
	case RIGHT_MKDIR:
	case RIGHT_RMDIR:
	case RIGHT_RNFR:
	  ret = (file_cur->permissions & 0002);
	  break;
	case RIGHT_CWD:
	  ret = (file_cur->permissions & 0001);
	  break;
	default:
	  ret = 0;
      }
/*      out_err(LEVEL_HIGH,"user is in others : %d !\n",ret);*/
      free_file_recursive(file_list);
      file_list = NULL;
      return !ret;

    }

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
    /* FIXME XXX search in parent dirs ???????? - group perms XXX FIXME */
    free_file_recursive(file_list);
    file_list = NULL;
    return _default_perm(wanted_right,user);
  } /* ! in acl */

}

/** MUST NOT be / terminated (except /) */
int _checkPerm(const char *filename, unsigned long wanted_right, wzd_user_t * user)
{
  char dir[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char *ptr;
  struct stat s;

  if (!filename || filename[0] == '\0')
    return -1;

  strncpy(dir,filename,BUFFER_LEN); 

  if (user->flags && strchr(user->flags,FLAG_ANONYMOUS))
  {
    switch (wanted_right) {
      case RIGHT_STOR:
      case RIGHT_MKDIR:
      case RIGHT_RMDIR:
      case RIGHT_RNFR:
	return -1;
    }
  }

  if (stat(filename,&s)==-1) {
    if (wanted_right != RIGHT_STOR && wanted_right != RIGHT_MKDIR)
      return -1; /* inexistant ? */
    ptr = strrchr(dir,'/');
    if (ptr) {
      strcpy(stripped_filename,ptr+1);
      if (ptr == &dir[0]) *(ptr+1) = '\0';
      else *ptr = 0;
    }
    /* we need to check in parent dir for the same right */
    if (_checkPerm(dir,wanted_right,user)) return -1; /* we do not have the right to modify parent dir */
  } else {
    if (S_ISDIR(s.st_mode)) { /* isdir */
      strcpy(stripped_filename,".");
    } else { /* ! isdir */
      ptr = strrchr(dir,'/');
      if (ptr) {
        strcpy(stripped_filename,ptr+1);
	if (ptr == &dir[0]) *(ptr+1) = '\0';
	else *ptr = 0;
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

/** MUST NOT be / terminated (except /) */
int _setPerm(const char *filename, const char *granted_user, const char *owner, const char *group, const char * rights, unsigned long perms, wzd_context_t * context)
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
#ifdef DEBUG
  out_err(LEVEL_FLOOD,"_setPerm: dir %s filename %s wanted file %s\n",dir,perm_filename,stripped_filename);
#endif

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
  if (perms)
  {
    file_cur->permissions = perms;
  }

  /* finally writes perm file on disk */
  ret = writePermFile(perm_filename,&file_list);

  free_file_recursive(file_list);
  file_list = NULL;

  return 0;
}

/** MUST NOT be / terminated (except /) */
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
    /* TODO XXX FIXME Check validity of this assertion ! */
    /* permissions of directory are self contained ! */
    return 0;
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
    if (S_ISDIR(s2.st_mode)) { /* isdir */
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

#ifdef DEBUG
fprintf(stderr,"%s:%d\n",__FILE__,__LINE__);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,src_perm_filename,src_stripped_filename);
fprintf(stderr,"dir %s filename %s wanted file %s\n",dir,dst_perm_filename,dst_stripped_filename);
#endif

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
      file_cur = add_new_file(dst_stripped_filename,file_dst->owner,file_dst->group,&dst_file_list);
    } else { /* permission file */
      file_cur = find_file(dst_stripped_filename,dst_file_list);
      if (!file_cur) { /* perm file exists, but does not contains acl concerning filename */
        file_cur = add_new_file(dst_stripped_filename,file_dst->owner,file_dst->group,&dst_file_list);
      } else {
	if (owner) strncpy(file_cur->owner,file_dst->owner,256);
	if (group) strncpy(file_cur->group,file_dst->group,256);
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
  short is_locked;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (mode & O_WRONLY)
    ret = _checkPerm(filename,RIGHT_STOR,user);
  else
    ret = _checkPerm(filename,RIGHT_RETR,user);
  if (ret)
    return -1;

  fd = open(filename,mode,0666);
  if (fd == -1) {
    fprintf(stderr,"Can't open %s,errno %d : %s\n",filename,errno,strerror(errno));
    return -1;
  }

  is_locked = file_islocked(fd,F_WRLCK);

  if (is_locked == -1) {
    out_log(LEVEL_NORMAL,"Could not get lock info\n");
  }
  else {
    if ( (mode & O_WRONLY) && is_locked) {
      close(fd);
/*      fprintf(stderr,"Can't open %s in write mode, locked !\n",filename);*/
      return -1;
    }
    else {
      if (is_locked) {
/*	fprintf(stderr,"%s is locked, trying to read\n",filename);*/
	if ( CFG_GET_DENY_ACCESS_FILES_UPLOADED(mainConfig) ) {
	  close(fd);
	  return -1;
	}
      }
    }
  }

  return fd;
}

/*void file_close(FILE *fp, wzd_context_t * context)*/
void file_close(int fd, wzd_context_t * context)
{
/*  fclose(fp);*/
  close(fd);
}

/** NOTE:
 * one of username/groupname can be NULL
 * context is usefull to check if the user can chown to other users
 */
int file_chown(const char *filename, const char *username, const char *groupname, wzd_context_t * context)
{
  return _setPerm(filename,0,username,groupname,0,0,context);
}

int file_mkdir(const char *dirname, unsigned int mode, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else 
#endif
    user = GetUserByID(context->userid);

  ret = _checkPerm(dirname,RIGHT_MKDIR,user);
  if (ret) return -1;
  ret = mkdir(dirname,0755);

  return ret;
}

int file_rmdir(const char *dirname, wzd_context_t * context)
{
  int ret;
  wzd_user_t * user;
  struct stat s;
  
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else 
#endif
    user = GetUserByID(context->userid);

  ret = _checkPerm(dirname,RIGHT_RMDIR,user);
  if (ret) return -1;

  /* is a directory ? */
  if (stat(dirname,&s)) return -1;
  if (!S_ISDIR(s.st_mode)) return -1;

  /* is dir empty ? */
  {
    DIR * dir;
    struct dirent *entr;
    char path_perm[2048];

    if ((dir=opendir(dirname))==NULL) return 0;
    
    while ((entr=readdir(dir))!=NULL) {
      if (strcmp(entr->d_name,".")==0 ||
          strcmp(entr->d_name,"..")==0 ||
          strcmp(entr->d_name,HARD_PERMFILE)==0) /* XXX hide perm file ! */
        continue;
      return 1; /* dir not empty */
    }

    closedir(dir);

    /* remove permission file */
    strcpy(path_perm,dirname); /* path is already ended by / */
    if (path_perm[strlen(path_perm)-1] != '/')
      strcat(path_perm,"/");
    strcat(path_perm,HARD_PERMFILE);
    unlink(path_perm);
  }

#ifdef DEBUG
fprintf(stderr,"Removing directory '%s'\n",dirname);
#endif

#ifndef __CYGWIN__
  {
    struct stat s;
    lstat(dirname,&s);
    if (S_ISLNK(s.st_mode))
      return unlink(dirname);
  }
#endif
  return rmdir(dirname);

}

/** RENAME
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
    user = GetUserByID(context->userid);

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
  
  ret = safe_rename(old_filename,new_filename);
  if (ret==-1) {
#ifdef DEBUG
fprintf(stderr,"rename error %d (%s)\n", errno, strerror(errno));
#endif
    return 1;
  }

  return 0;
}

int file_remove(const char *filename, wzd_context_t * context)
{
  char perm_filename[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char * ptr;
  int ret;
  wzd_user_t * user;
  wzd_file_t * file_list=NULL, * file_cur;
  int neededlength, length;

  /* find the dir containing the perms file */
  strncpy(perm_filename,filename,BUFFER_LEN);
  ptr = strrchr(perm_filename,'/');
  if (!ptr || *(ptr+1)=='\0') return -1;
  strcpy(stripped_filename,ptr+1);
  if (ptr != perm_filename) *(ptr+1)='\0';
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return -1;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);
  perm_filename[length+neededlength]='\0';

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  ret = _checkPerm(filename,RIGHT_STOR ,user);
  if (ret)
    return 1;

  /* remove name in perm file !! */
  ret = readPermFile(perm_filename,&file_list);
  if (!ret) {
    file_cur = remove_file(stripped_filename, &file_list);
    ret = writePermFile(perm_filename,&file_list);
    free_file_recursive(file_cur);
    free_file_recursive(file_list);
  }
  ret = unlink(filename);
  if (ret==-1) {
#ifdef DEBUG
fprintf(stderr,"remove error %d (%s)\n", errno, strerror(errno));
#endif
    return 1;
  }

  return 0;
}

wzd_user_t * file_getowner(const char *filename, wzd_context_t * context)
{
  char perm_filename[BUFFER_LEN];
  char stripped_filename[BUFFER_LEN];
  char * ptr;
  int ret;
  wzd_user_t * user;
  wzd_file_t * file_list=NULL, * file_cur;
  int neededlength, length;
  struct stat s;

  if (stat(filename,&s))
    return NULL;

  /* find the dir containing the perms file */
  strncpy(perm_filename,filename,BUFFER_LEN);
  ptr = strrchr(perm_filename,'/');
  if (!ptr || *(ptr+1)=='\0') return NULL;
  strcpy(stripped_filename,ptr+1);
  if (ptr != perm_filename) *(ptr+1)='\0';
  neededlength = strlen(HARD_PERMFILE);
  length = strlen(perm_filename);
  /* check if !overflow */
  if ( length+neededlength > 4095 )
      return NULL;

  strncpy(perm_filename+length,HARD_PERMFILE,neededlength);

  /* remove name in perm file !! */
  ret = readPermFile(perm_filename,&file_list);
  if (!ret) {
    /* we have a permission file */
    file_cur = file_list;
    while (file_cur)
    {
      if (strcmp(stripped_filename,file_cur->filename)==0) {
	if (file_cur->owner[0]!='\0')
	{
	  free_file_recursive(file_list);
	  return GetUserByName(file_cur->owner);
	}
	else
	{
	  free_file_recursive(file_list);
	  return GetUserByName("nobody");
	}
      }
      file_cur = file_cur->next_file;
    }
    free_file_recursive(file_list);
  }

  return GetUserByName("nobody");
}

int file_lock(int fd, short lock_mode)
{
  struct flock lck;
  lck.l_type = lock_mode;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;
  if (fcntl(fd, F_SETLK, &lck) < 0) {
    return -1;
  }
  return 0;
}

int file_unlock(int fd)
{
  struct flock lck;
  lck.l_type = F_UNLCK;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;
  if (fcntl(fd, F_SETLK, &lck) < 0) {
    return -1;
  }
  return 0;
}

int file_islocked(int fd, short lock_mode)
{
  struct flock lck;
  lck.l_type = lock_mode;
  lck.l_whence = SEEK_SET;/* offset l_start from beginning of file */
  lck.l_start = 0;
  lck.l_len = 0;

  if (fcntl(fd, F_GETLK, &lck) < 0) {
    return -1;
  }
  if (lck.l_type == F_RDLCK || lck.l_type == F_WRLCK) return 1;
  return 0;
}

