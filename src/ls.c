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


/* ls replacement
   security reasons
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"
#include "wzd_misc.h"

#include "wzd_file.h"
#include "wzd_vfs.h"

int list_match(char *,char *);

int list_call_wrapper(int sock, wzd_context_t *context, char *line, char *buffer, unsigned int *buffer_len,
    int callback(int,wzd_context_t*,char *))
{
  unsigned int length;
  if (!line) { /* request to flush */
/*out_err(LEVEL_CRITICAL,"Flushing buffer (%ld bytes)\n",*buffer_len);*/
    if (!callback(sock,context,buffer)) return 1;
    return 0;
  }
  length = strlen(line);
  if (*buffer_len + length >= HARD_LS_BUFFERSIZE-1) { /* flush buffer */
/*out_err(LEVEL_CRITICAL,"Flushing buffer (%ld bytes)\n",*buffer_len);*/
    *buffer_len = 0;
    if (!callback(sock,context,buffer)) return 1;
    strcpy(buffer,line);
    *buffer_len = length;
  } else {
/*out_err(LEVEL_INFO,"Adding %ld bytes to buffer (%ld bytes)\n",length,*buffer_len);*/
    strcpy(buffer+*buffer_len,line);
    *buffer_len += length;
  }
  return 0;
}

int list(int sock,wzd_context_t * context,list_type_t format,char *directory,char *mask,
	 int callback(int,wzd_context_t*,char *)) {

  DIR *dir;
  struct dirent *entr;

  char buffer[HARD_LS_BUFFERSIZE];
  unsigned int buffer_len;
  char filename[1024];
  /*  char fullpath[1024];*/
  char line[1024+80];
  char datestr[128];
  char buffer_name[256];
  int dirlen,i;
  time_t timeval;
  struct stat st;
  struct tm *ntime;
  wzd_user_t * user, * owner;
  short vfs_pad=0;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (directory==NULL) return 0;

  strcpy(filename,directory);
  if (directory[strlen(directory)-1]!='/') {
    strcat(filename,"/");
    vfs_pad=1;
  }
  dirlen=strlen(filename);

  if ((dir=opendir(directory))==NULL) return 0;
  memset(buffer,0,HARD_LS_BUFFERSIZE);
  buffer_len=0;

/*#ifdef DEBUG
  fprintf(stderr,"list(): %s\n",directory);
#endif*/

/* XXX show vfs if in current dir */
  {
    wzd_vfs_t * vfs = mainConfig->vfs;

    while (vfs) {
      if (strncmp(vfs->virtual_dir,directory,strlen(directory))==0) {
	char * ptr = vfs->virtual_dir + strlen(directory) + vfs_pad;
	if (strchr(ptr,'/')==NULL) {
	  if (stat(vfs->physical_dir,&st)<0) {
	    vfs = vfs->next_vfs;
	    continue;
	  }
	if (!vfs_match_perm(vfs->target,user)) { vfs = vfs->next_vfs; continue; }
	if (!list_match(ptr,mask)) { vfs = vfs->next_vfs; continue; }
        /* date */
        
        timeval=time(NULL);
        ntime=localtime(&timeval);
        i=ntime->tm_year;
        
        ntime=localtime(&st.st_mtime);
        
        if (ntime->tm_year==i)
          strftime(datestr,sizeof(datestr),"%b %d %H:%M",ntime);
        else strftime(datestr,sizeof(datestr),"%b %d  %Y",ntime);
        
        /* permissions */
        
        if (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) &&
            !S_ISREG(st.st_mode)) {
	  vfs = vfs->next_vfs;
	  continue;
	}

        sprintf(line,"%c%c%c%c%c%c%c%c%c%c %3d %s %s %13llu %s %s\r\n",
                S_ISDIR(st.st_mode) ? 'd' : S_ISLNK(st.st_mode) ? 'l' : '-',
                st.st_mode & S_IRUSR ? 'r' : '-',
                st.st_mode & S_IWUSR ? 'w' : '-',
                st.st_mode & S_IXUSR ? 'x' : '-',
                st.st_mode & S_IRGRP ? 'r' : '-',
                st.st_mode & S_IWGRP ? 'w' : '-',
                st.st_mode & S_IXGRP ? 'x' : '-',
                st.st_mode & S_IROTH ? 'r' : '-',
                st.st_mode & S_IWOTH ? 'w' : '-',
                st.st_mode & S_IXOTH ? 'x' : '-',
                (int)st.st_nlink,
                user->username,
                "ftp",
                (unsigned long long)st.st_size,
                datestr,
                ptr);
                
/*        if (!callback(sock,context,line)) break;*/
	if (list_call_wrapper(sock, context, line, buffer, &buffer_len, callback)) break;
	}
      }
      vfs = vfs->next_vfs;
    }
  }
  
  while ((entr=readdir(dir))!=NULL) {
    if (entr->d_name[0]=='.') {
      if (strcmp(entr->d_name,".")==0 ||
	  strcmp(entr->d_name,"..")==0 ||
	  is_hidden_file(entr->d_name) )
	  {
	continue;
      }
      if ( ! (format & LIST_SHOW_HIDDEN) ) continue;
    }
/*#ifdef DEBUG
    fprintf(stderr,"list_match(%s,%s)\n",entr->d_name,mask);
#endif*/
    if (list_match(entr->d_name,mask)) {
      if (format & LIST_TYPE_SHORT) {
	strcpy(line,entr->d_name);
	strcat(line,"\r\n");
/*        if (!callback(sock,context,line)) break;*/
	if (list_call_wrapper(sock, context, line, buffer, &buffer_len, callback)) break;
      } else {

	/* stat */

	if (strlen(entr->d_name)+dirlen>=1024) continue;  /* sorry ... */
	strcpy(filename+dirlen,entr->d_name);
	if (lstat(filename,&st)<0) continue;

	/* date */

	timeval=time(NULL);
	ntime=localtime(&timeval);
	i=ntime->tm_year;
	
	ntime=localtime(&st.st_mtime);

	if (ntime->tm_year==i)
	  strftime(datestr,sizeof(datestr),"%b %d %H:%M",ntime);
	else strftime(datestr,sizeof(datestr),"%b %d  %Y",ntime);

	/* permissions */

	if (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) && 
	    !S_ISREG(st.st_mode)) continue;

	if (S_ISLNK(st.st_mode)) {
	  char linkbuf[256];
	  int linksize;
	  linksize = readlink(filename,linkbuf,255);
	  if (linksize > 0) {
	    linkbuf[linksize]='\0';
	    snprintf(buffer_name,255,"%s -> %s",entr->d_name,linkbuf);
	  }
	  else
	    snprintf(buffer_name,255,"%s -> (INEXISTANT FILE)",entr->d_name);
	} else {
	  strncpy(buffer_name,entr->d_name,255);
	  if (strlen(entr->d_name)<256) buffer_name[strlen(entr->d_name)]='\0';
	  else buffer_name[255] = '\0';
	}

	owner = (wzd_user_t*)file_getowner( filename, context);

	sprintf(line,"%c%c%c%c%c%c%c%c%c%c %3d %s %s %13llu %s %s\r\n",
		S_ISDIR(st.st_mode) ? 'd' : S_ISLNK(st.st_mode) ? 'l' : '-',
		st.st_mode & S_IRUSR ? 'r' : '-',
		st.st_mode & S_IWUSR ? 'w' : '-',
		st.st_mode & S_IXUSR ? 'x' : '-',
		st.st_mode & S_IRGRP ? 'r' : '-',
		st.st_mode & S_IWGRP ? 'w' : '-',
		st.st_mode & S_IXGRP ? 'x' : '-',
		st.st_mode & S_IROTH ? 'r' : '-',
		st.st_mode & S_IWOTH ? 'w' : '-',
		st.st_mode & S_IXOTH ? 'x' : '-',
		(int)st.st_nlink,
		(owner)?owner->username:"unknown",
		"ftp",
		(unsigned long long)st.st_size,
		datestr,
		buffer_name);

/*        if (!callback(sock,context,line)) break;*/
	if (list_call_wrapper(sock, context, line, buffer, &buffer_len, callback)) break;
      }
    }
  }

  /* flush buffer ! */
  list_call_wrapper(sock, context, NULL, buffer, &buffer_len, callback);
  closedir(dir);

#ifdef DEBUG
  /*  fprintf(stderr,"Left list().\n");*/
#endif

  return 1;
}

int guess_star(char *str,char *mask) {
  /* pump from here !!! */
  int i=0;

#ifdef DEBUG
  /*  fprintf(stderr,"Entered guess_star(%s,%s).\n",str,mask);*/
#endif

  if (mask[0]==0) return 1;

  for (;i<strlen(str);i++)
    if (list_match(str+i,mask)) return 1;

#ifdef DEBUG
  /*  fprintf(stderr,"Left guess_star().\n");*/
#endif

  return 0;
}

int list_match(char *str,char *mask) {
  int i=0;

#ifdef DEBUG
  /*  fprintf(stderr,"Entered list_match(%s,%s).\n",str,mask);*/
#endif

  /* character per character matching */
  do {
    if (mask[i]=='*') return guess_star(str,mask+1);
    
    if (mask[i]=='?') {
      if (str[i]!=0) continue;
      else return 0;
    }
    
    if (mask[i]!=str[i]) return 0;

  } while (mask[++i]!=0);

#ifdef DEBUG
  /*  fprintf(stderr,"Left list_match().\n");*/
#endif

  if (str[i]==0) return 1;
  else return 0;
}

#ifdef TEST
int cb(char *str) {
  OUT(str);
  return 1;
}

int main(int argc,char **argv) {
  if (argc==3) {
    list(FORMAT_LONG,argv[1],argv[2],cb);
    return 0;
  } else {
    fprintf(stderr,"Need exactly 2 parameters!\n");
    fprintf(stderr,"Syntax: ls directory mask\n");
    return -1;
  }
}
#endif
