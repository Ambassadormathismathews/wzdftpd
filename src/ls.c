/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <unistd.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "wzd_structs.h"
#include "wzd_misc.h"
#include "wzd_log.h"

#include "wzd_file.h"
#include "wzd_fs.h"
#include "wzd_dir.h"
#include "wzd_utf8.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */

static int _format_date(time_t time, char * buffer, size_t length);

int list_match(char *,char *);

int list_call_wrapper(fd_t sock, wzd_context_t *context, char *line, char *buffer, size_t *buffer_len,
    int callback(fd_t,wzd_context_t*,char *))
{
  size_t length;
  if (!line) { /* request to flush */
/*out_err(LEVEL_CRITICAL,"Flushing buffer (%ld bytes)\n",*buffer_len);*/
    if (buffer && buffer[0]!='\0')
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



int list(fd_t sock,wzd_context_t * context,list_type_t format,char *directory,char *mask,
	 int callback(fd_t,wzd_context_t*,char *))
{
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  char * dirname;
  char buffer[WZD_MAX_PATH+1], * ptr_to_buffer;
  char line[WZD_MAX_PATH+80+1]; /* 80 is the long format max */
  char buffer_name[256];
  char send_buffer[HARD_LS_BUFFERSIZE];
  unsigned int send_buffer_len;
  char datestr[128];
  char * buffer_ptr;
  size_t length;
  unsigned long watchdog=0;
  fs_filestat_t sta;

  if (!directory || strlen(directory)<1) return 0;

  memset(send_buffer,0,HARD_LS_BUFFERSIZE);
  send_buffer_len = 0;

  length = strlen(directory);
  dirname = wzd_strdup(directory);
  REMOVE_TRAILING_SLASH(dirname);

  strncpy(buffer,directory,WZD_MAX_PATH);
  if (buffer[length-1] != '/') {
    buffer[length++] = '/';
    buffer[length] = '\0';
  }
  buffer_ptr = buffer+length; /* just after last '/' */

  dir = dir_open(dirname,context);
  wzd_free(dirname);
  if (!dir) return 0;

  while ( (file = dir_read(dir,context)) )
  {
    if (watchdog++ > 65535) {
      out_log(LEVEL_HIGH, "watchdog: detected infinite loop in list()\n");
      /* flush buffer ! */
      list_call_wrapper(sock, context, NULL, send_buffer, &send_buffer_len, callback);
      dir_close(dir);

      return 1;
    }


    if (file->filename[0] == '.' && !(format & LIST_SHOW_HIDDEN)) continue;
    if (mask && !list_match(file->filename,mask)) continue;

    if (format & LIST_TYPE_SHORT) {
      strncpy(line,file->filename,WZD_MAX_PATH);
      strncat(line,"\r\n",WZD_MAX_PATH);
      if (list_call_wrapper(sock,context,line,send_buffer,&send_buffer_len,callback)) break;
      continue;
    }

    /* format is long */

    switch (file->kind) {
      case FILE_LNK:
      case FILE_VFS:
        ptr_to_buffer = (char*)file->data;
        break;
      default:
        strncpy(buffer_ptr,file->filename,WZD_MAX_PATH-(buffer_ptr-buffer));
        ptr_to_buffer = buffer;
        break;
    }

/*    if (fs_lstat(ptr_to_buffer,&st)) {*/
    if (fs_file_lstat(ptr_to_buffer,&sta)) {
      /* destination does not exist */
      out_log(LEVEL_FLOOD, "list: broken file %s -> %s\n", file->filename, ptr_to_buffer);
      memset(&sta, 0, sizeof(sta));
      sta.mode = S_IFREG;
    };

    /* date */
    _format_date(sta.mtime, datestr, sizeof(datestr));

    /* permissions */

    if (!S_ISDIR(sta.mode) && !S_ISLNK(sta.mode) &&
      !S_ISREG(sta.mode)) {
      /* destination does not exist */
      out_log(LEVEL_FLOOD, "list: strange file %s\n", file->filename);
      memset(&sta, 0, sizeof(sta));
    };

    if (S_ISLNK(sta.mode)) {
      char linkbuf[256];
      int linksize;
      linksize = readlink(ptr_to_buffer,linkbuf,sizeof(linkbuf)-1);
      if (linksize > 0) {
        linkbuf[linksize]='\0';
        snprintf(buffer_name,sizeof(buffer_name)-1,"%s -> %s",file->filename,linkbuf);
      }
      else
        snprintf(buffer_name,sizeof(buffer_name)-1,"%s -> (INEXISTANT FILE)",file->filename);
    } else if (file->kind == FILE_LNK) {
      /** \bug file->data is an absolute path ... */
      if (sta.ctime != 0) {
        snprintf(buffer_name,sizeof(buffer_name)-1,"%s -> %s",file->filename,(char*)file->data);
      }
      else {
        snprintf(buffer_name,sizeof(buffer_name)-1,"%s -> (INEXISTANT FILE) %s",file->filename, (char*)file->data);
      }
    } else {
      strncpy(buffer_name,file->filename,sizeof(buffer_name)-1);
      if (strlen(file->filename)<sizeof(buffer_name)) buffer_name[strlen(file->filename)]='\0';
      else buffer_name[sizeof(buffer_name)-1] = '\0';
    }

#ifdef HAVE_UTF8
    if (context->connection_flags & CONNECTION_UTF8)
    {
      /* first, check that line is not already valid UTF-8 */
      if ( !utf8_valid(buffer_name,strlen(buffer_name)) ) {
        /* use line as a temp buffer */
        if (local_charset_to_utf8(buffer_name, line, sizeof(line), local_charset()))
        {
          out_log(LEVEL_NORMAL,"Error during UTF-8 conversion for %s\n", buffer_name);
        }
        strncpy(buffer_name, line, sizeof(buffer_name));
      }
    }
#endif

    snprintf(line,WZD_MAX_PATH+80,"%c%c%c%c%c%c%c%c%c%c %3d %s %s %13" PRIu64 " %s %s\r\n",
        (S_ISLNK(sta.mode) || (file->kind==FILE_LNK))? 'l' : S_ISDIR(sta.mode) ? 'd' : '-',
        file->permissions & S_IRUSR ? 'r' : '-',
        file->permissions & S_IWUSR ? 'w' : '-',
        file->permissions & S_IXUSR ? 'x' : '-',
        file->permissions & S_IRGRP ? 'r' : '-',
        file->permissions & S_IWGRP ? 'w' : '-',
        file->permissions & S_IXGRP ? 'x' : '-',
        file->permissions & S_IROTH ? 'r' : '-',
        file->permissions & S_IWOTH ? 'w' : '-',
        file->permissions & S_IXOTH ? 'x' : '-',
        (int)sta.nlink,
        (file->owner[0] != '\0')?file->owner:"unknown",
        (file->group[0] != '\0')?file->group:"unknown",
        sta.size,
        datestr,
        buffer_name);

    if (list_call_wrapper(sock, context, line, send_buffer, &send_buffer_len, callback)) break;
  }

  /* flush buffer ! */
  list_call_wrapper(sock, context, NULL, send_buffer, &send_buffer_len, callback);
  dir_close(dir);

  return 1;
}




/** build list in LIST format and send the result to callback
 * \deprecated use \ref list
 */
int old_list(fd_t sock,wzd_context_t * context,list_type_t format,char *directory,char *mask,
	 int callback(fd_t,wzd_context_t*,char *)) {

#ifndef _MSC_VER
  DIR *dir;
  struct dirent *entr;
#else
  HANDLE dir;
  WIN32_FIND_DATA fileData;
  int finished;
  char dirfilter[MAX_PATH];
#endif
  char *dir_filename;

  char buffer[HARD_LS_BUFFERSIZE];
  unsigned int buffer_len;
  char filename[1024];
  /*  char fullpath[1024];*/
  char line[1024+80];
  char datestr[128];
  char buffer_name[256];
  size_t dirlen;
  int i;
  time_t timeval;
  struct statbuf st;
  struct tm *ntime;
  wzd_user_t * user, * owner;
  short vfs_pad=0;

  user = GetUserByID(context->userid);

  if (directory==NULL) return 0;

  strcpy(filename,directory);
  if (directory[strlen(directory)-1]!='/') {
    strcat(filename,"/");
    vfs_pad=1;
  }
  dirlen=strlen(filename);

#ifndef _MSC_VER
  if ((dir=opendir(directory))==NULL) return 0;
#else
  if (directory[strlen(directory)-1]!='/')
    _snprintf(dirfilter,2048,"%s/*",directory);
  else
    _snprintf(dirfilter,2048,"%s*",directory);
  if ((dir = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return 0;
#endif
  memset(buffer,0,HARD_LS_BUFFERSIZE);
  buffer_len=0;

/*#ifdef DEBUG
  fprintf(stderr,"list(): %s\n",directory);
#endif*/

/* XXX show vfs if in current dir */
  {
    wzd_vfs_t * vfs = mainConfig->vfs;
    char * ptr_out;
    char buffer_vfs[4096];

    while (vfs) {
      ptr_out = vfs_replace_cookies(vfs->virtual_dir,context);
      if (!ptr_out) {
        out_log(LEVEL_CRITICAL,"vfs_replace_cookies returned NULL for %s\n",vfs->virtual_dir);
        vfs = vfs->next_vfs;
        continue;
      }
      strncpy(buffer_vfs,ptr_out,4096);
      wzd_free(ptr_out);

      if (DIRNCMP(buffer_vfs,directory,strlen(directory))==0)
      {
        char * ptr = buffer_vfs + strlen(directory) + vfs_pad;
        if (strchr(ptr,'/')==NULL) {
          if (fs_stat(vfs->physical_dir,&st)<0) {
            vfs = vfs->next_vfs;
            continue;
          }
          if (!vfs_match_perm(vfs->target,user)) { vfs = vfs->next_vfs; continue; }
          if (!list_match(ptr,mask)) { vfs = vfs->next_vfs; continue; }

          if (format & LIST_TYPE_SHORT) {
            strcpy(line,ptr);
            strcat(line,"\r\n");
          } else {
            /* date */

            timeval=time(NULL);
            ntime=localtime(&timeval);
            i=ntime->tm_year;

            ntime=localtime(&st.st_mtime);

            if (ntime->tm_year==i)
              (void)strftime(datestr,sizeof(datestr),"%b %d %H:%M",ntime);
            else (void)strftime(datestr,sizeof(datestr),"%b %d  %Y",ntime);

            /* permissions */

            if (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) &&
                !S_ISREG(st.st_mode)) {
              vfs = vfs->next_vfs;
              continue;
            }

            snprintf(line,WZD_MAX_PATH+80,"%c%c%c%c%c%c%c%c%c%c %3d %s %s %13" PRIu64 " %s %s\r\n",
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
                (u64_t)st.st_size,
                datestr,
                ptr);
          } /* format = LIST_TYPE_SHORT */


          /*        if (!callback(sock,context,line)) break;*/
          if (list_call_wrapper(sock, context, line, buffer, &buffer_len, callback)) break;
        }
      }
      vfs = vfs->next_vfs;
    }
  }

#ifndef _MSC_VER
  while ((entr=readdir(dir))!=NULL) {
    dir_filename = entr->d_name;
#else
  finished = 0;
  while (!finished) {
    dir_filename = fileData.cFileName;
#endif
    if (dir_filename[0]=='.') {
      if (strcmp(dir_filename,".")==0 ||
          strcmp(dir_filename,"..")==0 ||
          is_hidden_file(dir_filename) )
      {
#ifdef _MSC_VER
        if (!FindNextFile(dir,&fileData))
        {
          if (GetLastError() == ERROR_NO_MORE_FILES)
            finished = 1;
        }
#endif
        continue;
      }
      if ( ! (format & LIST_SHOW_HIDDEN) )
      {
#ifdef _MSC_VER
        if (!FindNextFile(dir,&fileData))
        {
          if (GetLastError() == ERROR_NO_MORE_FILES)
            finished = 1;
        }
#endif
        continue;
      }
    }
/*#ifdef DEBUG
    fprintf(stderr,"list_match(%s,%s)\n",entr->d_name,mask);
#endif*/
    if (list_match(dir_filename,mask)) {
      if (format & LIST_TYPE_SHORT) {
        strcpy(line,dir_filename);
        strcat(line,"\r\n");
/*        if (!callback(sock,context,line)) break;*/
        if (list_call_wrapper(sock, context, line, buffer, &buffer_len, callback)) break;
      } else {

        /* stat */

        if (strlen(dir_filename)+dirlen>=1024)/* continue; FIXME VISUAL */  /* sorry ... */
        {
#ifdef _MSC_VER
          if (!FindNextFile(dir,&fileData))
          {
            if (GetLastError() == ERROR_NO_MORE_FILES)
              finished = 1;
          }
#endif
          continue;
        }
        strcpy(filename+dirlen,dir_filename);
        if (fs_lstat(filename,&st)<0)
        {
#ifdef _MSC_VER
          if (!FindNextFile(dir,&fileData))
          {
            if (GetLastError() == ERROR_NO_MORE_FILES)
              finished = 1;
          }
#endif
          continue;
        }

        /* date */

        timeval=time(NULL);
        ntime=localtime(&timeval);
        i=ntime->tm_year;

        ntime=localtime(&st.st_mtime);

        if (ntime->tm_year==i)
          (void)strftime(datestr,sizeof(datestr),"%b %d %H:%M",ntime);
        else (void)strftime(datestr,sizeof(datestr),"%b %d  %Y",ntime);

        /* permissions */

        if (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) && 
            !S_ISREG(st.st_mode))
        {
#ifdef _MSC_VER
          if (!FindNextFile(dir,&fileData))
          {
            if (GetLastError() == ERROR_NO_MORE_FILES)
              finished = 1;
          }
#endif
        continue;
        }

        if (S_ISLNK(st.st_mode)) {
          char linkbuf[256];
          int linksize;
          linksize = readlink(filename,linkbuf,255);
          if (linksize > 0) {
            linkbuf[linksize]='\0';
            snprintf(buffer_name,255,"%s -> %s",dir_filename,linkbuf);
          }
          else
            snprintf(buffer_name,255,"%s -> (INEXISTANT FILE)",dir_filename);
        } else {
          strncpy(buffer_name,dir_filename,255);
          if (strlen(dir_filename)<256) buffer_name[strlen(dir_filename)]='\0';
          else buffer_name[255] = '\0';
        }

        owner = (wzd_user_t*)file_getowner( filename, context);

        snprintf(line,WZD_MAX_PATH+80,"%c%c%c%c%c%c%c%c%c%c %3d %s %s %13" PRIu64 " %s %s\r\n",
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
            (u64_t)st.st_size,
            datestr,
            buffer_name);

/*        if (!callback(sock,context,line)) break;*/
        if (list_call_wrapper(sock, context, line, buffer, &buffer_len, callback)) break;
      }
    }
#ifdef _MSC_VER
    if (!FindNextFile(dir,&fileData))
    {
      if (GetLastError() == ERROR_NO_MORE_FILES)
        finished = 1;
    }
#endif
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
  unsigned int i=0;

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

/* kind of strftime, but not locale-dependant
 * ctime returns a string like:
 * Wed Jun 30 21:49:08 1993
 *     ^^^^^^
 *     this is what we keep
 *
 * If file is older than one year, we do not show hour, but print the year
 */
static int _format_date(time_t t, char * buffer, size_t length)
{
  char * date;
  int b=0, i;

  if (length < 10) return -1;

  /** \bug FIXME localtime is NOT reentrant ! */
  date = ctime(&t);
  if (!date) return -1;

  for (i=4; i<11; i++)
    buffer[b++] = date[i];

#define YEARSEC 365*24*60*60

  if (t + YEARSEC > time(NULL))
    for (i=11; i<16; i++)
      buffer[b++] = date[i];
  else {
    buffer[b++] = ' ';
    for (i=20; i<24; i++)
      buffer[b++] = date[i];
  }
  buffer[b++] = '\0';

  return 0;
}

