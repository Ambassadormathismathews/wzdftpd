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

static int list_match(char *,char *);

int list_call_wrapper(fd_t sock, wzd_context_t *context, const char *line, char *buffer, size_t *buffer_len,
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


/* filename must be an ABSOLUTE path */
int mlst_single_file(const char *filename, wzd_string_t * buffer, wzd_context_t * context)
{
  struct wzd_file_t * file_info;
  char *ptr;
  fs_filestat_t s;
  wzd_string_t *temp;
  const char *type;

  if (!filename  || !buffer) return -1;

  ptr = strrchr(filename,'/');
  if (!ptr) return -1;
  if (ptr+1 != '\0') ptr++;

  if (fs_file_lstat(filename,&s)) return -1;

  temp = str_allocate();

  str_sprintf(buffer,"");

  /* XXX build info */
  file_info = file_stat(filename,context);

  /* Type=... */
  if (file_info && file_info->kind != FILE_NOTSET) {
    switch (file_info->kind) {
      case FILE_REG:
        type = "file"; break;
      case FILE_DIR:
        type = "dir"; break;
      case FILE_LNK:
        type = "OS.unix=slink"; break;
      case FILE_VFS:
        type = "OS.wzdftpd=vfs"; break;
      default:
        type = "unknown"; break;
    }
  } else {
    switch (s.mode & S_IFMT) {
      case S_IFREG:
        type = "file"; break;
      case S_IFDIR:
        type = "dir"; break;
      case S_IFLNK:
        type = "OS.unix=slink"; break;
      default:
        type = "unknown"; break;
    }
  }
  str_sprintf(temp,"Type=%s;",type);
  str_append(buffer,str_tochar(temp));

  /* Size=... */
  {
    str_sprintf(temp,"Size=%" PRIu64 ";",s.size);
    str_append(buffer,str_tochar(temp));
  }

  /* Modify=... */
  {
    char tm[32];
    strftime(tm,sizeof(tm),"%Y%m%d%H%M%S",gmtime(&s.mtime));

    str_sprintf(temp,"Modify=%s;",tm);
    str_append(buffer,str_tochar(temp));
  }

#if 0
  /* Perm=... */
  {
    str_sprintf(temp," Perm=");
    /* "a" / "c" / "d" / "e" / "f" /
     * "l" / "m" / "p" / "r" / "w"
     */
    str_append(buffer,str_tochar(temp));
  }
#endif

#if 0
  /* Unique=... */
  {
    str_sprintf(temp," Unique=%llu;",(u64_t)s.ino);
    str_append(buffer,str_tochar(temp));
  }
#endif

  /* End, append name */
  str_append(buffer," ");
  str_append(buffer,ptr);

  free_file_recursive(file_info);
  str_deallocate(temp);

  return 0;
}

int mlsd_directory(const char * dirname, fd_t sock, int callback(fd_t,wzd_context_t*,char *),
    wzd_context_t * context)
{
  fs_dir_t * dir;
  fs_fileinfo_t * finfo;
  unsigned long watchdog=0;
  char buffer[WZD_MAX_PATH+1], * ptr_to_buffer;
  size_t length;
  wzd_string_t * str;
  char send_buffer[HARD_LS_BUFFERSIZE];
  size_t send_buffer_len;
  const char * dir_filename;

  if (fs_dir_open(dirname, &dir)) return 1;

  /* ensure buffer is / terminated */
  strncpy(buffer, dirname, sizeof(buffer)-1);
  ptr_to_buffer = buffer + strlen(buffer) - 1;
  if (*ptr_to_buffer != '/') {
    ptr_to_buffer++;
    *ptr_to_buffer = '/';
    *(ptr_to_buffer+1) = '\0';
  }
  ptr_to_buffer++;

  length = sizeof(buffer) - (ptr_to_buffer - buffer) - 1;

  str = str_allocate();
  memset(send_buffer,0,HARD_LS_BUFFERSIZE);
  send_buffer_len = 0;

  /** \todo send info on current dir and parent dir ? */

  while ( !fs_dir_read(dir, &finfo) )
  {
    if (watchdog++ > 65535) {
      out_log(LEVEL_HIGH, "watchdog: detected infinite loop in list()\n");

      break;
    }

    dir_filename = fs_fileinfo_getname(finfo);

    if (strcmp(dir_filename,".")==0 ||
        strcmp(dir_filename,"..")==0 ||
        is_hidden_file(dir_filename) )
      continue;

    strncpy(ptr_to_buffer, dir_filename, length);

    if (mlst_single_file(buffer, str, context)) {
      out_log(LEVEL_HIGH, "error during mlst_single_file (%s)\n", buffer);

      break;
    }

#ifdef HAVE_UTF8
    if (context->connection_flags & CONNECTION_UTF8)
    {
      /* first, check that line is not already valid UTF-8 */
      if ( !str_is_valid_utf8(str) ) {
        /* use line as a temp buffer */
        if (str_local_to_utf8(str, local_charset()))
        {
          out_log(LEVEL_NORMAL,"Error during UTF-8 conversion for %s\n", str_tochar(str));
        }
      }
    }
#endif

    str_append(str,"\r\n");
    if (list_call_wrapper(sock, context, str_tochar(str), send_buffer, &send_buffer_len, callback)) break;


  }
  /* flush buffer ! */
  list_call_wrapper(sock, context, NULL, send_buffer, &send_buffer_len, callback);

  fs_dir_close(dir);
  str_deallocate(str);

  return 0;
}




static int guess_star(char *str,char *mask) {
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

static int list_match(char *str,char *mask) {
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

