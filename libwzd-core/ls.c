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

#ifdef WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <libwzd-auth/wzd_md5crypt.h>
#include <libwzd-base/strpcpy.h>

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

static char * mlst_format_line(struct wzd_file_t * file_info, fs_filestat_t *s, char * buffer, wzd_context_t * context);

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



int list(fd_t sock,wzd_context_t * context,enum list_type_t format,char *directory,char *mask,
	 int callback(fd_t,wzd_context_t*,char *))
{
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  char * dirname;
  char buffer[WZD_MAX_PATH+1], * ptr_to_buffer;
  char line[WZD_MAX_PATH+80+1]; /* 80 is the long format max */
  char buffer_name[256];
  char send_buffer[HARD_LS_BUFFERSIZE];
  size_t send_buffer_len;
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

  wzd_strncpy(buffer,directory,WZD_MAX_PATH);
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
      wzd_strncpy(line,file->filename,WZD_MAX_PATH);
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
        wzd_strncpy(buffer_ptr,file->filename,WZD_MAX_PATH-(buffer_ptr-buffer));
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
      wzd_strncpy(buffer_name,file->filename,sizeof(buffer_name)-1);
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
        wzd_strncpy(buffer_name, line, sizeof(buffer_name));
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


/* filename must be an ABSOLUTE path
 * return a newly allocated string
 */
char * mlst_single_file(const char *filename, wzd_context_t * context)
{
  struct wzd_file_t * file;
  char *ptr;
  fs_filestat_t s;
  int ret;
  char * str_buffer;

  if (!filename) return NULL;

  ptr = strrchr(filename,'/');
  if (!ptr) return NULL;
  if (ptr+1 != '\0') ptr++;

  /** \bug this kills VFS */
/*  if (fs_file_lstat(filename,&s)) return -1;*/

  file = file_stat(filename,context);
  if (file == NULL) return NULL;

  /** \bug file_stat sets the filename to ".", so we must overwrite it */
  wzd_strncpy(file->filename,filename,sizeof(file->filename));

  ret = fs_file_lstat(filename,&s);
  if (ret) {
    out_log(LEVEL_HIGH,"ERROR while stat'ing file %s, ignoring\n",filename);
    return NULL;
  }

  if (file->kind == 0) {
    if (S_ISDIR(s.mode)) file->kind = FILE_DIR;
    if (S_ISLNK(s.mode)) file->kind = FILE_LNK;
    if (S_ISREG(s.mode)) file->kind = FILE_REG;
  }

  str_buffer = wzd_malloc(HARD_LS_BUFFERSIZE);

  mlst_format_line(file,&s,str_buffer,context);

  return str_buffer;
}

int mlsd_directory(const char * dirname, fd_t sock, int callback(fd_t,wzd_context_t*,char *),
    wzd_context_t * context)
{
  char send_buffer[HARD_LS_BUFFERSIZE];
  char str_buffer[HARD_LS_BUFFERSIZE];
  char * ptr_to_buffer;
  size_t send_buffer_len;
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  fs_filestat_t s;
  char buffer[WZD_MAX_PATH+1];
  char * ptr;
  size_t length;
  int ret;

  if (!dirname || strlen(dirname)<1) return 1;

  dir = dir_open(dirname, context);
  if (dir == NULL) return E_PARAM_INVALID;

  memset(send_buffer,0,HARD_LS_BUFFERSIZE);
  send_buffer_len = 0;

  wzd_strncpy(buffer,dirname,WZD_MAX_PATH);
  length = strlen(buffer);
  if (buffer[length-1]!='/') buffer[length++] = '/';

  ptr = buffer + length; /* points to the terminating \0 */

  while ( (file = dir_read(dir,context)) != NULL ) {
    /* for a VFS, we stat() the destination */
    if (file->kind == FILE_VFS) ptr_to_buffer = file->data;
    else {
      wzd_strncpy(ptr,file->filename,WZD_MAX_PATH-length);
      ptr_to_buffer = buffer;
    }

    ret = fs_file_lstat(ptr_to_buffer,&s);
    if (ret) {
      out_log(LEVEL_HIGH,"ERROR while stat'ing file %s, ignoring\n",buffer);
      continue;
    }

    if (file->kind == 0) {
      if (S_ISDIR(s.mode)) file->kind = FILE_DIR;
      if (S_ISLNK(s.mode)) file->kind = FILE_LNK;
      if (S_ISREG(s.mode)) file->kind = FILE_REG;
    }


    mlst_format_line(file,&s,str_buffer,context);

    strcat(str_buffer,"\r\n"); /* TODO check size */
    if (list_call_wrapper(sock, context, str_buffer, send_buffer, &send_buffer_len, callback)) {
      out_log(LEVEL_HIGH, "error during list_call_wrapper %s\n", str_buffer);
    }

  }

  /* flush buffer ! */
  list_call_wrapper(sock, context, NULL, send_buffer, &send_buffer_len, callback);

  dir_close(dir);

  return 0;
}




static int guess_star(char *str,char *mask) {
  /* pump from here !!! */
  unsigned int i=0;

  if (mask[0]==0) return 1;

  for (;i<strlen(str);i++)
    if (list_match(str+i,mask)) return 1;

  return 0;
}

static int list_match(char *str,char *mask) {
  int i=0;

  /* character per character matching */
  do {
    if (mask[i]=='*') return guess_star(str,mask+1);

    if (mask[i]=='?') {
      if (str[i]!=0) continue;
      else return 0;
    }

    if (mask[i]!=str[i]) return 0;

  } while (mask[++i]!=0);

  if (str[i]==0) return 1;
  else return 0;
}

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

/** \warning no check is done on buffer overflow XXX */
static char * mlst_format_line(struct wzd_file_t * file_info, fs_filestat_t *s, char * buffer, wzd_context_t * context)
{
  char *ptr, *buffer_end;
  wzd_string_t *temp;
  const char *type;

  if (!file_info || !s || !buffer) return NULL;

  temp = str_allocate();
  buffer[0] = '\0';
  buffer_end = buffer;

  ptr = file_info->filename;

  /* Type=... */
  if (file_info && file_info->kind != FILE_NOTSET) {
    switch (file_info->kind) {
      case FILE_REG:
        type = "file"; break;
      case FILE_DIR:
        if (strcmp(ptr,".")==0) type = "cdir";
        else if (strcmp(ptr,"..")==0) type = "pdir";
        else type = "dir";
        break;
      case FILE_LNK:
        type = "OS.unix=slink"; break;
      case FILE_VFS:
        type = "OS.wzdftpd=vfs"; break;
      default:
        type = "unknown"; break;
    }
  } else {
    switch (s->mode & S_IFMT) {
      case S_IFREG:
        type = "file"; break;
      case S_IFDIR:
        if (strcmp(ptr,".")==0) type = "cdir";
        else if (strcmp(ptr,"..")==0) type = "pdir";
        else type = "dir";
        break;
#ifndef WIN32
      case S_IFLNK:
        type = "OS.unix=slink"; break;
#endif
      default:
        type = "unknown"; break;
    }
  }
  buffer_end = strpcpy(buffer_end,"Type=");
  buffer_end = strpcpy(buffer_end,type);
  buffer_end = strpcpy(buffer_end,";");

  /* Size=... */
  {
    str_sprintf(temp,"Size=%" PRIu64 ";",s->size);
    buffer_end = strpcpy(buffer_end,str_tochar(temp));
  }

  /* Modify=... */
  {
    char tm[32];
    strftime(tm,sizeof(tm),"%Y%m%d%H%M%S",gmtime(&s->mtime));

    buffer_end = strpcpy(buffer_end,"Modify=");
    buffer_end = strpcpy(buffer_end,tm);
    buffer_end = strpcpy(buffer_end,";");
  }

  /* Perm=... */
  {
    unsigned long perms;
    char perm_buf[64];
    size_t length=0;

    perms = file_getperms(file_info, context);

    str_sprintf(temp,"Perm=");
    if (file_info && file_info->kind == FILE_REG) {
      if (perms & RIGHT_STOR) perm_buf[length++] = 'a';
      if (perms & RIGHT_RETR) perm_buf[length++] = 'r';
      if (perms & RIGHT_STOR) perm_buf[length++] = 'w';
    }
    if (file_info && file_info->kind == FILE_DIR) {
      if (perms & RIGHT_STOR) perm_buf[length++] = 'c';
      if (perms & RIGHT_CWD)  perm_buf[length++] = 'e';
      if (perms & RIGHT_LIST) perm_buf[length++] = 'l';
      if (perms & RIGHT_MKDIR) perm_buf[length++] = 'm';
      if (perms & RIGHT_STOR) perm_buf[length++] = 'p';
    }
    if (perms & RIGHT_DELE) perm_buf[length++] = 'd';
    if (perms & RIGHT_RNFR) perm_buf[length++] = 'f';

    perm_buf[length++] = ';';
    perm_buf[length++] = '0';
    buffer_end = strpcpy(buffer_end,perm_buf);
  }

  /* Unique=... 
   *
   * we use MD5 hash as unique value (not completely satisfying, but works !
   * 
   * note: MD5 algorithm needs at least (2*sizeof(digest)+1) input data to work,
   * so we pad input to at least 33 bytes
   *
   * FIXME this is really slow !
   */
  {
    char digest[128];
    char input[128];

    memset(digest,0,sizeof(digest));

    /* we need at least 33 bytes of input */
    strncpy(input,ptr,sizeof(input));
    if (strlen(input) < 33) {
      memset(input+strlen(input),66,33-strlen(input));
    }

    md5_hash_r(input, digest, strlen(input));

    buffer_end = strpcpy(buffer_end,"Unique=");
    buffer_end = strpcpy(buffer_end,digest);
    buffer_end = strpcpy(buffer_end,";");
  }

  /* End, append name */
  buffer_end = strpcpy(buffer_end," ");

  /* if ptr is not valid UTF-8, convert it */
#ifdef HAVE_UTF8
    if (context->connection_flags & CONNECTION_UTF8)
    {
      /* first, check that line is not already valid UTF-8 */
      if ( !utf8_valid(ptr,strlen(ptr)) ) {
        char * utf_buf;
        size_t length;

        length = strlen(ptr) + 30; /* we allocate more, small security */
        utf_buf = wzd_malloc(length);
        if (local_charset_to_utf8(ptr, utf_buf, length, local_charset())) {
          out_log(LEVEL_NORMAL,"Error during UTF-8 conversion for %s\n", ptr);
        }
        buffer_end = strpcpy(buffer_end,utf_buf);
        free(utf_buf);
      }
      else
        buffer_end = strpcpy(buffer_end,ptr);
    } else
#endif
      buffer_end = strpcpy(buffer_end,ptr);

  str_deallocate(temp);

  return buffer;
}

