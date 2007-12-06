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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRTOK_R
#include "libwzd-base/wzd_strtok_r.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <io.h>
#else
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/*#include "wzd.h"*/
#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_crc32.h>
#include <libwzd-core/wzd_vfs.h> /* checkpath_new */
#include <libwzd-core/wzd_debug.h>
#include <libwzd-core/wzd_dir.h>
#include <libwzd-core/wzd_file.h>


#include "libwzd_sfv_site.h"
#include "libwzd_sfv_main.h"
#include "libwzd_sfv_sfv.h"


#ifdef HAVE_ZLIB
#include "./minizip/unzip.h"
#endif

/***** SITE SFV FUNCTIONS *****/

/** site help messages */
void do_site_help_sfv(wzd_context_t * context)
{
  char buffer[WZD_MAX_PATH];

  snprintf(buffer,WZD_MAX_PATH,"Syntax error in command SFV\n");
  strcat(buffer," site sfv check sfv_filename\n");
  strcat(buffer," site sfv create sfv_filename\n");
  strcat(buffer," ");
  send_message_with_args(501,context,buffer);
}

/** used for SITE SFV CREATE
returns 0 if all ok
 -1 for other errors
 !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_create(const char * sfv_file)
{
  int ret=0, thisret;
  char * directory,*dirname;
  size_t len;
  char * sfvfile;
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  wzd_sfv_file sfv;
  int i;
  unsigned long crc;
  struct stat s;
  wzd_context_t * context;
  int count_comments=0, count_entries=0;

  context = GetMyContext();

  sfv_init(&sfv);
  sfv.comments = malloc(50*sizeof(char*));
  sfv.sfv_list = malloc(50*sizeof(wzd_sfv_entry*));

  /* Get the dirname */
  directory = path_getdirname(sfv_file);
  if (!directory) return -1;

  dirname = wzd_strdup(directory);
  dir = dir_open(dirname,context);
  wzd_free(dirname);

  if(!dir) {
    free(directory);
    return -1;
  }

  /* Loop trough dir */
  while ( (file = dir_read(dir,context)) ){
    len = strlen(file->filename);
    if (len<5) continue;
    {
      char * ptr=strrchr(file->filename,'.');
      if (ptr){
        /* files that shouldn't be in an sfv */
        if (
          !strcasecmp(ptr,".nfo")||
          !strcasecmp(ptr,".diz")||
          !strcasecmp(ptr,".sfv")||
          !strcasecmp(ptr,".m3u")||
          !strcasecmp(ptr,".jpg")||
          !strcasecmp(ptr,".txt")||
          !strcasecmp(ptr,".bad")||
          !strcasecmp(ptr,".missing")||
          !strcasecmp(ptr,HARD_PERMFILE)
        ) continue;
      }
    }
    /* add to sfv file */
    sfvfile=create_filepath(directory,file->filename);
    if(!sfvfile) break;

    if (stat(sfvfile,&s) || S_ISDIR(s.st_mode)) {
      continue;
      free(sfvfile);
    }
    crc = 0;
    thisret = calc_crc32(sfvfile,&crc,0,-1);
    free(sfvfile);
    /* count_entries + 2 : +1 for the new line to add, +1 to terminate  array by NULL */
    if ((count_entries + 2 )% 50 == 0)
      sfv.sfv_list = realloc(sfv.sfv_list,(count_entries+50)*sizeof(wzd_sfv_entry*));

    sfv.sfv_list[count_entries] = malloc(sizeof(wzd_sfv_entry));
    sfv.sfv_list[count_entries]->crc = crc;
    sfv.sfv_list[count_entries]->filename = strdup(file->filename);
    sfv.sfv_list[count_entries]->state = SFV_OK;
    sfv.sfv_list[count_entries]->size = s.st_size;
    count_entries++;
  } /* while dir_read */

  free(directory);
  dir_close(dir);

  /* Close with NULL pointer */
  sfv.comments[count_comments] = NULL;
  sfv.sfv_list[count_entries] = NULL;

  /* writes file */
  {
    char buffer[2048];
    int fd_sfv;
    fd_sfv = open(sfv_file,O_CREAT | O_WRONLY | O_TRUNC,0644);

    for (i=0; sfv.comments[i]; i++) {
      write(fd_sfv,sfv.comments[i],strlen(sfv.comments[i]));
      write(fd_sfv,"\n",1);
    }

    for (i=0; sfv.sfv_list[i]; i++) {
      if (snprintf(buffer,2047,"%s %lx\n",sfv.sfv_list[i]->filename,
      sfv.sfv_list[i]->crc) <= 0) return -1;
      ret = strlen(buffer);
      if ( write(fd_sfv,buffer,ret) != ret ) {
        out_err(LEVEL_CRITICAL,"Unable to write sfv_file (%s)\n",strerror(errno));
        return -1;
      }
    }

    close(fd_sfv);
  }

  sfv_free(&sfv);
  return 0;
}

/** used for SITE SFV CHECK
returns 0 if all ok
number 0xaaabbb: a == missing files, b == errors
-1 for other errors
!! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_check(const char * sfv_file)
{
  int ret=0, thisret;
  char * ptr;
  char dir[1024];
  char filename[2048];
  wzd_sfv_file sfv;
  int i;
  unsigned long crc;
  struct stat s;

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(dir,sfv_file,1023);
  ptr = strrchr(dir,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  sfv_init(&sfv);
  if (sfv_read(sfv_file,&sfv)) {
    sfv_free(&sfv);
    return -1;
  }

  strcpy(filename,dir);
  ptr = filename + strlen(dir);
  for (i=0; sfv.sfv_list[i]; i++) {
    strcpy(ptr,sfv.sfv_list[i]->filename);
    if (stat(filename,&s) || S_ISDIR(s.st_mode)) {
      ret += 0x1000;
      sfv.sfv_list[i]->state = SFV_MISSING;
    } else {
      crc = 0;
      thisret = calc_crc32(filename,&crc,0,-1);
      if (thisret || crc != sfv.sfv_list[i]->crc) {
      ret ++;
      sfv.sfv_list[i]->state = SFV_BAD;
      } else {
      sfv.sfv_list[i]->state = SFV_OK;
      }
#ifdef DEBUG
out_err(LEVEL_CRITICAL,"file %s calculated: %08lX reference: %08lX\n",filename,crc,sfv.sfv_list[i]->crc);
#endif
    }
    *ptr = '\0';
  }

  sfv_free(&sfv);
  return ret;
}

/** site sfv: add / check / create
check sfv_name
create new_sfv_name
 */
int do_site_sfv(wzd_string_t *commandname, wzd_string_t *param, wzd_context_t *context)
{
  char buffer[WZD_MAX_PATH];
  char * ptr;
  char * command, *name;
  int ret;
  char * command_line;
  wzd_sfv_file sfv;

  command_line = (char*)str_tochar(param); /** \todo convert code to use wzd_string_t */

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help_sfv(context);
    return -1;
  }
  name = strtok_r(NULL," \t\r\n",&ptr);

  if (!name) {
    send_message_raw("501 Error: Specify a filename\n",context);
    return -1;
  }

  /* convert file to absolute path, remember sfv wants ABSOLUTE paths ! */
  if ( (ret = checkpath_new(name,buffer,context)) != E_OK && ret!=E_FILE_NOEXIST ) {
    do_site_help_sfv(context);
    return -1;
  }
  sfv_init(&sfv);

  if (strcasecmp(command,"add")==0) {
    ret = send_message_with_args(200,context,"Site SFV add successful");
  }
  if (strcasecmp(command,"check")==0) {
    ret = sfv_check(buffer);
    if (ret == 0) {
      ret = send_message_with_args(200,context,"All files ok");
    } else if (ret < 0) {
       ret = send_message_with_args(501,context,"Critical error occured");
    }
    else {
      char buf2[128];
      snprintf(buf2,128,"SFV check: missing files %d;  crc errors %d", (ret >> 12),ret & 0xfff);
      ret = send_message_with_args(501,context,buf2);
    }
  }
  if (strcasecmp(command,"create")==0) {
    ret = sfv_create(buffer);
    if (ret == 0) {
      ret = send_message_with_args(200,context,"All files ok");
    } else {
       ret = send_message_with_args(501,context,"Critical error occured");
    }
  }

  sfv_free(&sfv);

  return ret;
}

