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

#ifdef WIN32
#include <winsock2.h>
#include <direct.h>
#include <io.h>

#include "../../gnu_regex/regex.h"
#else
#include <dirent.h>
#include <sys/types.h>
#include <regex.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_messages.h>
#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_debug.h>
#include <libwzd-core/wzd_dir.h>
#include <libwzd-core/wzd_file.h>

#ifdef HAVE_ZLIB
#include "./minizip/unzip.h"
#endif

#include "libwzd_sfv_zip.h"
#include "libwzd_sfv_indicators.h"

/***** ZIP/DIZ CHECK FUNCTIONS *****/

/** parse dir to calculate zip with diz release stats
-> also manages .bad and .missing
return:
-1 on error
0 no error
*/
int sfv_diz_update_release_and_get_stats(wzd_release_stats * stats , const char *directory, unsigned long files_total)
{
  char *dirbuffer;
  int curfile,bad,missing;
  size_t dirlen, filelen;
  char *dirname;
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  wzd_context_t * context;
  struct stat s;
  char * ptr;
  double size_total=0;
  unsigned long cur_st_size;
  int count_ok=0;

  context = GetMyContext();

  /* Dont set info if total files is not determined */
  if(files_total==0) return -1;

  dirname = wzd_strdup(directory);
  dir = dir_open(dirname,context);
  wzd_free(dirname);
  if (!dir) return -1;

  dirlen=strlen(directory);

  /* Loop trough dir */
  while ( (file = dir_read(dir,context)) ){
    filelen = strlen(file->filename);
    if (filelen<5) continue;

    ptr=strrchr(file->filename,'.');
    if (ptr){
      if ( strcasecmp(ptr,".zip") ) continue;
    } else continue;

    dirbuffer=malloc(dirlen+filelen+15); /* Some extra len for .missing or .bad*/
    if(!dirbuffer) continue;

    memset(dirbuffer,0,dirlen+filelen+15);
    strncpy(dirbuffer,directory,dirlen);
    if (dirbuffer[dirlen-1] != '/') strcat(dirbuffer,"/");
    strncat(dirbuffer,file->filename,filelen);
    filelen=strlen(dirbuffer);

    curfile=stat(dirbuffer,&s);
    if(!curfile) cur_st_size=(unsigned long) s.st_size;
    strncpy(dirbuffer+filelen,".missing",10);
    missing=stat(dirbuffer,&s);
    strncpy(dirbuffer+filelen,".bad",10);
    bad=stat(dirbuffer,&s);

    /* file is found and ok */
    if ( !curfile && missing && bad ) {
      size_total += (cur_st_size / 1024.);
      count_ok++;
    }
    else if ( curfile ) {
      /* else file is not found */
      if ( !bad ) {
        /* A .bad files does exist , remove it*/
        strncpy(dirbuffer+filelen,".bad",10);
        remove(dirbuffer);
      }
      if ( missing ){
        /* create a .missing file */
        strncpy(dirbuffer+filelen,".missing",10);
        close(open(dirbuffer,O_WRONLY|O_CREAT,0666));
      }
    }
    free(dirbuffer);
  }

  dir_close(dir);

  stats->files_ok=count_ok;
  stats->files_total=files_total;
  stats->size_total=size_total;

  return 0;
}


/** search for following patterns in .diz file:
 [xx/15] ,   [01/15] ,  <xx/15> , xx/15 , ...
NOTE: 0 is sometime replaced with O
Returns 0 when no number found
*/
unsigned long GetDizFileTotalCount(char * dizbuffer)
{
  regex_t reg_format;
  regmatch_t regmatch[3];
  char * str_num_files;
  int num_files=0;
  int ret,i;
  char *ptr;

  ret = regcomp(&reg_format, "([0-9xXo0]+)/([0-9o0]+)", REG_EXTENDED);
  if(ret) return 0;

  ptr=dizbuffer;
  ret = regexec(&reg_format,ptr,3,regmatch,0);
  while(!ret){
    /*Check for "/" at the end to catch dates like 01/01/06 */
    if(ptr[regmatch[2].rm_eo]!='/'){
      str_num_files = ptr+regmatch[2].rm_so;
      ptr[regmatch[2].rm_eo] = '\0';
      /* replace oO with 0 */
      for (i=0;str_num_files[i] != '\0';i++){
        if (str_num_files[i] == 'o' || str_num_files[i] == 'O')  str_num_files[i] = '0';
      }
      num_files = atoi(str_num_files);
      if (num_files!=0) break;
    } else {
    ptr+=regmatch[2].rm_eo;
    }
    if(ptr==NULL) break;
    ret = regexec(&reg_format,ptr,3,regmatch,0);
  }

  regfree(&reg_format);
  return num_files;
}

/** called after a zip file is uploaded to check if file is ok
It also checks .diz inside zip for # of files
 zip_file must be an ABSOLUTE path to a file
retuns -1 if error
 0 else
 */
int sfv_check_zip(const char *zip_file, wzd_context_t *context, unsigned long * files_total)
{
#ifdef HAVE_ZLIB
  unsigned char buffer[UNZIP_BUFFER_SIZE];
  char filename_inzip[UNZ_MAXFILENAMEINZIP+1];
  int err;
  unz_file_info finfo;
  unzFile zf;

  /* init files total with 0 */
  *files_total=0;

  /* Open zip file */
  zf =unzOpen(zip_file);
  if(!zf) return -1;

  /* Go to first file */
  err=unzGoToFirstFile(zf);
  if(err!=UNZ_OK){
    unzClose(zf);
    return -1;
  }

  while(err==UNZ_OK){
    /* Get some file info */
    err=unzGetCurrentFileInfo(zf,&finfo,filename_inzip,UNZ_MAXFILENAMEINZIP,0,0,0,0);
    if(err!=UNZ_OK){
      unzClose(zf);
      return -1;
    }
    /* open current file */
    err=unzOpenCurrentFile(zf);
    if(err!=UNZ_OK){
      unzClose(zf);
      return -1;
    }

    if(!strcasecmp(filename_inzip,"file_id.diz") ){
      /* Found .diz file, get files total */
      char * dizfile=malloc(finfo.uncompressed_size+1);
      if(dizfile){
        memset(dizfile,0,finfo.uncompressed_size+1);
        err = unzReadCurrentFile(zf,dizfile,finfo.uncompressed_size);
        if (err >= 0) { /* Extract to memory was ok, now get the info */
          *files_total=GetDizFileTotalCount(dizfile);
        }else {
          unzCloseCurrentFile(zf);
          unzClose(zf);
          return -1;
        }
        free(dizfile);
      }
    } else {
     /* found other file, unzip to check if file is ok */
      do {
        err = unzReadCurrentFile(zf,buffer,UNZIP_BUFFER_SIZE-1);
        if (err < 0){
          unzCloseCurrentFile(zf);
          unzClose(zf);
          return -1;
        }
      } while (err > 0);
    }

    err=unzCloseCurrentFile(zf);
    if(err!=UNZ_OK){
      unzClose(zf);
      return -1;
    }

    err=unzGoToNextFile(zf);
    if (err != UNZ_OK && err !=UNZ_END_OF_LIST_OF_FILE) {
      unzClose(zf);
      return -1;
    }
  }
  unzClose(zf);
#endif /* HAVE_ZLIB */
  return 0;
}

int sfv_process_zip(const char *zip_file, wzd_context_t *context)
{
#ifdef HAVE_ZLIB
  int ret;
  struct stat s;
  unsigned long files_total=0;
  char * directory;
  char * filebuffer;
  size_t len;

  /* Get .bad path + filename*/
  len = strlen(zip_file);
  filebuffer=malloc(len+15); /* Some extra len for .bad*/
  if(!filebuffer) return -1;
  memset(filebuffer,0,len+15);
  strncpy(filebuffer,zip_file,len);
  strncpy(filebuffer+len,".bad",10);

  ret = sfv_check_zip(zip_file,context,&files_total);
  if (ret){
    close(open(filebuffer,O_WRONLY|O_CREAT,0666) );
  } else {
    /* file was ok */
    if (!stat(filebuffer,&s)) remove(filebuffer); /* if .bad exists, remove it */
  }
  free(filebuffer);

  /* no file count found, abort */
  if (files_total==0) return -1;

  directory = path_getdirname(zip_file);
  if(directory) {
    wzd_release_stats stats;
    char * incomplete;

    /* create incomplete indicator */
    incomplete = c_incomplete_indicator(SfvConfig.incomplete_indicator,directory,context);
    /* create empty file|dir / symlink ? */
    if (incomplete){
      if(SfvConfig.incomplete_symlink)
        symlink_create(directory, incomplete);
      else
        close(creat(incomplete,0600) );
      free(incomplete);
    }

    /* update status bar */
    memset(&stats,0,sizeof(wzd_release_stats) );
    sfv_diz_update_release_and_get_stats( &stats , directory, files_total );
    sfv_update_completebar(&stats, directory, context) ;

    free(directory);
  }
#endif
  return 0;
}


/** called after a diz file is uploaded
diz_file must be an ABSOLUTE path to a file
retun:
 -1 if error
0 else
 */
int sfv_process_diz(const char *diz_file, wzd_context_t *context)
{
  char buffer[1024];
  wzd_cache_t * fp;
  char * stripped_dirname;
  int num_files=0;

  fp = wzd_cache_open(diz_file,O_RDONLY,0644);
  if (!fp) {
    wzd_cache_close(fp);
    return -1;
  }
  while ( wzd_cache_gets(fp,buffer,1024-1) ) {
     num_files=GetDizFileTotalCount(buffer);
     if (num_files) {  break; }
  }
  wzd_cache_close(fp);

  /* no file count found in diz file, abort */
  if(num_files==0) return -1;

  stripped_dirname=path_getdirname(diz_file);
  if (stripped_dirname){
    wzd_release_stats stats;
    char * incomplete;

    incomplete = c_incomplete_indicator(SfvConfig.incomplete_indicator,stripped_dirname,context);
    /* create empty file|dir / symlink ? */
    if (incomplete){
      if(SfvConfig.incomplete_symlink)
        symlink_create(stripped_dirname, incomplete);
      else
        close(creat(incomplete,0600) );
      free(incomplete);
    }

    /* update status bar */
    memset(&stats,0,sizeof(wzd_release_stats) );
    sfv_diz_update_release_and_get_stats( &stats , stripped_dirname, num_files );
    sfv_update_completebar(&stats, stripped_dirname , context);

    /* warn user that we await xx files */
    log_message("DIZ","\"%s\" \"Got DIZ %s. Expecting %d file(s).\"",stripped_dirname,stripped_dirname,num_files );
    free(stripped_dirname);
  }

  return 0;
}
