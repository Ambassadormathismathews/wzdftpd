/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

#include <libwzd-core/wzd_types.h>
#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_crc32.h>
#include <libwzd-core/wzd_debug.h>
#include <libwzd-core/wzd_dir.h>
#include <libwzd-core/wzd_file.h>

#include "libwzd_sfv_sfv.h"
#include "libwzd_sfv_main.h"
#include "libwzd_sfv_indicators.h"


/***** SFV CHECK FUNCTIONS *****/


/** inits an sfv struct */
void sfv_init(wzd_sfv_file *sfv)
{
  sfv->comments = NULL;
  sfv->sfv_list = NULL;
}

/** frees contents of a sfv structure */
void sfv_free(wzd_sfv_file *sfv)
{
  int i;

  if(sfv->comments){
    for(i=0;sfv->comments[i];i++){
      free(sfv->comments[i]);
      sfv->comments[i] = NULL;
    }
    free( sfv->comments );
    sfv->comments = NULL;
  }

  if(sfv->sfv_list){
    for(i=0;sfv->sfv_list[i];i++){
      free(sfv->sfv_list[i]->filename);
      sfv->sfv_list[i]->filename = NULL;
      free(sfv->sfv_list[i]);
      sfv->sfv_list[i] = NULL;
    }
    free( sfv->sfv_list );
    sfv->sfv_list = NULL;
  }
  
}


/** parse dir to calculate sfv release stats
-> also manages .bad and .missing
return:
-1 on error
0 no error
*/
int sfv_sfv_update_release_and_get_stats(wzd_release_stats * stats , const char *directory, wzd_sfv_file * sfv )
{
  char *dirbuffer;
  int file,bad,missing;
  size_t dirlen, filelen;
  unsigned int count_ok=0, total_count=0;
  unsigned long cur_st_size;
  double size_total=0;
  struct stat s;
  fd_t fd;
  int i;

  if (sfv->sfv_list == NULL) 
    return -1;
  dirlen = strlen(directory);

  for ( i=0; sfv->sfv_list[i]; i++ ){
    total_count++;
    filelen = strlen(sfv->sfv_list[i]->filename);
    dirbuffer=malloc(dirlen+filelen+15); /* Some extra len for .missing or .bad*/
    if(!dirbuffer) 
      continue;

    memset(dirbuffer,0,dirlen+filelen+15);
    strncpy(dirbuffer,directory,dirlen);
    if (dirbuffer[dirlen-1] != '/') 
      strcat(dirbuffer,"/");
    
    strncat(dirbuffer,sfv->sfv_list[i]->filename,filelen);
    filelen=strlen(dirbuffer);

    file=stat(dirbuffer,&s);        /* if file = 0, file is found */
    if(!file) cur_st_size=(unsigned long) s.st_size;
    strcpy( dirbuffer+filelen,".missing" );
    
    missing=stat(dirbuffer,&s);     /* if missing = 0, missing is found */
    strcpy(dirbuffer+filelen,".bad" );
    bad=stat(dirbuffer,&s);         /* if bad = 0, .bad is found */

    /* file is found and ok */
    if ( file==0 && missing && bad ) {
      size_total += (cur_st_size / 1024.);
      count_ok++;
    }
    else if ( file!=0 ) {
      /*  file is not found */
      if ( missing ){ /* no missing file yet, create one */
        /* create a .missing file */
        strcpy( dirbuffer+filelen, ".missing" );
        fd = open( dirbuffer,O_WRONLY|O_CREAT,0666 );
        if ( fd != -1 )
          close(fd);
      }
    }
    free(dirbuffer);
  }

  stats->files_ok=count_ok;
  stats->files_total=total_count;
  stats->size_total=size_total;

  return 0;
}


/** create / remove ".missing" / ".bad" depending on the result of the test */
int sfv_check_create(const char *filename, wzd_sfv_entry * entry)
{
  char missing[512], bad[512];
  unsigned long real_crc;
  int ret, fd;
  struct stat s;

  if (strlen(filename) > 500)
    return -1;

  strcpy(missing,filename);
  strcpy(bad,filename);
  strcat(missing,".missing");
  strcat(bad,".bad");

  if (stat(filename,&s) && errno==ENOENT) {
    /* missing */
    fd = open(missing,O_WRONLY|O_CREAT,0666);
    if (fd != -1)
      close(fd);
    
    if (!stat(bad,&s)) remove(bad);
    entry->state = SFV_MISSING;
    return 0;
  }
  if (s.st_size == 0) {
    /* remove 0-sized file and treat it as missing */
    remove(filename);
    fd = open(missing,O_WRONLY|O_CREAT,0666);
    if (fd != -1)
      close(fd);
    if (!stat(bad,&s)) remove(bad);
    entry->state = SFV_MISSING;
    return 0;
  }
  
  entry->size = s.st_size;
  real_crc = 0;
  ret = calc_crc32(filename,&real_crc,0,-1);
  if (ret) 
    return -1; /* something weird has happened, crc calc failed, do nothing */

  /* remove any existing .bad file first */
    if (!stat(bad,&s)) remove(bad);

  if (real_crc == entry->crc) {
    /* CRC OK */
    if (!stat(missing,&s)) remove(missing); /* remove also .missing if still there */
    entry->state = SFV_OK;
  } else { /* CRC differs */
    entry->state = SFV_BAD;
    rename( filename , bad ); /* rename to .bad */
  }
  return 0;
}



/** reads sfv file */
int sfv_read(const char *filename, wzd_sfv_file *sfv)
{
  wzd_cache_t * fp;
  struct stat st;
  char buf[BUFSIZ];
  char * ptr;
  char *err_ptr;
  int count_comments=0, count_entries=0;
  size_t length;

  if (stat(filename,&st) < 0) 
    return -1;
  if (!S_ISREG(st.st_mode)) 
    return -1;
  if ((fp=wzd_cache_open(filename,O_RDONLY,0644)) == NULL)
    return -1;

  sfv->comments = malloc(50*sizeof(char*));
  sfv->sfv_list = malloc(50*sizeof(wzd_sfv_entry*));

  while ( wzd_cache_gets(fp,buf,BUFSIZ-1) != NULL) {
/*    if (i == -1) return -1;*/

    ptr = buf;
    length = strlen(buf); /* fgets put a '\0' at the end */
    /* trim trailing space, because fgets keep a \n */
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
      *(ptr+length-1) = '\0';
      length--;
    }
    
    if (length <= 0) 
      continue;
    /* XXX limitation */
    if (length > 512)
      continue;
      
    if (buf[0] == ';') { /* comment */
      /* count_comments + 2 : +1 for the new line to add, +1 to terminate
         array by NULL */
      if ((count_comments + 2 )% 50 == 0)
        sfv->comments = realloc(sfv->comments,(count_comments+50)*sizeof(char*));
      sfv->comments[count_comments] = malloc(length+1);
      strcpy(sfv->comments[count_comments],buf);
      count_comments++;
    } /* comment */
    else { /* entries */
      /* count_entries + 2 : +1 for the new line to add, +1 to terminate
         array by NULL */
      if ((count_entries + 2 )% 50 == 0)
        sfv->sfv_list = realloc(sfv->sfv_list,(count_entries+50)*sizeof(wzd_sfv_entry*));
      
      if (length < 10) 
        continue;
        
      ptr = buf + length - 8;
      *(buf+length-9) = '\0';
      sfv->sfv_list[count_entries] = malloc(sizeof(wzd_sfv_entry));
      sfv->sfv_list[count_entries]->crc = strtoul(ptr,&err_ptr, 16);
      if (*err_ptr != '\0') {
        free(sfv->sfv_list[count_entries]);
        continue;
      }
      sfv->sfv_list[count_entries]->filename = malloc(strlen(buf)+1);
      strcpy(sfv->sfv_list[count_entries]->filename,buf);
      sfv->sfv_list[count_entries]->state = SFV_UNKNOWN;
      sfv->sfv_list[count_entries]->size = 0;
      count_entries++;
    }
  }
  sfv->comments[count_comments] = NULL;
  sfv->sfv_list[count_entries] = NULL;

  wzd_cache_close(fp);
  return 0;
}


/** find sfv file in same dir than file
file must be an ABSOLUTE path to a file
 retun:
 -1 if error
0 if sfv found and file present in sfv, and put crc
1 if no sfv found or sfv found but file not present

NOTE: on success an sfv_free( of wzd_sfv_file *sfv is needed afterwards
 */
int sfv_find_sfv(const char * filename, wzd_sfv_file *sfv, wzd_sfv_entry ** entry)
{
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  char * dirname,*sfv_dir=NULL,*stripped_filename=NULL;
  wzd_context_t * context;
  int ret,status=1;
  size_t len;
  char * ptr;

  context = GetMyContext();

  /* Get the dirname */
  sfv_dir = path_getdirname(filename);
  if (!sfv_dir) 
    return -1;

  /* Get the current filename */
  stripped_filename = path_getbasename(filename, NULL);
  if (!stripped_filename){
    free(sfv_dir);
    return -1;
  }

  dirname = wzd_strdup(sfv_dir);
  dir = dir_open(dirname,context);
  wzd_free(dirname);
  if (!dir){
    free(sfv_dir);
    return -1;
  }

  sfv_init(sfv);

  /* Loop trough dir */
  while ( (file = dir_read(dir,context)) ) {
    len = strlen(file->filename);
    if (len<5) 
      continue;
    ptr=strrchr(file->filename,'.');
    if (!ptr) 
      continue;
    if (!strcasecmp(ptr,".sfv")){ /* sfv found */
      int i;
      char * sfv_file=NULL;
      /* Get full path of dir + sfv name */
      sfv_file = create_filepath(sfv_dir, file->filename);
      if(!sfv_file){
        status=-1;
        break;
      }
      ret = sfv_read(sfv_file,sfv);
#ifdef DEBUG
      out_err(LEVEL_CRITICAL,"sfv file: %s\n",file->filename);
#endif
      free(sfv_file);
      if ( ret == -1 || sfv->sfv_list == NULL) {
        status=-1;
        break;
      }

      /* sfv file found, check if file is in sfv */
      for (i=0; sfv->sfv_list[i]; i++){
        if (DIRCMP(stripped_filename,sfv->sfv_list[i]->filename)==0) {
          *entry = sfv->sfv_list[i];
          status=0;
          break;
        }
      }
      if (status==0) 
        break;
    }
  } /* while dir_read */

  if(status!=0)
    sfv_free(sfv);

  dir_close(dir);
  free(stripped_filename);
  free(sfv_dir);
  return status;
}

/** called after a sfv file is uploaded
sfv_file must be an ABSOLUTE path to a file
retuns -1 if error
0 else
 */
int sfv_process_new(const char *sfv_file, wzd_context_t *context)
{
  wzd_sfv_file sfv;
  char * sfv_dir;
  int i;
  int num_files;

  /* Get the dirname */
  sfv_dir = path_getdirname(sfv_file);
  if (!sfv_dir) return -1;

  sfv_init(&sfv);
  if (sfv_read(sfv_file,&sfv)) {
    sfv_free(&sfv);
    return -1;
  }

  i=0;
  while (sfv.sfv_list[i]){
    char * tmpfile=create_filepath(sfv_dir,sfv.sfv_list[i]->filename);
    if(tmpfile)
      sfv_check_create(tmpfile,sfv.sfv_list[i]);
      free(tmpfile);
    /* Check file ? - means sfv uploaded AFTER files */
    i++;
  }
  num_files = i;

  /* create a dir/symlink to mark incomplete */
  {
    char * incomplete;
    incomplete = c_incomplete_indicator(SfvConfig.incomplete_indicator,sfv_dir,context);
    /* create empty file|dir / symlink ? */
    if (incomplete) {
      if(SfvConfig.incomplete_symlink){
        char * tmpdir;
        tmpdir=create_filepath(sfv_dir,NULL);
        if(tmpdir){
          symlink_create(tmpdir, incomplete);
          free(tmpdir);
        }
      } else {
        int fh = creat(incomplete,0600);
        if(fh !=-1 ) 
          close( fh );
      }
      free(incomplete);
    }
  }


  /* warn user that we await xx files */
  if (sfv_file) {
      log_message("SFV","Got SFV %s. Expecting %d file(s).\"", sfv_file,  num_files );
   }

  {
    wzd_release_stats stats;
    memset(&stats,0,sizeof(wzd_release_stats) );
    sfv_sfv_update_release_and_get_stats( &stats , sfv_dir, &sfv);
    sfv_update_completebar(&stats, sfv_dir, context) ;  
  }
  sfv_free(&sfv);
  free(sfv_dir);
  return 0;
}


/** called after any file is uploaded which doesnt belong to any of the other category's
filename must be an ABSOLUTE path to a file
retuns -1 if error
0 else
 */
int sfv_process_default(const char *filename, wzd_context_t *context)
{
  wzd_sfv_file sfv;
  wzd_sfv_entry *entry=NULL;
  unsigned long real_crc;
  int ret;
  char * sfv_dir;

  ret = sfv_find_sfv(filename,&sfv,&entry);
  if(ret!=0) 
    return -1; /* Dont process if no sfv is found */

#ifdef DEBUG
  out_err(LEVEL_NORMAL,"sfv_hook_postupload user %d file %s, crc %08lX OK\n",context->userid,filename,entry->crc);
#endif

  real_crc = 0;
  ret = calc_crc32(filename,&real_crc,0,-1);
  if (ret){
    sfv_free(&sfv);
    return -1;
  }

  sfv_check_create(filename,entry);

  sfv_dir = path_getdirname(filename);
  if (!sfv_dir){
    sfv_free(&sfv);
    return -1;
  }
    
  {
    wzd_release_stats stats;
    memset(&stats,0,sizeof(wzd_release_stats) );
    sfv_sfv_update_release_and_get_stats( &stats , sfv_dir, &sfv);
    sfv_update_completebar(&stats, sfv_dir, context) ;  
  }
  free(sfv_dir);
  sfv_free(&sfv);
  return 0;
}

