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
#include <ctype.h> /* isdigit */

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
#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_crc32.h>
#include <libwzd-core/wzd_debug.h>
#include <libwzd-core/wzd_dir.h>
#include <libwzd-core/wzd_file.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_user.h>

#include "libwzd_sfv_indicators.h"
#include "libwzd_sfv_main.h"


/** Given a dir it will handle the complete incomplete indicators (including cookies)
Caller needs to free
*** TODO Clean up function
*/
char *c_incomplete_indicator(const char * indicator, const char * currentdir, wzd_context_t * context)
{
  char buffer[2*WZD_MAX_PATH];
  char releasename[128]; /*take max 127 characters for the releasename*/
  size_t length, needed;
  char * out=NULL;
  const char * ptr_in;
  char * ptr_out;
  wzd_user_t * user;
  size_t dirlen;
  char * directory;
  char * ptr;

  user = GetUserByID(context->userid);
  if (!user)
    return NULL;

  dirlen=strlen(currentdir);
  directory=malloc(dirlen+5);
  memset(directory,0,dirlen+5);
  strncpy(directory,currentdir,dirlen);
  if (directory[dirlen-1]=='/')
    directory[dirlen-1]='\0';
  
  /* Get the releasename */
  ptr=strrchr(directory,'/');
  if(!ptr++)
    return NULL;

  /* TODO: check if name is CD1 , CD2 etc, if so than create a name like Release-CD1 */
  strncpy( releasename, ptr ,127 ) ;
  releasename[127]='\0';


  /* Always make dir / terminated */
  strcat(directory,"/");

  length = 0;
  ptr_in = indicator; ptr_out = buffer;

#ifdef WIN32
  if(strncmp(&ptr_in[0],"/",1)==0){  /* replace with current dir if / is used; win32 only */
    needed = strlen(directory);
    length += needed;
    if (length >= 2*WZD_MAX_PATH) {
      out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
      free(directory);
      return NULL;
    }
    memcpy(ptr_out,directory,needed);
    ptr_in +=1; /* 1 strlen /   */
    ptr_out += needed;
  }
  else
#endif
  if(strncmp(&ptr_in[0],".",1)==0){ /* check for ./ and ../ at start  */
    if(strncmp(&ptr_in[1],"./",2)==0){
      needed = strlen(directory);
      length += needed + 3;
      if (length >= 2*WZD_MAX_PATH) {
        out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
        free(directory);
        return NULL;
      }
      memcpy(ptr_out,directory,needed);
      ptr_in +=3; /* 3 strlen ../   */
      ptr_out += needed;
      memcpy(ptr_out,"../",3);
      ptr_out+=3;
    }
    else if (strncmp(&ptr_in[1],"/",1)==0){
      needed = strlen(directory);
      length += needed;
      if (length >= 2*WZD_MAX_PATH) {
        out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
        free(directory);
        return NULL;
      }
      memcpy(ptr_out,directory,needed);
      ptr_in +=2; /* 2 strlen ./   */
      ptr_out += needed;
    } else {
      free(directory);
      return NULL;
    }
  }
  
  /* Current dir not longer needed */
  free(directory);

  
  while ( (*ptr_in) ){
    if (length >= 2*WZD_MAX_PATH) {
      out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
      return NULL;
    }
    if (*ptr_in == '%') {
      if (strncmp(ptr_in,"%userhome",9)==0){
        /* 9 == strlen(%userhome) */
        /* TODO XXX FIXME only print iff homedir exists !! */
        needed = strlen(user->rootpath);
        length += needed;
        if (length >= 2*WZD_MAX_PATH) {
          out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
          return NULL;
        }
        memcpy(ptr_out,user->rootpath,needed);
        ptr_in += 9; /* 9 == strlen(%userhome) */
        ptr_out += needed;
      }
      else if (strncmp(ptr_in,"%grouphome",10)==0){

        wzd_group_t * group;
        if (user->group_num > 0) group = GetGroupByID(user->groups[0]);
        else group = NULL;

        if (group){
          needed = strlen(group->defaultpath);
          length += needed;
          if (length >= 2*WZD_MAX_PATH) {
            out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
            return NULL;
          }
          memcpy(ptr_out,group->defaultpath,needed);
          ptr_in += 10; /* 10 == strlen(%usergroup) */
          ptr_out += needed;
        }
        else return NULL; /* we want user's main group and he has no one ... */
      }
      else if (strncmp(ptr_in,"%releasename",12)==0){
        needed = strlen(releasename);
        length += needed;
        if (length >= 2*WZD_MAX_PATH) {
           out_log(LEVEL_CRITICAL,"libwzd_sfv: buffer size exceeded for indicator %s\n",indicator);
           return NULL;
        }
        memcpy(ptr_out,releasename,needed);
        ptr_in += 12;
        ptr_out += needed;
      } else {
        return NULL;
      }
    } else {
      *ptr_out++ = *ptr_in++;
      length++;
    }
  }
  *ptr_out = '\0';

  out = malloc(length+1);
  strncpy(out,buffer,length+1);
  if (out[strlen(out)-1]=='/') out[strlen(out)-1]='\0';

  return out;
}


/** Converts cookies in complete indicators and create the full path + bar
Caller has to free
NOTE: sfv file MUST be filled !
*** TODO Rewrite and extend
 */
char *c_complete_indicator(const char * indicator, const char * currentdir, wzd_release_stats * stats)
{
  int val1, val2;
  char *out_p;
  const char *m;
  char ctrl[10];
  char output[2048];
  char * buffer;
  int files_total=stats->files_total;
  double size_total=stats->size_total;

  out_p = output;

  for ( ; *indicator ; indicator++ ) if ( *indicator == '%' ) {
    indicator++;
    m = indicator;
    if (*indicator == '-' && isdigit(*(indicator + 1))) indicator += 2;
    while (isdigit(*indicator)) indicator++;
    if ( m != indicator ) {
      snprintf(ctrl, sizeof(ctrl), "%.*s", (int)(indicator - m), m);
      val1 = atoi(ctrl);
      } else {
      val1 = 0;
    }
    
    if ( *indicator == '.' ) {
      indicator++;
      m = indicator;
      if (*indicator == '-' && isdigit(*(indicator + 1))) indicator += 2;
      while (isdigit(*indicator)) indicator++;
      if ( m != indicator ) {
        snprintf(ctrl, sizeof(ctrl), "%.*s", (int)(indicator - m), m);
        val2 = atoi(ctrl);
        } else {
        val2 = 0;
        }
    } else {
      val2 = -1;
    }
    
    switch ( *indicator ) {
    case 'f': out_p += sprintf(out_p, "%*i", val1, files_total); break;
    case 'm': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(size_total / 1024.)); break;
    
    }
  } else *out_p++ = *indicator;

 *out_p = 0;

  buffer=create_filepath(currentdir,output);
  return buffer;
}




/** updates complete bar (erasing preceding one if existing) (for both .diz and .sfv) */
void sfv_update_completebar(wzd_release_stats * stats, const char * directory, wzd_context_t * context)
{
  char *dirname;
  regex_t preg;
  regmatch_t pmatch[1];
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;

  dirname = wzd_strdup(directory);
  dir = dir_open(dirname,context);
  wzd_free(dirname);

  if (!dir) return;

  regcomp( &preg, SfvConfig.del_progressmeter, REG_NEWLINE|REG_EXTENDED );
  /*Look for the old progressmeter and delete if found */
  while ( (file = dir_read(dir,context)) ) {
    if ( regexec( &preg, file->filename, 1, pmatch, 0) == 0 ){
      /* found, remove it  */
      char * oldbar=create_filepath(directory, file->filename);
      if(oldbar){
        rmdir(oldbar);
        free(oldbar);
      }
    }
  }
  regfree(&preg);
  dir_close(dir);

  /*Check status */
  if (stats->files_total==stats->files_ok) {
    /* complete */
    { /* create complete bar */
      char *bardir;
      bardir = c_complete_indicator(SfvConfig.other_completebar,directory,stats);
      if(bardir){
        mkdir(bardir,0755);
        free(bardir);
      }
    }
    
    { /* remove incomplete bar */
      char *incomplete=NULL;
      incomplete = c_incomplete_indicator(SfvConfig.incomplete_indicator,directory,context);
      if (incomplete){
        if(SfvConfig.incomplete_symlink)
          symlink_remove(incomplete);
        else
          remove(incomplete);
        free(incomplete);
      }
    }
    
    { /* log some info */
      wzd_context_t * context;
      wzd_user_t * user;
      char * groupname=NULL;
      char buffer[2048];
      char *ptr;
      int len;
      
      context = GetMyContext();
      user = GetUserByID(context->userid);
      strncpy(buffer,context->currentpath,2048);
      len = strlen(buffer);
      if (buffer[len-1] != '/'){
        buffer[len++]='/';
        buffer[len]='\0';
      }
      strncpy(buffer+len,context->current_action.arg,2048-len);
      ptr = strrchr(buffer,'/');
      if (!ptr){
        return;
      }
      
      *ptr='\0';
      if (user->group_num>0){
        wzd_group_t * group;
        group = GetGroupByID(user->groups[0]);
        if (group) groupname = group->groupname;
      }
      log_message("COMPLETE","\"%s\" \"%s\" \"%s\" \"%s\"",
        buffer, /* ftp-absolute path */
        user->username,
        (groupname)?groupname:"No Group",
        user->tagline
      );
    }
  } else if(stats->files_ok<stats->files_total) {
    /* make progress bar*/
    char * progressdir,*tmpprog;
    int len=strlen(SfvConfig.progressmeter)+16;
    tmpprog=malloc(len);
    if(tmpprog){
      float percent = stats->files_ok * 100.f/stats->files_total;
      snprintf(tmpprog,len-1,SfvConfig.progressmeter,(int)percent);
      progressdir=create_filepath(directory,tmpprog);
      if(progressdir){
        mkdir(progressdir,0755);
        free(progressdir);
      }
      free(tmpprog);
    }
  } 
  /* files_ok > files_total -> ERROR something wrong with .diz OR  some zips in dir which dont belong there */
  else return;

}

