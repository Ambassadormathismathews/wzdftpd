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

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h> /* WZD_MODULE_INIT */
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_file.h>


#include "libwzd_sfv_main.h"
#include "libwzd_sfv_indicators.h"
#include "libwzd_sfv_sfv.h"
#include "libwzd_sfv_zip.h"
#include "libwzd_sfv_site.h"

MODULE_NAME(sfv);
MODULE_VERSION(120);

wzd_sfv_config SfvConfig;

static event_reply_t sfv_event_preupload(const char * args);
int sfv_hook_preupload(unsigned long event_id, const char * username, const char *filename);
static event_reply_t sfv_event_postupload(const char * args);
int sfv_hook_postupload(unsigned long event_id, const char * username, const char *filename);
static event_reply_t sfv_event_rmdir(const char * args);
int sfv_hook_rmdir(unsigned long event_id, const char * username, const char *filename);

/** Unions a path + filename
if no filename is specified it will make the path non / terminated
Caller has to free !
*/
char * create_filepath(const char *dir, const char * file){

  char * output;
  size_t dirlen=0,filelen=0;

  if(!dir) return NULL;

  dirlen=strlen(dir);
  if(file) filelen=strlen(file);

  output=malloc(dirlen+filelen+5);
  if(!output) return NULL;
  memset(output,0,dirlen+filelen+5);
  strncpy(output,dir,dirlen);
  if(file){
    if (output[dirlen-1] != '/') strcat(output,"/");
    strncat(output,file,filelen);
  }
  if (output[dirlen-1]=='/') output[dirlen-1]='\0';

  return output;
}


static int get_all_params(wzd_sfv_config * SfvConfig)
{
  const char * ptr;
  int b, err;

  SfvConfig->incomplete_symlink=0; /* default: false */
  b = config_get_boolean (mainConfig->cfg_file, "sfv", "create_symlinks", &err);
  if (err == CF_OK) SfvConfig->incomplete_symlink = b;

  ptr = config_get_value (mainConfig->cfg_file, "sfv", "progressmeter");
  if (ptr == NULL) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'progressmeter' in section [sfv]\n");
    return 1;
  }
  strncpy(SfvConfig->progressmeter,ptr,255);

  ptr = config_get_value (getlib_mainConfig()->cfg_file, "sfv", "del_progressmeter");
  if (ptr == NULL) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'del_progressmeter' in section [sfv]\n");
    return 1;
  }
  strncpy(SfvConfig->del_progressmeter,ptr,255);

  ptr = config_get_value (getlib_mainConfig()->cfg_file, "sfv", "incomplete_indicator");
  if (ptr == NULL) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'incomplete_indicator' in section [sfv]\n");
    return 1;
  }
  strncpy(SfvConfig->incomplete_indicator,ptr,255);

  ptr = config_get_value (getlib_mainConfig()->cfg_file, "sfv", "other_completebar");
  if (ptr == NULL) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'other_completebar' in section [sfv]\n");
    return 1;
  }
  strncpy(SfvConfig->other_completebar,ptr,255);

  return 0;
}


/**removes the incomplete bar (if exists)  when directory is deleted before upload completed  */
int sfv_remove_incomplete_indicator(const char *dirname, wzd_context_t *context)
{
  char *incomplete;
  char dir[WZD_MAX_PATH+1];

  strncpy(dir,dirname,WZD_MAX_PATH);
  incomplete = c_incomplete_indicator(SfvConfig.incomplete_indicator,dir,context);

  if (incomplete){
    if(SfvConfig.incomplete_symlink)
      symlink_remove(incomplete);
    else
      remove(incomplete);
    free(incomplete);
  }
  return 0;
}


/***** EVENT HOOKS *****/
static event_reply_t sfv_event_preupload(const char * args)
{
  int ret;
  const char * username;
  const char * filename;
  char * str = strdup(args);
  char * end;

  username = strchr(str, '\"') + 1;
  if (!username) {
    free(str);
    return EVENT_ERROR;
  }
  end = strchr(username, '\"');
  if (!end) {
    free(str);
    return EVENT_ERROR;
  }
  *end = '\0';

  filename = strchr(end + 1, '\"') + 1;
  if (!filename) {
    free(str);
    return EVENT_ERROR;
  }
  end = strchr(filename, '\"');
  if (!end) {
    free(str);
    return EVENT_ERROR;
  }
  *end = '\0';
  
  ret = sfv_hook_preupload(EVENT_PREUPLOAD, username, filename);

  free(str);

  return EVENT_OK;
}

int sfv_hook_preupload(unsigned long event_id, const char * username, const char *filename)
{
  wzd_sfv_file sfv;
  wzd_sfv_entry *entry=NULL;
  int ret;
  char *ptr;

  /* check file type */
  ptr=strrchr(filename,'.');
  if (ptr){
    if (!strcasecmp(ptr,".sfv") ) /* do not check sfv files against themselves ... */
      return 0;
  }
  
  ret = sfv_find_sfv(filename,&sfv,&entry);
  switch (ret) {
  case 0:
#ifdef DEBUG
    out_err(LEVEL_FLOOD,"sfv_hook_preupload user %s file %s, ret %d crc %08lX\n",username,filename,ret,entry->crc);
#endif
    break;
  case 1:
#ifdef DEBUG
    out_err(LEVEL_FLOOD,"No sfv found or file not present in sfv\n");
#endif
    break;
  default:
    /* error */
    return -1;
  }
  sfv_free(&sfv);
  return 0;
}

static event_reply_t sfv_event_postupload(const char * args)
{
  int ret;
  const char * username;
  const char * filename;
  char * str = strdup(args);
  char * end;

  username = strchr(str, '\"') + 1;
  if (!username) {
    free(str);
    return EVENT_ERROR;
  }
  end = strchr(username, '\"');
  if (!end) {
    free(str);
    return EVENT_ERROR;
  }
  *end = '\0';

  filename = strchr(end + 1, '\"') + 1;
  if (!filename) {
    free(str);
    return EVENT_ERROR;
  }
  end = strchr(filename, '\"');
  if (!end) {
    free(str);
    return EVENT_ERROR;
  }
  *end = '\0';

  ret = sfv_hook_postupload(EVENT_POSTUPLOAD, username, filename);

  free(str);

  return EVENT_OK;
}


int sfv_hook_postupload(unsigned long event_id, const char * username, const char *filename)
{
  wzd_context_t * context;
  char * ptr;

  context = GetMyContext();

  /* check file type */
  ptr=strrchr(filename,'.');
  if (ptr){
    if ( !strcasecmp(ptr,".sfv") ) /* Process a new sfv file */
      return sfv_process_new(filename,context);
    else if ( !strcasecmp(ptr,".zip") ) /* Process a zip file */
      return sfv_process_zip(filename,context);
    else if ( !strcasecmp(ptr,".diz") ) /* Process a diz file */
      return sfv_process_diz(filename,context);
  }
  /* Default */
  return sfv_process_default(filename,context);
}


static event_reply_t sfv_event_rmdir(const char * args)
{
  int ret;
  const char * username;
  const char * dirname;
  char * str = strdup(args);
  char * end;

  username = strchr(str, '\"') + 1;
  if (!username) {
    free(str);
    return EVENT_ERROR;
  }
  end = strchr(username, '\"');
  if (!end) {
    free(str);
    return EVENT_ERROR;
  }
  *end = '\0';

  dirname = strchr(end + 1, '\"') + 1;
  if (!dirname) {
    free(str);
    return EVENT_ERROR;
  }
  end = strchr(dirname, '\"');
  if (!end) {
    free(str);
    return EVENT_ERROR;
  }
  *end = '\0';

  ret = sfv_hook_rmdir(EVENT_RMDIR, username, dirname);

  free(str);

  return EVENT_OK;
}

int sfv_hook_rmdir(unsigned long event_id, const char * username, const char *dirname)
{

  wzd_context_t * context;

  context = GetMyContext();
  sfv_remove_incomplete_indicator(dirname, context);

  return 0;

}


/***********************/
/* WZD_MODULE_INIT     */
int WZD_MODULE_INIT (void)
{
/*  printf("WZD_MODULE_INIT\n");*/

  if( get_all_params(&SfvConfig) ){
    out_log(LEVEL_CRITICAL,"module sfv: failed to load parameters, check config\n");
    return -1;
  }

  event_connect_function(getlib_mainConfig()->event_mgr,EVENT_PREUPLOAD,sfv_event_preupload,NULL);
  event_connect_function(getlib_mainConfig()->event_mgr,EVENT_POSTUPLOAD,sfv_event_postupload,NULL);
  event_connect_function(getlib_mainConfig()->event_mgr,EVENT_RMDIR,sfv_event_rmdir,NULL);
  {
    const char * command_name = "site_sfv";
    /* add custom command */
    if (commands_add(getlib_mainConfig()->commands_list,command_name,do_site_sfv,NULL,TOK_CUSTOM)) {
      out_log(LEVEL_HIGH,"ERROR while adding custom command: %s\n",command_name);
    }
    
    /* default permission XXX hardcoded */
    if (commands_set_permission(getlib_mainConfig()->commands_list,command_name,"+O")) {
      out_log(LEVEL_HIGH,"ERROR setting default permission to custom command %s\n",command_name);
      /** \bug XXX remove command from   config->commands_list */
    }
  }
  
  out_log(LEVEL_INFO,"INFO module SFV loaded\n");
  return 0;
}

int WZD_MODULE_CLOSE(void)
{
/* Using it does more bad than good
 hook_remove(&getlib_mainConfig()->hook,EVENT_PREUPLOAD,(void_fct)&sfv_hook_preupload);
  hook_remove(&getlib_mainConfig()->hook,EVENT_POSTUPLOAD,(void_fct)&sfv_hook_postupload);
  hook_remove(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&sfv_hook_site);
  */
#ifdef DEBUG
  out_err(LEVEL_INFO,"module sfv: hooks unregistered\n");
#endif
  return 0;
}
