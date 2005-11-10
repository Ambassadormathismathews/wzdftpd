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

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <winsock2.h>
#include <process.h> /* _getpid() */
#include <direct.h> /* _rmdir() */
#include <sys/utime.h>
#else
#include <unistd.h>
#include <sys/resource.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <utime.h>

#include <dirent.h> /* opendir, readdir, closedir */
#endif

#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_site.h"
#include "wzd_site_group.h"
#include "wzd_site_user.h"
#include "wzd_vars.h"
#include "wzd_vfs.h"
#include "wzd_file.h"
#include "wzd_fs.h"
#include "wzd_dir.h"
#include "wzd_perm.h"
#include "wzd_mod.h"
#include "wzd_cache.h"

#include <libwzd-auth/wzd_tls.h> /* XXX test only */

#include "wzd_debug.h"

#else /* WZD_USE_PCH */

#ifdef WIN32
# include <sys/utime.h>
#endif

#endif /* WZD_USE_PCH */

extern int serverstop;
extern time_t server_start;

#define	BUFFER_LEN	4096

void do_site_print_file_raw(const char *filename, wzd_context_t *context);

/********************* do_site_test ************************/

int do_site_test(wzd_string_t *command, wzd_string_t *param, wzd_context_t * context)
{
  int ret;

/*  backend_commit_changes();*/
/*if (context->userinfo.flags)
  out_err(LEVEL_CRITICAL,"FLAGS '%s'\n",context->userinfo.flags);*/
#if 0
  {
    wzd_sfv_file sfv;
    char buffer[BUFFER_LEN];
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if ( (ret = checkpath(command,buffer,context)) == 0 ) {
      buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
      sfv_init(&sfv);
      ret = sfv_read(buffer,&sfv);
      sfv_free(&sfv);
      ret = sfv_check(buffer);
    }
  }
#endif
  /* prints some stats */
  out_err(LEVEL_INFO,"# Connections: %d\n",mainConfig->stats.num_connections);
  out_err(LEVEL_INFO,"# Childs     : %d\n",mainConfig->stats.num_childs);
  ret = 0;

  out_err(LEVEL_INFO,"sizeof(wzd_context_t) = %d\n", sizeof(wzd_context_t));
  out_err(LEVEL_INFO,"sizeof(wzd_user_t) = %d\n", sizeof(wzd_user_t));

  fd_dump();

#if 0
  {
    char buffer[WZD_MAX_PATH+1];
    ret = checkpath_new(command, buffer, context);
    if (!ret)
      out_err(LEVEL_INFO,"[%s] => [%s]\n",command,buffer);
    else
      out_err(LEVEL_INFO,"[%s] : error %d\n",command,ret);
  }
#endif

/*  ret = module_unload(&mainConfig->module,command);*/

/*  libtest(); ret = 0; */

#if 0
  {
    wzd_user_t *me = GetUserByID(context->userid);
    ret = check_certificate(me->username,me->userpass);
  }
#endif

#if 0
  {
    fs_dir_t * dir;
    char buffer[WZD_MAX_PATH+1];
    fs_fileinfo_t * finfo;

    ret = checkpath_new(context->currentpath, buffer, context);

    ret = fs_dir_open(buffer,&dir);

    while (!ret) {
      ret = fs_dir_read(dir,&finfo);
    }

    ret = fs_dir_close(dir);

    ret = 0;
  }
#endif

  out_err(LEVEL_CRITICAL,"Ret: %d\n",ret);

  ret = send_message_with_args(200,context,"TEST command ok");
  return 0;
}

/********************* do_site_help ************************/

void do_site_help(const char *site_command, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];

  send_message_raw("501-\r\n",context);
  if (strcasecmp(site_command,"backend")==0) {
    send_message_raw("operations on backend\r\n",context);
    send_message_raw("site backend command backend_name\r\n",context);
    send_message_raw("command can be one of:\r\n",context);
    send_message_raw(" close   (unloads backend)\r\n",context);
    send_message_raw(" commit  (commits changes synchronously)\r\n",context);
    send_message_raw(" init    (loads new backend)\r\n",context);
    send_message_raw(" reload  (close and init)\r\n",context);
    send_message_raw("\r\n",context);
    send_message_raw("e.g: site backend commit plaintext\r\n",context);
    send_message_raw("\r\n",context);
    send_message_raw(" THIS IS A DANGEROUS COMMAND\r\n",context);
  } else
  if (strcasecmp(site_command,"checkperm")==0) {
    send_message_raw("checks access for a user on a file/dir\r\n",context);
    send_message_raw("site checkperm user file rights\r\n",context);
    send_message_raw(" rights can be one of:\r\n",context);
    send_message_raw(" RIGHT_LIST\r\n",context);
    send_message_raw(" RIGHT_CWD\r\n",context);
    send_message_raw(" RIGHT_RETR\r\n",context);
    send_message_raw(" RIGHT_STOR\r\n",context);
    send_message_raw(" RIGHT_RNFR\r\n",context);
    send_message_raw("e.g: site checkperm toto dir RIGHT_CWD\r\n",context);
  } else
  if (strcasecmp(site_command,"chgrp")==0) {
    send_message_raw("change the group of a file or directory\r\n",context);
    send_message_raw("usage: site chgrp group file1 [file2 ...]\r\n",context);
    send_message_raw("e.g: site chgrp admin file1\r\n",context);
  } else
  if (strcasecmp(site_command,"chmod")==0) {
    send_message_raw("change permissions of a file or directory\r\n",context);
    send_message_raw("usage: site chmod mode file1 [file2 ...]\r\n",context);
    send_message_raw("e.g: site chmod 644 file1\r\n",context);
  } else
  if (strcasecmp(site_command,"chown")==0) {
    send_message_raw("change the owner of a file or directory\r\n",context);
    send_message_raw("usage: site chown user file1 [file2 ...]\r\n",context);
    send_message_raw("e.g: site chown toto file1\r\n",context);
  } else
  if (strcasecmp(site_command,"chpass")==0) {
    send_message_raw("change the password of a user\r\n",context);
    send_message_raw("site chpass [user] new_pass\r\n",context);
  } else
  if (strcasecmp(site_command,"grpkill")==0) {
    send_message_raw("kill all connected users from a group\r\n",context);
    send_message_raw("site grpkill groupname\r\n",context);
  } else
  if (strcasecmp(site_command,"link")==0) {
    send_message_raw("create/remove symbolink links\r\n",context);
    send_message_raw("site link create dir linkname\r\n",context);
    send_message_raw("site link remove linkname\r\n",context);
  } else
  if (strcasecmp(site_command,"msg")==0) {
    send_message_raw("manage directory messages\r\n",context);
    send_message_raw("site msg show\r\n",context);
    send_message_raw("site msg new msg_line\r\n",context);
    send_message_raw("site msg append msg_line\r\n",context);
    send_message_raw("site msg convert file\r\n",context);
    send_message_raw("site msg delete\r\n",context);
  } else
  if (strcasecmp(site_command,"perm")==0) {
    send_message_raw("manage permissions\r\n",context);
    send_message_raw("site perm show (show all permissions)\r\n",context);
    send_message_raw("site perm show name (show permissions for commands starting with perm_name)\r\n",context);
    send_message_raw("site perm add name perms\r\n",context);
    send_message_raw("site perm change name perms\r\n",context);
    send_message_raw("site perm remove\r\n",context);
    send_message_raw("\r\n",context);
    send_message_raw("ex: site perm add site_newcmd +O\r\n",context);
  } else
  if (strcasecmp(site_command,"user")==0) {
    send_message_raw("show user info\r\n",context);
    send_message_raw("site user username\r\n",context);
  } else
  if (strcasecmp(site_command,"vars")==0) {
    send_message_raw("access server variables\r\n",context);
    send_message_raw("site vars get varname\r\n",context);
  } else
  if (strcasecmp(site_command,"vars_user")==0) {
    send_message_raw("access user variables\r\n",context);
    send_message_raw("site vars_user get user varname\r\n",context);
  } else
  if (strcasecmp(site_command,"vars_group")==0) {
    send_message_raw("access group variables\r\n",context);
    send_message_raw("site vars_group get group varname\r\n",context);
  } else
  {
    snprintf(buffer,BUFFER_LEN,"Syntax error in command %s\r\n",site_command);
    send_message_raw(buffer,context);
  }
  send_message_raw("501 \r\n",context);
}

/********************* do_site_backend *********************/
/** backend: close / reload / init / commit
 */
int do_site_backend(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * command, *name;
  int ret;

  command = str_tok(command_line," \t\r\n");
  if (!command) {
    do_site_help("backend",context);
    return 1;
  }
  name = str_tok(command_line," \t\r\n");
  if (!name) {
    do_site_help("backend",context);
    str_deallocate(command);
    return 1;
  }
  if (strcasecmp(str_tochar(command),"close")==0) {
    str_deallocate(command);
    ret = backend_close(str_tochar(name));
    if (ret) {
      ret = send_message_with_args(501,context,"Could not close backend");
    } else {
      ret = send_message_with_args(200,context,"Backend close successfully");
    }
    str_deallocate(name);
    return 0;
  } /* close */
  if (strcasecmp(str_tochar(command),"init")==0) {
    str_deallocate(command);
    ret = backend_init(str_tochar(name),0 /* max users */,0 /* max groups */);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not init backend");
    } else {
      ret = send_message_with_args(200,context,"Backend loaded successfully");
    }
    str_deallocate(name);
    return 0;
  } /* init */
  if (strcasecmp(str_tochar(command),"reload")==0) {
    str_deallocate(command);
    ret = backend_reload(str_tochar(name));
    if (ret) {
      ret = send_message_with_args(501,context,"Could not reload backend ** WARNING you could have NO backend NOW");
    } else {
      ret = send_message_with_args(200,context,"Backend reloaded successfully");
    }
    str_deallocate(name);
    return 0;
  } /* reload */
  if (strcasecmp(str_tochar(command),"commit")==0) {
    str_deallocate(command);
    ret = backend_commit_changes(str_tochar(name));
    if (ret) {
      ret = send_message_with_args(501,context,"Could not commit backend");
    } else {
      ret = send_message_with_args(200,context,"Backend commited successfully");
    }
    str_deallocate(name);
    return 0;
  } /* commit */
  do_site_help("backend",context);
  str_deallocate(command);
  str_deallocate(name);
  return 0;
}

/********************* do_site_chacl ***********************/
/** chacl: user mode file1 [file2 ...]
 */

int do_site_chacl(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  wzd_string_t * mode, *username, *filename;
  int ret;
  wzd_user_t * user;
  unsigned long long_perms;
  char str_perms[64];
  char * endptr;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help("chacl",context);
    return 1;
  }
  /* check that username exists */
  user = GetUserByName( str_tochar(username) );
  str_deallocate(username);
  if ( !user ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return 1;
  }
  mode = str_tok(command_line," \t\r\n");
  if (!mode) {
    do_site_help("chacl",context);
    return 1;
  }
  /* TODO check that mode is ok */
  if (strlen(str_tochar(mode)) > 15) {
    do_site_help("chacl",context);
    str_deallocate(mode);
    return 1;
  }
  long_perms = strtoul(str_tochar(mode),&endptr,8);
  if (endptr != str_tochar(mode)) {
    snprintf(str_perms,63,"%c%c%c",
        (long_perms & 01) ? 'r' : '-',
        (long_perms & 02) ? 'w' : '-',
        (long_perms & 04) ? 'x' : '-'
        );
  } else
    strncpy(str_perms,str_tochar(mode),63);
  str_deallocate(mode);

  while ( (filename = str_tok(command_line," \t\r\n")) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (!checkpath(str_tochar(filename),buffer,context))
    {
      _setPerm(buffer,user->username,0,0,str_perms,(unsigned long)-1,context);
    }
    str_deallocate(filename);
  }

  snprintf(buffer,BUFFER_LEN,"acl successfully set");
  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/********************* do_site_chgrp ***********************/
/** chgrp: group file1 [file2 ...]
 */

int do_site_chgrp(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char * buffer;
  wzd_string_t * groupname, *filename;
  int ret;
  wzd_group_t * group;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help("chgrp",context);
    return 1;
  }
  /* check that groupname exists */
  group=GetGroupByName(str_tochar(groupname));
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exists");
    str_deallocate(groupname);
    return 1;
  }

  buffer = malloc(WZD_MAX_PATH+1);

  while ( (filename = str_tok(command_line," \t\r\n")) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (!checkpath(str_tochar(filename),buffer,context))
    {
      _setPerm(buffer,0,0,str_tochar(groupname),0,(unsigned long)-1,context);
    }
    str_deallocate(filename);
  }

  snprintf(buffer,WZD_MAX_PATH,"group changed to '%s'",str_tochar(groupname));
  ret = send_message_with_args(200,context,buffer);

  free(buffer);
  str_deallocate(groupname);
  return 0;
}

/********************* do_site_chmod ***********************/
/** chmod: mode file1 [file2 ...]
 */
int do_site_chmod(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char * buffer;
  char * endptr;
  const char * mode;
  wzd_string_t * str_mode, *filename;
  int ret;
  unsigned long long_perms;

  str_mode = str_tok(command_line," \t\r\n");
  if (!str_mode) {
    do_site_help("chmod",context);
    return 1;
  }
  mode = str_tochar(str_mode);
  /* TODO check that mode is ok */
  if (strlen(mode) > 15) {
    do_site_help("chmod",context);
    str_deallocate(str_mode);
    return 1;
  }
  long_perms = strtoul(mode,&endptr,8);

  if (endptr == mode) {
    unsigned short error = 0, i;
    unsigned int mask = 1 << 8;
    /* try to read perm in text mode ? */
    long_perms = 0;
    for (i = 0; i<3; i++) {
      if (*mode == 'r') { long_perms += mask; }
      else if (*mode != '-') { error = 1; break; }
      mask >>= 1; mode++;
      if (*mode == 'w') { long_perms += mask; }
      else if (*mode != '-') { error = 1; break; }
      mask >>= 1; mode++;
      if (*mode == 'x') { long_perms += mask; }
      else if (*mode != '-') { error = 1; break; }
      mask >>= 1; mode++;
    }

    if (error) {
      ret = send_message_with_args(501,context,"Invalid permission");
      str_deallocate(str_mode);
      return 0;
    }
  }
  str_deallocate(str_mode);

  buffer = malloc(WZD_MAX_PATH+1);

  while ( (filename = str_tok(command_line," \t\r\n")) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (!checkpath_new(str_tochar(filename),buffer,context)) {
      _setPerm(buffer,0,0,0,0,long_perms,context);
    }
    str_deallocate(filename);
  }

  snprintf(buffer,WZD_MAX_PATH,"mode changed to '%lo'",long_perms);
  ret = send_message_with_args(200,context,buffer);

  free(buffer);
  return 0;
}

/********************* do_site_chown ***********************/
/** chown: user file1 [file2 ...]
 */

int do_site_chown(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char * buffer;
  wzd_string_t * username, *filename;
  int ret;
  wzd_user_t  *user;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help("chown",context);
    return 1;
  }
  /* check that username exists */
  user = GetUserByName(str_tochar(username));
  if ( !user ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return 1;
  }

  buffer = malloc(WZD_MAX_PATH+1);

  while ( (filename = str_tok(command_line," \t\r\n")) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (!checkpath_new(str_tochar(filename),buffer,context))
    {
      _setPerm(buffer,0,str_tochar(username),0,0,(unsigned long)-1,context);
    }
    str_deallocate(filename);
  }

  snprintf(buffer,WZD_MAX_PATH,"owner changed to '%s'",str_tochar(username));
  ret = send_message_with_args(200,context,buffer);

  free(buffer);
  str_deallocate(username);
  return 0;
}

/********************* do_site_chpass **********************/
/** chpass: [user] new_pass
 *   siteops can change everyones password
 *   gadmins can change the groups password
 *   everyone can change their own password
 *   noone can change a siteops password except himself
 */
int do_site_chpass(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * username, *new_pass;
  int ret;
  wzd_user_t *user, *me;
  short is_gadmin;
  unsigned long mod_type;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help("chpass",context);
    return 1;
  }
  new_pass = str_tok(command_line," \t\r\n");
  if (!new_pass) { /* assume changing own password */
    new_pass = username;
    username = NULL;
    user = me;
  }
  else {
    /* check that username exists */
    user = GetUserByName(str_tochar(username));
    str_deallocate(username);
    username = NULL;
    if ( !user ) {
      ret = send_message_with_args(501,context,"User does not exists");
      str_deallocate(username); str_deallocate(new_pass);
      return 1;
    }
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user->group_num==0 || me->groups[0]!=user->groups[0]) {
      ret = send_message_with_args(501,context,"You can't change this user");
      str_deallocate(username); str_deallocate(new_pass);
      return 1;
    }
  }
  else {
    if ( !(me->flags && strchr(me->flags,FLAG_SITEOP)) 
        && me->uid != user->uid )
    {
      ret = send_message_with_args(501,context,"You can't change password for other users");
      str_deallocate(username); str_deallocate(new_pass);
      return 1;
    }
  }
  if ( (user->flags && strchr(user->flags,FLAG_SITEOP)) 
      && me->uid != user->uid )
  {
    ret = send_message_with_args(501,context,"You can't change password for a siteop");
    str_deallocate(username); str_deallocate(new_pass);
    return 1;
  }

  mod_type = _USER_USERPASS;
  strncpy(user->userpass,str_tochar(new_pass),sizeof(user->userpass));
  str_deallocate(new_pass);

  /* commit to backend */
  ret = backend_mod_user(mainConfig->backend.name,user->username,user,mod_type);

  if (ret)
    ret = send_message_with_args(501,context,"An error occurred during password change");
  else
    ret = send_message_with_args(200,context,"Password changed");
  return 0;
}

/********************* do_site_checkperm *******************/
int do_site_checkperm(wzd_string_t *ignored, wzd_string_t * commandline, wzd_context_t * context)
{
  unsigned long word;
  char * buffer;
  wzd_string_t *username, *filename, *perms;
  wzd_user_t *user;

  username = str_tok(commandline," \t\r\n");
  if (!username) { do_site_help("checkperm",context); return 1; }
  filename = str_tok(commandline," \t\r\n");
  if (!filename) {
    str_deallocate(username);
    do_site_help("checkperm",context);
    return 1;
  }
  perms = str_tok(commandline,"\r\n");
  if (!perms) {
    str_deallocate(username); str_deallocate(filename);
    do_site_help("checkperm",context);
    return 1;
  }

  word = right_text2word(str_tochar(perms));
  str_deallocate(perms);
  if (word == 0) {
    str_deallocate(username); str_deallocate(filename);
    send_message_with_args(501,context,"Invalid permission");
    return 1;
  }

  user = GetUserByName(str_tochar(username));
  str_deallocate(username);
  if ( !user ) {
    str_deallocate(filename);
    send_message_with_args(501,context,"User does not exist");
    return 1;
  }

  buffer = malloc(WZD_MAX_PATH+1);

  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(str_tochar(filename),buffer,context)) {
    send_message_with_args(501,context,"file does not exist");
    str_deallocate(filename);
    free(buffer);
    return 1;
  }
  str_deallocate(filename);

/*  buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */

  if (_checkPerm(buffer,word,user)==0) {
    wzd_strncpy(buffer,"right ok",WZD_MAX_PATH);
  } else {
    wzd_strncpy(buffer,"refused",WZD_MAX_PATH);
  }

  send_message_with_args(200,context,buffer);
  free(buffer);
  return 0;
}

/********************* do_site_free ************************/
/** free sectionname
 */

int do_site_free(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context)
{
  char * buffer;
  int ret;
/*  char * ptr;
  char * sectionname;
  wzd_user_t user;
  int uid;
  wzd_context_t user_context;*/
  long f_type, f_bsize, f_blocks, f_free;
  float freeb,totalb;
  char unit;

/*  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("user",context);
    return;
  }*/

  buffer = malloc(WZD_MAX_PATH+1);

  if (checkpath_new(".",buffer,context)) {
    send_message_with_args(501,context,". does not exist ?!");
    free(buffer);
    return -1;
  }

  ret = get_device_info(buffer,&f_type, &f_bsize, &f_blocks, &f_free);

  unit='k';
  freeb = f_free*(f_bsize/1024.f);
  totalb = f_blocks*(f_bsize/1024.f);

  if (totalb > 1000.f) {
    unit='M';
    freeb /= 1024.f;
    totalb /= 1024.f;
  }
  if (totalb > 1000.f) {
    unit='G';
    freeb /= 1024.f;
    totalb /= 1024.f;
  }

  snprintf(buffer,WZD_MAX_PATH,"[FREE] + [current dir: %.2f / %.2f %c] -",freeb,totalb,unit);

  ret = send_message_with_args(200,context,buffer);

  free(buffer);
  return 0;
}

/********************* do_site_invite **********************/
/** invite: ircnick
 */
int do_site_invite(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * ircnick;
  int ret;
  wzd_user_t *user;
  wzd_group_t *group;
  char buffer[2048], path[2048];

  ircnick = str_tok(command_line," \t\r\n");
  if (!ircnick) {
    do_site_help("invite",context);
    return 1;
  }
  /* TODO check that user is allowed to be invited ? */
  user = GetUserByID(context->userid);
  group = GetGroupByID(user->groups[0]);

  strncpy(buffer,context->currentpath,sizeof(buffer));
  stripdir(buffer,path,2047);

  log_message("INVITE","\"%s\" \"%s\" \"%s\" \"%s\"",
      path, /* ftp-absolute path */
      user->username,
      (group->groupname)?group->groupname:"No Group",
      ircnick);

  ret = send_message_with_args(200,context,"SITE INVITE command ok");
  str_deallocate(ircnick);
  return 0;
}

/********************* do_site_link ************************/
/** link: create dir linkname
  * link: remove linkname
  */

int do_site_link(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer_dir[BUFFER_LEN], buffer_link[BUFFER_LEN];
  wzd_string_t * dirname, *linkname;
  wzd_string_t * command;
  int ret;

  command = str_read_token(command_line);
  if (!command) {
    do_site_help("link",context);
    return 1;
  }
  dirname = str_read_token(command_line);
  if (!dirname) {
    do_site_help("link",context);
    str_deallocate(command);
    return 1;
  }
 
  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(str_tochar(dirname),buffer_dir,context)) {
    ret = send_message_with_args(501,context,"dirname is invalid");
    str_deallocate(command); str_deallocate(dirname);
    return 0;
  }
  str_deallocate(dirname);
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */

  if (strcasecmp(str_tochar(command),"CREATE")==0)
  {
    linkname = str_read_token(command_line);
    if (!linkname) {
      do_site_help("link",context);
      str_deallocate(command);
      str_deallocate(linkname);
      return 1;
    }
    if (checkpath(str_tochar(linkname),buffer_link,context)) {
      ret = send_message_with_args(501,context,"linkname is invalid");
      str_deallocate(command);
      str_deallocate(linkname);
      return 0;
    }
    str_deallocate(linkname);
    ret = symlink_create(buffer_dir, buffer_link);
  }
  else if (strcasecmp(str_tochar(command),"REMOVE")==0)
  {
    ret = symlink_remove(buffer_dir);
  }
  else {
    do_site_help("link",context);
    str_deallocate(command);
    return 1;
  }

  ret ? send_message_with_args(501,context,"command_failed") : send_message_with_args(200,context,"command ok");
  str_deallocate(command);

  return 0;
}


/********************* do_site_msg *************************/
/** msg: show
 *       new msg_line
 *       append msg_line
 *       convert filename
 *       delete
 */
int do_site_msg(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
/*  int ret;*/
  wzd_string_t * command, * filename;
  char msg_file[2048];
  char other_file[2048];
  unsigned int length;
  fs_filestat_t s;

  if (!mainConfig->dir_message) {
    send_message_with_args(501,context,"no dir_message defined in config");
    return 1;
  }

  if (checkpath_new(".",msg_file,context)) {
    send_message_with_args(501,context,". does not exist ?!");
    return 1;
  } else {
    length = strlen(msg_file);
    if (msg_file[length-1] != '/') msg_file[length++] = '/'; /** \bug now we are _sure_ that checkpath_new appends a / so we can remove check ? */
    strncpy(other_file,msg_file,2048);
    strncpy(msg_file+length,mainConfig->dir_message,2048-length-1);
  }

  command = str_tok(command_line," \t\r\n");
  if (!command) {
    do_site_help("msg",context);
    return 1;
  }

  if (strcasecmp(str_tochar(command),"show")==0)
  {
    str_deallocate(command);
    do_site_print_file_raw(msg_file,context);
    return 0;
  }
  else if (strcasecmp(str_tochar(command),"convert")==0)
  {
    str_deallocate(command);
    filename = str_tok(command_line,"\r\n");
    if (!filename) {
      do_site_help("msg",context);
      return 1;
    }
    strncpy(other_file+length,str_tochar(filename),2048-length-1);
    str_deallocate(filename);
    if (fs_file_stat(other_file,&s) || !S_ISREG(s.mode))
    {
      send_message_with_args(501,context,"inexistant file, or not a regular file");
      return -1;
    }
    unlink(msg_file);
    if (!safe_rename(other_file,msg_file))
    {
      send_message_with_args(200,context,"message file loaded");
      return 0;
    }
    send_message_with_args(501,context,"error while renaming file");
    return -1;
  }
  else if (strcasecmp(str_tochar(command),"delete")==0)
  {
    str_deallocate(command);
    unlink(msg_file);
    send_message_with_args(200,context,"message file deleted");
    return 0;
  }
  else if (strcasecmp(str_tochar(command),"new")==0)
  {
    FILE * fp;
    wzd_string_t * buf;
    unsigned int length;

    str_deallocate(command);
    fp = fopen(msg_file,"w");
    if (!fp) {
      send_message_with_args(501,context,"unable to open message file for writing");
      return 1;
    }
    buf = str_tok(command_line,"\r\n");
    if (!buf) {
      fclose(fp);
      do_site_help("msg",context);
      return 1;
    }
    length = strlen(str_tochar(buf));
    if (length != fwrite(str_tochar(buf),1,length,fp)) {
      fclose(fp);
      send_message_with_args(501,context,"unable to write message");
      str_deallocate(buf);
      return 1;
    }
    fclose(fp);
    send_message_with_args(200,context,"message file written");
    str_deallocate(buf);
    return 0;
  }
  else if (strcasecmp(str_tochar(command),"append")==0)
  {
    FILE * fp;
    wzd_string_t * buf;
    unsigned int length;

    str_deallocate(command);
    fp = fopen(msg_file,"a");
    if (!fp) {
      send_message_with_args(501,context,"unable to open message file for writing");
      return 1;
    }
    buf = str_tok(command_line,"\r\n");
    if (!buf) {
      fclose(fp);
      do_site_help("msg",context);
      return 1;
    }
    length = strlen(str_tochar(buf));
    if (length != fwrite(str_tochar(buf),1,length,fp)) {
      fclose(fp);
      send_message_with_args(501,context,"unable to write message");
      str_deallocate(buf);
      return 1;
    }
    fclose(fp);
    send_message_with_args(200,context,"message file written");
    str_deallocate(buf);
    return 0;
  }

  do_site_help("msg",context);
  str_deallocate(command);
  return 0;
}

static int subcmp(const char * string, const char * substring)
{
  return strncasecmp(string,substring,strlen(substring));
}



/********************* do_site_perm ************************/
/** perm: show  (show all permissions)
 *        show perm_name  (show permissions for all commands starting with perm_name)
 *        add perm_name perms
 *        change perm_name perms
 *        remove perm_name
 * XXX FIXME sort perms before sending !
 */
int do_site_perm(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
/*  int ret;*/
  wzd_string_t * command_name, * perm_name, * ptr;
  char perm_buffer[256];
  char buffer[2048];
  wzd_command_t * command;
  int ret;

  command_name = str_tok(command_line," \t\r\n");
  if (!command_name) {
    do_site_help("perm",context);
    return 1;
  }
  perm_name = str_tok(command_line," \t\r\n");

  if (strcasecmp(str_tochar(command_name),"show")==0)
  {
    str_deallocate(command_name);
    send_message_raw("200-\r\n",context);
    if ( !perm_name ) {
      /* no argument: print all perms */
      List * list;
      ListElmt * elmnt;

      list = chtbl_extract(mainConfig->commands_list, NULL, NULL, (cmp_function)strcmp);

      if (list) {
        for (elmnt=list_head(list); elmnt; elmnt=list_next(elmnt)) {
          command = list_data(elmnt);
          if (command && !perm2str(command->perms,perm_buffer,sizeof(perm_buffer)) ) {
            snprintf( buffer, sizeof(buffer), " %s%s\r\n", command->name, perm_buffer);
            send_message_raw(buffer,context);
          }
        }
        list_destroy(list);
        free(list);
      }
    } else {
      /* search on perms name */
      int found=0;
      List * list;
      ListElmt * elmnt;

      list = chtbl_extract(mainConfig->commands_list, (cmp_function)subcmp, str_tochar(perm_name), (cmp_function)strcmp);

      if (list) {
        if (list_size(list)>0) found=1;
        for (elmnt=list_head(list); elmnt; elmnt=list_next(elmnt)) {
          command = list_data(elmnt);
          if (command && !perm2str(command->perms,perm_buffer,sizeof(perm_buffer)) ) {
            snprintf( buffer, sizeof(buffer), " %s%s\r\n", command->name, perm_buffer);
            send_message_raw(buffer,context);
          }
        }
        list_destroy(list);
        free(list);
      }
      if (!found)
        send_message_raw(" permission not found\r\n",context);
      str_deallocate(perm_name);
    }
    send_message_raw("200 \r\n",context);
    return 0;
  }
  else if (strcasecmp(str_tochar(command_name),"change")==0)
  {
    str_deallocate(command_name);
    ptr = str_tok(command_line,"\r\n");
    if (!perm_name || !ptr) {
      do_site_help("perm",context);
      str_deallocate(perm_name);
      return 1;
    }

    ret = commands_set_permission(mainConfig->commands_list,str_tochar(perm_name),str_tochar(ptr));

    str_deallocate(perm_name);
    str_deallocate(ptr);
    if (ret) {send_message_with_args(501,context,"error changing permission"); return 1; }
    send_message_with_args(200,context,"command ok, permission changed");
    return -1;
  }
  else if (strcasecmp(str_tochar(command_name),"remove")==0)
  {
    str_deallocate(command_name);
    if (!perm_name) {
      do_site_help("perm",context);
      return 1;
    }
    if ( commands_delete_permission(mainConfig->commands_list,perm_name) )
      send_message_with_args(501,context,"error, permission NOT deleted");
    else
      send_message_with_args(200,context,"command ok, permission deleted");
    str_deallocate(perm_name);
    return 0;
  }
  else if (strcasecmp(str_tochar(command_name),"add")==0)
  {
    str_deallocate(command_name);
    ptr = str_tok(command_line,"\r\n");
    if (!perm_name || !ptr) {
      do_site_help("perm",context);
      str_deallocate(perm_name); str_deallocate(ptr);
      return 1;
    }

    ret = commands_add_permission(mainConfig->commands_list,str_tochar(perm_name),str_tochar(ptr));

    str_deallocate(perm_name);
    str_deallocate(ptr);
    if (ret) {send_message_with_args(501,context,"error adding permission"); return 1; }
    send_message_with_args(200,context,"command ok, permission changed");
    return 0;
  }

  do_site_help("perm",context);
  str_deallocate(command_name);
  str_deallocate(perm_name);
  return 0;
}


/********************* do_site_print_file ******************/
/** Print filename to control connection. Cookies are replaced as usual.
 */
void do_site_print_file(const char *filename, wzd_user_t *user, wzd_group_t *group, wzd_context_t *context)
{
  wzd_cache_t * fp;
  char * file_buffer;
  unsigned int size, filesize;
  u64_t sz64;
  fp = wzd_cache_open(filename,O_RDONLY,0644);
  if (!fp) {
    send_message_with_args(501,context,"Inexistant file");
    return;
  }
  sz64 = wzd_cache_getsize(fp);
  if (sz64 > INT_MAX) {
    out_log(LEVEL_HIGH,"%s:%d couldn't allocate" PRIu64 "bytes for file %s\n",__FILE__,__LINE__,sz64,filename);
	wzd_cache_close(fp);
	send_message_with_args(501,context,"Internal error (see log)");
	return;
  }
  filesize = (unsigned int)sz64;
  file_buffer = malloc(filesize+1);
  if ( (size=wzd_cache_read(fp,file_buffer,filesize))!=filesize )
  {
    out_err(LEVEL_HIGH,"Could not read file %s read %u instead of %u (%s:%d)\n",filename,size,filesize,__FILE__,__LINE__);
    free(file_buffer);
    wzd_cache_close(fp);
	send_message_with_args(501,context,"Internal error (see log)");
    return;
  }
  file_buffer[filesize]='\0';

  /* send header */
  send_message_raw("200-\r\n",context);

  cookie_parse_buffer(file_buffer,user,group,context,NULL,0);

  wzd_cache_close(fp);

  send_message_raw("200 \r\n",context);

  free(file_buffer);
}

/********************* do_site_print_file_raw **************/
/** Print filename to control connection, without replacing cookies.
 */
void do_site_print_file_raw(const char *filename, wzd_context_t *context)
{
  wzd_cache_t * fp;
  char buffer[1024];
  unsigned int length;

  fp = wzd_cache_open(filename,O_RDONLY,0644);
  if (!fp) {
    send_message_with_args(501,context,"Inexistant file");
    return;
  }

  /* send header */
  send_message_raw("200--\r\n",context);

  strncpy(buffer,"200-",5);
  while (wzd_cache_gets(fp, buffer+4, sizeof(buffer)-8))
  {
    chop(buffer);
    length = strlen(buffer);
    buffer[length  ] = '\r';
    buffer[length+1] = '\n';
    buffer[length+2] = '\0';
    send_message_raw(buffer,context);
  }

  wzd_cache_close(fp);

  send_message_raw("200 -\r\n",context);
}

/********************* do_site_reload **********************/

int do_site_reload(wzd_string_t * ignored, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  pid_t pid;
#ifndef WIN32
  char buffer[256];
#endif

#ifdef WZD_MULTIPROCESS
  pid = getppid();
#else
  pid = getpid();
#endif
  if (pid <2) {
    ret = send_message_with_args(501,context,"ARG ! Getting invalid pid ?!");
    return 1;
  }
  out_log(LEVEL_CRITICAL,"Target pid: %d\n",pid);

#ifndef WIN32
  ret = send_message_raw("200-Sending SIGHUP to main server, waiting for result\r\n",context);
  ret = kill(pid,SIGHUP);
  if (ret)
    snprintf(buffer,255,"200 ERROR kill returned %d (%s)\r\n",ret,strerror(errno));
  else
    snprintf(buffer,255,"200 kill returned ok\r\n");
  ret = send_message_raw(buffer,context);
#else
  /* FIXME VISUAL : call server_restart explicitely ? */
  /*ret = send_message_with_args(501,context,"kill(getpid(),SIGHUP) not supported on visual ...");*/
  ret = send_message_with_args(501, context, "restarting server, cross your fingers ...");
  server_restart(SIGHUP);
  return 1;
#endif
  return 0;
}

/********************* do_site_rusage **********************/

int do_site_rusage(wzd_string_t * ignored, wzd_string_t *param, wzd_context_t * context)
{
#ifndef WIN32
  int ret=0;
  char buffer[256];
  struct rusage ru;
  struct rlimit rlim;

  send_message_raw("200-\r\n",context);

  if (getrusage(RUSAGE_SELF,&ru)<0)
  {
    ret=errno; /* save errno value */
    send_message_raw("200- getrusage() failed !\r\n",context);
    snprintf(buffer,255,"200-errno: %d (%s)\r\n",ret,strerror(ret));
    send_message_raw(buffer,context);
    send_message_raw("200 \r\n",context);
    return 0;
  }
  send_message_raw("200- Ressources used for wzdftpd:\r\n",context);
  sprintf(buffer,"200-  user time used: %ld s %ld ms\r\n",ru.ru_utime.tv_sec,ru.ru_utime.tv_usec/1000);
  send_message_raw(buffer,context);
  sprintf(buffer,"200-  system time used: %ld s %ld ms\r\n",ru.ru_stime.tv_sec,ru.ru_stime.tv_usec/1000);
  send_message_raw(buffer,context);
  /* system time used */
  /* maximum resident set size */
  /* integral shared memory size */
  /* integral unshared data size */
  /* integral unshared stack size */
  /* page reclaims */
  /* page faults */
  /* swaps */
  /* block input operations */
  /* block output operations */
  /* messages sent */
  /* messages received */
  /* signals received */
  /* voluntary context switches */
  /* involuntary context switches */

  /* Number of opened files:
   *  LINUX: read directory  /proc/`getpid()`/fd/
   *    contains symlinks, destination is file
   */
#ifdef __linux__
  {
    char dirname[256], buflink[256];
    unsigned int childs[256];
    unsigned int child;
    pid_t mother;
    DIR * d;
    struct dirent *dent;
    int count, rdi, fdcount;

    send_message_raw("200- LINUX specific:\r\n",context);
    mother = getpid();
    sprintf(buffer,"200-  mother pid: %ld\r\n",(long)mother);
    send_message_raw(buffer,context);

    /* searching for child threads */
    count = 0;
    snprintf(dirname,sizeof(dirname),"/proc/%ld/task",(long)mother); /** \todo XXX 2.6 specific ? */
    d = opendir(dirname);
    if (d) {
      while ( (dent = readdir(d)) ) {
        if (dent->d_name[0] == '.') continue;
        child = atoi(dent->d_name);
        childs[count] = child;
        count ++;
        sprintf(buffer,"200-   |-> child pid: %s\r\n",dent->d_name);
        send_message_raw(buffer,context);
      }
      closedir(d);
    }

    sprintf(buffer,"200-  resources for: %d\r\n",mother);
    send_message_raw(buffer,context);
    snprintf(dirname,sizeof(dirname),"/proc/%d/task/%d/fd",mother,mother); /** \todo XXX 2.6 specific ? */
    d = opendir(dirname);
    if (d) {
      fdcount = 0;
      while ( (dent = readdir(d)) ) {
        if (dent->d_name[0] == '.') continue;
        fdcount ++;
        snprintf(dirname,sizeof(dirname),"/proc/%d/task/%d/fd/%s",mother,mother,dent->d_name); /** \todo XXX 2.6 specific ? */
        rdi = readlink(dirname,buflink,sizeof(buflink));
        if (rdi > 0) {
          buflink[rdi] = '\0';
          sprintf(buffer,"200-   |-> %s -> %s\r\n",dent->d_name,buflink);
          send_message_raw(buffer,context);
        }
      }
      closedir(d);

      sprintf(buffer,"200-  number of open files: %d\r\n",fdcount);
      send_message_raw(buffer,context);
    }
  }
#endif /* __linux__ */

  if (getrlimit(RLIMIT_NOFILE,&rlim)<0) {
    send_message_raw("200- getrlimit(RLIMIT_NOFILE) failed !\r\n",context);
    snprintf(buffer,255,"200-errno: %d (%s)\r\n",ret,strerror(ret));
    send_message_raw(buffer,context);
    send_message_raw("200 \r\n",context);
    return 0;
  }

  send_message_raw("200- LIMITS:\r\n",context);
  sprintf(buffer,"200-  number of open files: %ld ; max: %ld\r\n",(long)rlim.rlim_cur,(long)rlim.rlim_max);
  send_message_raw(buffer,context);

  send_message_raw("200 \r\n",context);
#else /* _MSC_VER */
  send_message_with_args(501,context,"can't be implemented on win32 !");
#endif /* _MSC_VER */
  return 0;
}

/********************* do_site_savecfg *********************/
int do_site_savecfg(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  send_message_with_args(501,context,"Not yet implemented");
  return 1;

#if 0
  if( wzd_savecfg() )
    send_message_with_args(501,context,"Cannot save server config");
  else
    send_message_with_args(200,context,"Server config saved");
  return 0;
#endif
}

/********************* do_site_sections ******************/
/** Print all sections
 */
int do_site_sections(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_section_t * section;
  wzd_string_t * buffer = str_allocate();

  /* send header */
  send_message_raw("200-\r\n",context);
  send_message_raw(" NAME  MASK  REGEX\r\n",context);

  for (section = mainConfig->section_list; section; section = section->next_section) {
    str_sprintf(buffer, " %s  %s  %s\r\n", section->sectionname, section->sectionmask, section->sectionre);
    send_message_raw(str_tochar(buffer), context);
  }

  send_message_raw("200 \r\n",context);
  str_deallocate(buffer);

  return 0;
}

/********************* do_site_unlock **********************/
/** unlock: file1 [file2 ...]
 */

int do_site_unlock(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  wzd_string_t * filename;
  int ret=0;

  filename = str_tok(command_line," \t\r\n");
  if (!filename) {
    do_site_help("unlock",context);
    return 1;
  }

  do
  {
    /* convert file to absolute path, remember file_unlock wants ABSOLUTE paths ! */
    ret = checkpath(str_tochar(filename),buffer,context);
    str_deallocate(filename);
    if (ret) continue; /* path is NOT ok ! */
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */

    /* we need to use open() directly because file_open uses file_islocked ... */
    ret = file_force_unlock(buffer);
    if (ret < 0) {
      break;
    }
  }
  while ( (filename = str_tok(command_line," \t\r\n")) );

  if (ret == 0) {
    ret = send_message_with_args(200,context,"file(s) unlocked");
  } else {
    ret = send_message_with_args(501,context,"UNLOCK FAILED");
  }

  return 0;
}
/********************* do_site_user ************************/
/** user username
 */

void do_site_user(const char *command_line, wzd_context_t * context)
{
  const char * username;
  int ret;
  wzd_user_t user;
  int uid;

  username = command_line;
  if (!username) {
    do_site_help("user",context);
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }

  do_site_print_file(mainConfig->site_config.file_user,&user,NULL,context);
}

/********************* do_site_utime ***********************/
/** utime filename YYYYMMDDhhmmss YYYYMMDDhhmmss YYYYMMDDhhmmss UTC
 * change access time, modification time, modification of status of a file
 */

int do_site_utime(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
#ifdef HAVE_STRPTIME
  extern char *strptime (__const char *__restrict __s,
    __const char *__restrict __fmt, struct tm *__tp);
#endif
  char buffer[BUFFER_LEN];
  char * ptr;
  wzd_string_t * filename;
  wzd_string_t * new_atime, * new_mtime, * new_ctime;
  wzd_string_t * timezone;
  struct tm tm_atime, tm_mtime, tm_ctime;
  struct utimbuf utime_buf;
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  filename = str_tok(command_line," \t\r\n");
  if (!filename) {
    do_site_help("utime",context);
    return 1; 
  }
  new_atime = str_tok(command_line," \t\r\n");
  if (!new_atime) {
    do_site_help("utime",context);
    str_deallocate(filename);
    return 1;
  }
  new_mtime = str_tok(command_line," \t\r\n");
  if (!new_mtime) {
    do_site_help("utime",context);
    str_deallocate(filename); str_deallocate(new_atime);
    return 1;
  }
  new_ctime = str_tok(command_line," \t\r\n");
  if (!new_ctime) {
    do_site_help("utime",context);
    str_deallocate(filename); str_deallocate(new_atime); str_deallocate(new_mtime);
    return 1;
  }
  timezone = str_tok(command_line," \t\r\n");
  if (!timezone) {
    do_site_help("utime",context);
    str_deallocate(filename); str_deallocate(new_atime); str_deallocate(new_mtime);
    str_deallocate(new_ctime);
    return 1;
  }
  /* TODO check that timezone is UTC */
  memset(&tm_atime,0,sizeof(struct tm));
  ptr=strptime((char*)str_tochar(new_atime),"%Y%m%d%H%M%S",&tm_atime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    str_deallocate(filename); str_deallocate(new_atime); str_deallocate(new_mtime);
    str_deallocate(new_ctime); str_deallocate(timezone);
    return 1;
  }
  str_deallocate(new_atime);
  memset(&tm_mtime,0,sizeof(struct tm));
  ptr=strptime((char*)str_tochar(new_mtime),"%Y%m%d%H%M%S",&tm_mtime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    str_deallocate(filename); str_deallocate(new_mtime);
    str_deallocate(new_ctime); str_deallocate(timezone);
    return 1;
  }
  str_deallocate(new_mtime);
  /* TODO ctime is useless in *nix systems ... */
  memset(&tm_ctime,0,sizeof(struct tm));
  ptr=strptime((char*)str_tochar(new_ctime),"%Y%m%d%H%M%S",&tm_ctime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    str_deallocate(filename); str_deallocate(new_ctime); str_deallocate(timezone);
    return 1;
  }
  str_deallocate(new_ctime);
  str_deallocate(timezone);

  utime_buf.actime = mktime(&tm_atime);
  utime_buf.modtime = mktime(&tm_mtime);
  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(str_tochar(filename),buffer,context)) { /* path is NOT ok ! */
    ret = send_message_with_args(501,context,"File does not exists");
    str_deallocate(filename);
    return 1;
  }
  str_deallocate(filename);
/*  buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
  ret = _checkPerm(buffer,RIGHT_RNFR,user);  
  if (ret) {
    ret = send_message_with_args(501,context,"Access denied");
    return 1;
  }

  ret = utime(buffer,&utime_buf);

  ret = send_message_with_args(200,context,"UTIME command ok");
  return 0;
}

/********************* do_site_vars *********************/

int do_site_vars(wzd_string_t *ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  wzd_string_t *command, *varname, *value;
  char * buffer;
  int ret;

  command = str_tok(command_line," \t\r\n");
  if (!command) {
    do_site_help("vars",context);
    return 1; 
  }
  str_tolower(command);

  varname = str_tok(command_line," \t\r\n");
  if (!varname) {
    do_site_help("vars",context);
    str_deallocate(command);
    return 1;
  }

  if (strcmp(str_tochar(command),"get")==0) {
    str_deallocate(command);
    buffer = malloc(1024); /** \todo XXX harcoded value ! */
    ret = vars_get(str_tochar(varname),buffer,1024,mainConfig);

    if (ret)
      send_message_with_args(200,context,"an error occurred");
    else {
      send_message_raw("200-\r\n",context);
      send_message_raw(buffer,context);
      send_message_raw("\r\n200 Command OK\r\n",context);
    }

    free(buffer);
    str_deallocate(varname);
    return 0;
  }
  else if (strcmp(str_tochar(command),"set")==0) {
    str_deallocate(command);
    value = str_tok(command_line," \t\r\n");
    if (!value) {
      do_site_help("vars",context);
      str_deallocate(varname);
      return 1;
    }

    ret = vars_set(str_tochar(varname),str_tochar(value),strlen(str_tochar(value)),mainConfig);

    if (ret)
      send_message_with_args(200,context,"an error occurred");
    else
      send_message_with_args(200,context,"command ok");

    str_deallocate(varname);
    str_deallocate(value);
    return 0;
  }

  send_message_with_args(200,context,"command ok");
  str_deallocate(command);
  str_deallocate(varname);
  return 0;
}

/****************** do_site_vars_group *******************/

int do_site_vars_group(wzd_string_t *ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  wzd_string_t *groupname, *command, *varname, *value;
  char * buffer;
  int ret;
  wzd_group_t * group;

  command = str_tok(command_line," \t\r\n");
  if (!command) {
    do_site_help("vars_group",context);
    return 1; 
  }
  str_tolower(command);

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help("vars_group",context);
    str_deallocate(command);
    return 1; 
  }
  group = GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    send_message_with_args(501,context,"group does not exist");
    str_deallocate(command);
    return 1; 
  }

  varname = str_tok(command_line," \t\r\n");
  if (!varname) {
    do_site_help("vars_group",context);
    str_deallocate(command);
    return 1;
  }

  if (strcmp(str_tochar(command),"get")==0) {
    str_deallocate(command);
    buffer = malloc(1024); /** \todo XXX harcoded value ! */
    ret = vars_group_get(group->groupname,str_tochar(varname),buffer,1024,mainConfig);

    if (ret)
      send_message_with_args(200,context,"an error occurred");
    else {
      send_message_raw("200-\r\n",context);
      send_message_raw(buffer,context);
      send_message_raw("\r\n200 Command OK\r\n",context);
    }

    free(buffer);
    str_deallocate(varname);
    return 0;
  }
  else if (strcmp(str_tochar(command),"set")==0) {
    str_deallocate(command);
    value = str_tok(command_line," \t\r\n");
    if (!value) {
      do_site_help("vars_group",context);
      str_deallocate(varname);
      return 1;
    }

    ret = vars_group_set(group->groupname,str_tochar(varname),str_tochar(value),strlen(str_tochar(value)),mainConfig);

    if (ret)
      send_message_with_args(200,context,"an error occurred");
    else
      send_message_with_args(200,context,"command ok");
    str_deallocate(value);
    str_deallocate(varname);
    return 0;
  }

  send_message_with_args(200,context,"command ok");
  str_deallocate(command);
  str_deallocate(varname);
  return 0;
}

/****************** do_site_vars_user *******************/

int do_site_vars_user(wzd_string_t *ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  wzd_string_t *username, *command, *varname, *value;
  char * buffer;
  int ret;
  wzd_user_t * user;

  command = str_tok(command_line," \t\r\n");
  if (!command) {
    do_site_help("vars_user",context);
    return 1; 
  }
  str_tolower(command);

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help("vars_user",context);
    str_deallocate(command);
    return 1; 
  }
  user = GetUserByName(str_tochar(username));
  str_deallocate(username);
  if ( !user ) {
    send_message_with_args(501,context,"user does not exist");
    str_deallocate(command);
    return 1; 
  }

  varname = str_tok(command_line," \t\r\n");
  if (!varname) {
    do_site_help("vars_user",context);
    str_deallocate(command);
    return 1;
  }

  if (strcmp(str_tochar(command),"get")==0) {
    str_deallocate(command);
    buffer = malloc(1024); /** \todo XXX harcoded value ! */
    ret = vars_user_get(user->username,str_tochar(varname),buffer,1024,mainConfig);

    if (ret)
      send_message_with_args(200,context,"an error occurred");
    else {
      send_message_raw("200-\r\n",context);
      send_message_raw(buffer,context);
      send_message_raw("\r\n200 Command OK\r\n",context);
    }

    free(buffer);
    str_deallocate(varname);
    return 0;
  }
  else if (strcmp(str_tochar(command),"set")==0) {
    str_deallocate(command);
    value = str_tok(command_line," \t\r\n");
    if (!value) {
      do_site_help("vars_user",context);
      str_deallocate(varname);
      str_deallocate(value);
      return 1;
    }

    ret = vars_user_set(user->username,str_tochar(varname),str_tochar(value),strlen(str_tochar(value)),mainConfig);

    if (ret)
      send_message_with_args(200,context,"an error occurred");
    else
      send_message_with_args(200,context,"command ok");
    str_deallocate(varname);
    str_deallocate(value);
    return 0;
  }

  send_message_with_args(200,context,"command ok");
  str_deallocate(varname);
  return 0;
}

/********************* do_site_version *********************/

int do_site_version(wzd_string_t * ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  char str[256];
  snprintf(str,256,"%s build %s (%s)",
      WZD_VERSION_STR,WZD_BUILD_NUM,WZD_BUILD_OPTS);
  send_message_with_args(200,context,str);
  return 0;
}

/********************* do_site_vfsls ***********************/

/* XXX : just send last vfs */

int do_site_vfsls(wzd_string_t * ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  do_site_print_file(mainConfig->site_config.file_vfs,NULL,NULL,context);

  return 0;
}

/********************* do_site_vfsadd **********************/
/** vfsadd |/home/vfsroot|/physical/path| +O =user
 */

int do_site_vfsadd(wzd_string_t * ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  char *vpath, *ppath, *target;
/*  int i;*/
  int ret;
  char sep;
  const char *ptr;
  char * dstptr;
  unsigned int dstlen, length;
  char buffer[1024];

  strncpy(buffer,str_tochar(command_line),1024);

  /* allocate enough memory */
  length = strlen(buffer);
  vpath = malloc(length);
  ppath = malloc(length);

  /* parse command line */
  ptr = buffer;
  sep = *ptr++;

  dstptr = vpath;
  dstlen = 0;

  while (*ptr) {
    if (*ptr == sep) break; /* end */
    if (dstlen++ == length-1) break; /* too long */
    *dstptr++ = *ptr++;
  }
  if (!*ptr || *ptr != sep) {
    free(vpath); free(ppath);
    send_message_with_args(501,context,"site vfsadd |/home/vfsroot|/physical/path| [PERM]");
    return 1;
  }
  *dstptr = '\0';

  dstptr = ppath;
  dstlen = 0;
  ptr++;

  while (*ptr) {
    if (*ptr == sep) break; /* end */
    if (dstlen++ == length-1) break; /* too long */
    *dstptr++ = *ptr++;
  }
  if (!*ptr || *ptr != sep) {
    free(vpath); free(ppath);
    send_message_with_args(501,context,"site vfsadd |/home/vfsroot|/physical/path| [PERM]");
    return 1;
  }
  *dstptr = '\0';
 
  target = NULL;
  ptr++;

  if (*ptr) {
    while( *ptr && (*ptr==' ' || *ptr=='\t')) ptr++;
    if (*ptr)
      target = (char*)ptr;
  }
 
  if( target )
    ret = vfs_add_restricted( &mainConfig->vfs, vpath, ppath, target );
  else
    ret = vfs_add( &mainConfig->vfs, vpath, ppath );

  if (ret==1)
    send_message_with_args(501,context,"site vfsadd |/home/vfsroot|/physical/path| [PERM]");
  else if (ret==2)
  {
    char tmp[80];
    snprintf( tmp, 80, "vfs %s already set", vpath );
    send_message_with_args(501,context,tmp);
  }  else
    send_message_with_args(200,context,"VFSADD command ok");
  
  free(vpath); free(ppath);

  return 0;
}

/********************* do_site_vfsdel **********************/
/** vfsdel /home/vfsroot
 */

int do_site_vfsdel(wzd_string_t * ignored, wzd_string_t * command_line, wzd_context_t * context)
{
  int ret;

  if (command_line && strlen(str_tochar(command_line))>0)
    ret = vfs_remove( &mainConfig->vfs, str_tochar(command_line) );
  else ret = 1;

  if (ret==1)
    send_message_with_args(501,context,"site vfsdel /home/vfsroot");
  else if (ret==2)
  {
    char tmp[80];
    snprintf( tmp, 80, "vfs %s does not exist", str_tochar(command_line) );
    send_message_with_args(501,context,tmp);
  } else
    send_message_with_args(200,context,"VFSDEL command ok");

  return 0;
}

/* TODO XXX FIXME tests missing
 */
static int do_internal_wipe(const char *filename, wzd_context_t * context)
{
  fs_filestat_t s;
  int ret;
  const char *dir_filename;
  char buffer[1024];
  char path[1024];
  char * ptr;
  fs_dir_t * dir;
  fs_fileinfo_t * finfo;

  split_filename(filename,path,NULL,1024,0);

  if (fs_file_lstat(filename,&s)) return -1;

  if (S_ISREG(s.mode) || S_ISLNK(s.mode)) {
    ret = file_remove(filename,context);
    if (ret) return 1;
  }
  if (S_ISDIR(s.mode))
  {
    strncpy(buffer,filename,sizeof(buffer));
    ptr = buffer + strlen(buffer);
    *ptr++ = '/';

    if ( fs_dir_open(filename,&dir) ) return -1;

    while ( !fs_dir_read(dir,&finfo) ) {
      dir_filename = fs_fileinfo_getname(finfo);

      if (strcmp(dir_filename,".")==0 || strcmp(dir_filename,"..")==0)
        continue;
      if (strlen(buffer)+strlen(dir_filename)>=1024) { fs_dir_close(dir); return 1; }
      strncpy(ptr,dir_filename,256);

/*      if (fs_file_stat(buffer,&s)) { fs_dir_close(dir); return -1; }*/
      if (fs_file_lstat(buffer,&s)==0) {
        if (S_ISREG(s.mode) || S_ISLNK(s.mode)) {
/*          ret = file_remove(buffer,context);*/
          ret = unlink(buffer);
          if (ret) { fs_dir_close(dir); return 1; }
        }
        if (S_ISDIR(s.mode)) {
          ret = do_internal_wipe(buffer,context);
          if (ret) { fs_dir_close(dir); return 1; }
        }
      }
    }

    fs_dir_close(dir);
    ret = rmdir(filename);
    if (ret) return 1;
  }

  return 0;
}

/********************* do_site_wipe ************************/
/** wipe: [-r] file1 [file2 ...]
 */

int do_site_wipe(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[WZD_MAX_PATH+1];
  wzd_string_t * firstarg, *filename;
  int is_recursive;
  int ret;
/*  wzd_user_t user;*/
/*  int uid;*/

  firstarg = str_read_token(command_line);
  if (!firstarg) {
    do_site_help("wipe",context);
    return 1;
  }
  /* check if wiping is recursive */
  if ( strcasecmp(str_tochar(firstarg),"-r")==0 ) {
    str_deallocate(firstarg);
    is_recursive=1;
    filename = str_read_token(command_line);
    if( !filename) {
      do_site_help("wipe",context);
      return 1;
    }
  }
  else
    filename = firstarg;

  do
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (!checkpath(str_tochar(filename),buffer,context))
    {
      /* wipe file | if_recursive dir/file */
      ret = do_internal_wipe(buffer,context);
      if (ret) {
        ret = send_message_with_args(501,context,"WIPE failed");
        str_deallocate(filename);
        return 1;
      }
    }
    str_deallocate(filename);
  }
  while ( (filename = str_read_token(command_line)) );

  ret = send_message_with_args(200,context,"File(s) wiped");

  return 0;
}

/********************* do_site *****************************/

int do_site(wzd_string_t *command, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[4096];
  int ret=0;
  wzd_hook_reply_t hook_reply;
  int first_reply;
  const char *s_token;

  if (!command || !command_line) {
    ret = send_message_with_args(501,context,"SITE command failed");
    return 1;
  }

  /* check general site permission */
#ifdef DEBUG
  if (strlen(str_tochar(command))>255) {
    out_err(LEVEL_HIGH,"*** WARNING *** permissions name too long > 255 - truncated : '%s'\n",str_tochar(command));
  }
#endif

  {
    wzd_command_t * command_real;

    command_real = commands_find(mainConfig->commands_list,command);
    /* disabled because this breaks custom site commands */
#if 0
    if (!command_real) {
      ret = send_message_with_args(501,context,"Permission not found for site command");
      return 1;
    }
#endif
    if (command_real && commands_check_permission(command_real,context)) {
      ret = send_message_with_args(501,context,"Permission Denied");
      return 1;
    }
  }

  s_token = str_tochar(command);

#if 0
  fct = site_find(s_token);

  if (fct)
  {
    tok_command = str_tok(command_line,"\r\n");
    ret = (*fct)((char*)str_tochar(tok_command),context);
    str_deallocate(tok_command);
    return ret;
  }
#endif

/******************** CLOSE *********************/
  if (strcmp(s_token,"site_close")==0) {
    mainConfig->site_closed = 1;
    ret = send_message_with_args(250,context,"SITE: ","server is now closed");
    return 0;
  } else
/******************* GINFO **********************/
  if (strcmp(s_token,"site_groups")==0) {
    do_site_print_file(mainConfig->site_config.file_groups,NULL,NULL,context);
    return 0;
  } else
/******************* HELP ***********************/
  if (strcmp(s_token,"site_help")==0) {
    /* TODO check if there are arguments, and call specific help */
    do_site_print_file(mainConfig->site_config.file_help,GetUserByID(context->userid),NULL,context);
    return 0;
  } else
/******************** REOPEN ********************/
  if (strcmp(s_token,"site_reopen")==0) {
    mainConfig->site_closed = 0;
    ret = send_message_with_args(250,context,"SITE: ","server is now opened");
    return 0;
  } else
/******************* SWHO ***********************/
  if (strcmp(s_token,"site_swho")==0) {
    do_site_print_file(mainConfig->site_config.file_swho,NULL,NULL,context);
    return 0;
  } else
/******************* USER ***********************/
  if (strcmp(s_token,"site_user")==0) {
    do_site_user(str_tochar(command_line),context);
    return 0;
  } else
/******************* USERS **********************/
  if (strcmp(s_token,"site_users")==0) {
    do_site_print_file(mainConfig->site_config.file_users,NULL,NULL,context);
    return 0;
  } else
/******************* WHO ************************/
  if (strcmp(s_token,"site_who")==0) {
    do_site_print_file(mainConfig->site_config.file_who,NULL,NULL,context);
    return 0;
  } else
/******************* UPTIME *********************/
  if (strcmp(s_token,"site_uptime")==0) {
    time_t t;
    time(&t);
    t = t - mainConfig->server_start;
    snprintf(buffer,sizeof(buffer),"Uptime: %s",time_to_str(t));
    ret = send_message_with_args(200,context,buffer);
    return 0;
  }
/******************* SHUTDOWN *******************/
#ifndef WZD_MULTITHREAD
  else if (strcmp(s_token,"site_shutdown")==0) {
    mainConfig->serverstop = 1;
    ret = send_message_with_args(250,context,"SITE: ","server will shutdown after you logout");
    return 0;
  }
#endif /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
  else if (strcmp(s_token,"site_shutdown")==0) {
    ret = send_message_with_args(250,context,"SITE: ","server will shutdown NOW");
    mainConfig->serverstop = 1;
    return 0;
  }
#endif /* WZD_MULTITHREAD */

  hook_reply = EVENT_IGNORED;
  first_reply = 1;

  FORALL_HOOKS(EVENT_SITE)
    typedef wzd_hook_reply_t (*site_hook)(unsigned long, wzd_context_t *, const char*,const char *);
    if (hook->hook) {
      hook_reply = (*(site_hook)hook->hook)(EVENT_SITE,context,s_token,str_tochar(command_line));
      /** \todo implement and use constants: HANDLED, NEXT, ERROR or something like .. */
      if (hook_reply != EVENT_IGNORED && hook_reply != EVENT_NEXT) break;
    }
    /* custom site commands */
    if (hook->opt && hook->external_command && strcasecmp(hook->opt,s_token)==0) {
      if (first_reply) { send_message_raw("200-\r\n",context); first_reply=0; }
      ret = hook_call_custom(context, hook, 200, (char*)str_tochar(command_line));
      if (!ret) {
        ret = send_message_with_args(200,context,"SITE command ok");
      } else {
        ret = send_message_with_args(200,context,"SITE command failed");
      }
      return 0; /* there can be only one site command ! */
    }
  END_FORALL_HOOKS

  switch (hook_reply) {
  case EVENT_ERROR:
    /* we do not know how to reply .. trying 200 */
    out_log(LEVEL_INFO, "Someone reported errors for site command %s\n", s_token);
    ret = send_message_with_args(200,context,"SITE command failed");
    break;
  case EVENT_NEXT:
    /* we do not know how to reply .. trying 200 */
    out_log(LEVEL_INFO, "Received only EVENT_NEXT for site command %s\n", s_token);
    out_log(LEVEL_INFO, "The last handler should send EVENT_CATCHED\n");
    ret = send_message_with_args(200,context,"SITE command executed (with warnings)");
    break;
  case EVENT_IGNORED:
    ret = send_message_with_args(250,context,"SITE ","command unknown");
    break;
  case EVENT_HANDLED:
    break;
  }

  return 0;
}

/********************* do_site *****************************/

int do_sitecmd(wzd_string_t *command, wzd_string_t *command_line, wzd_context_t * context)
{
  int ret=0;
  wzd_hook_reply_t hook_reply;
  int first_reply;
  const char *s_token;

  if (!command || !command_line) {
    ret = send_message_with_args(501,context,"Custom SITE command failed");
    return 1;
  }

  s_token = str_tochar(command);

  hook_reply = EVENT_IGNORED;
  first_reply = 1;

  FORALL_HOOKS(EVENT_SITE)
    typedef wzd_hook_reply_t (*site_hook)(unsigned long, wzd_context_t *, const char*,const char *);
    if (hook->hook) {
      hook_reply = (*(site_hook)hook->hook)(EVENT_SITE,context,s_token,str_tochar(command_line));
      /** \todo implement and use constants: HANDLED, NEXT, ERROR or something like .. */
      if (hook_reply != EVENT_IGNORED && hook_reply != EVENT_NEXT) break;
    }
    /* custom site commands */
    if (hook->opt && hook->external_command && strcasecmp(hook->opt,s_token)==0) {
      if (first_reply) { send_message_raw("200-\r\n",context); first_reply=0; }
      ret = hook_call_custom(context, hook, 200, (char*)str_tochar(command_line));
      if (!ret) {
        ret = send_message_with_args(200,context,"SITE command ok");
      } else {
        ret = send_message_with_args(200,context,"SITE command failed");
      }
      return 0; /* there can be only one site command ! */
    }
  END_FORALL_HOOKS

  switch (hook_reply) {
  case EVENT_ERROR:
    /* we do not know how to reply .. trying 200 */
    out_log(LEVEL_INFO, "Someone reported errors for site command %s\n", s_token);
    ret = send_message_with_args(200,context,"SITE command failed");
    break;
  case EVENT_NEXT:
    /* we do not know how to reply .. trying 200 */
    out_log(LEVEL_INFO, "Received only EVENT_NEXT for site command %s\n", s_token);
    out_log(LEVEL_INFO, "The last handler should send EVENT_CATCHED\n");
    ret = send_message_with_args(200,context,"SITE command executed (with warnings)");
    break;
  case EVENT_IGNORED:
    ret = send_message_with_args(250,context,"SITE ","command unknown");
    break;
  case EVENT_HANDLED:
    break;
  }

  return 0;
}

