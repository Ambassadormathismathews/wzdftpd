/* vi:ai:et:ts=8 sw=2
 */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _MSC_VER
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
#include "wzd_vfs.h"
#include "wzd_file.h"
#include "wzd_dir.h"
#include "wzd_perm.h"
#include "wzd_mod.h"
#include "wzd_cache.h"
#include "wzd_savecfg.h"

#include "wzd_debug.h"

extern int serverstop;
extern time_t server_start;

#define	BUFFER_LEN	4096

typedef int (*site_fct_t)(char *cl, wzd_context_t *context);

/** @brief Site function definition: name, pointer to function */
struct wzd_site_fct_t {
  char *name;
  site_fct_t fct;

  struct wzd_site_fct_t * next_site_fct;
};

void do_site_print_file_raw(const char *filename, wzd_context_t *context);

/********************* do_site_test ************************/

int do_site_test(char *command, wzd_context_t * context)
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
    send_message_raw("site chpass user new_pass\r\n",context);
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
  {
    snprintf(buffer,BUFFER_LEN,"Syntax error in command %s\r\n",site_command);
    send_message_raw(buffer,context);
  }
  send_message_raw("501 \r\n",context);
}

/********************* do_site_backend *********************/
/** backend: close / reload / init / commit
 */
int do_site_backend(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * command, *name;
  int ret;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help("backend",context);
    return 1;
  }
  name = strtok_r(NULL," \t\r\n",&ptr);
  if (!name) {
    do_site_help("backend",context);
    return 1;
  }
  if (strcasecmp(command,"close")==0) {
    ret = backend_close(name);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not close backend");
    } else {
      ret = send_message_with_args(200,context,"Backend close successfully");
    }
    return 0;
  } /* close */
  if (strcasecmp(command,"init")==0) {
    int backend_storage;
    ret = backend_init(name,&backend_storage,mainConfig->user_list,HARD_DEF_USER_MAX,mainConfig->group_list,HARD_DEF_GROUP_MAX);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not init backend");
    } else {
      ret = send_message_with_args(200,context,"Backend loaded successfully");
    }
    return 0;
  } /* init */
  if (strcasecmp(command,"reload")==0) {
    ret = backend_reload(name);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not reload backend ** WARNING you could have NO backend NOW");
    } else {
      ret = send_message_with_args(200,context,"Backend reloaded successfully");
    }
    return 0;
  } /* reload */
  if (strcasecmp(command,"commit")==0) {
    ret = backend_commit_changes(name);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not commit backend");
    } else {
      ret = send_message_with_args(200,context,"Backend commited successfully");
    }
    return 0;
  } /* commit */
  do_site_help("backend",context);
  return 0;
}

/********************* do_site_chacl ***********************/
/** chacl: user mode file1 [file2 ...]
 */

int do_site_chacl(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * mode, *username, *filename;
  int ret;
  wzd_user_t user;
  int uid;
  unsigned long long_perms;
  char str_perms[64];
  char * endptr;

  ptr = command_line;
  username = strtok_r(NULL," \t\r\n",&ptr);
  if (!username) {
    do_site_help("chacl",context);
    return 1;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return 1;
  }
  mode = strtok_r(NULL," \t\r\n",&ptr);
  if (!mode) {
    do_site_help("chacl",context);
    return 1;
  }
  /* TODO check that mode is ok */
  if (strlen(mode) > 15) {
    do_site_help("chacl",context);
    return 1;
  }
  long_perms = strtoul(mode,&endptr,8);
  if (endptr != mode) {
    snprintf(str_perms,63,"%c%c%c",
        (long_perms & 01) ? 'r' : '-',
        (long_perms & 02) ? 'w' : '-',
        (long_perms & 04) ? 'x' : '-'
        );
  } else
    strncpy(str_perms,mode,63);

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
    _setPerm(buffer,username,0,0,str_perms,0,context);
  }

  snprintf(buffer,BUFFER_LEN,"acl successfully set");
  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/********************* do_site_chgrp ***********************/
/** chgrp: group file1 [file2 ...]
 */

int do_site_chgrp(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * groupname, *filename;
  int ret;
  wzd_group_t group;
  int gid;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help("chgrp",context);
    return 1;
  }
  /* check that groupname exists */
  gid = GetGroupIDByName(groupname);
  if ( !(gid=GetGroupIDByName(groupname)) ) {
    ret = send_message_with_args(501,context,"Group does not exists");
    return 1;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
    _setPerm(buffer,0,0,groupname,0,0,context);
  }

  snprintf(buffer,BUFFER_LEN,"group changed to '%s'",groupname);
  ret = send_message_with_args(200,context,buffer);

  return 0;
}

/********************* do_site_chmod ***********************/
/** chmod: mode file1 [file2 ...]
 */
int do_site_chmod(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * mode, *filename;
  int ret;
  unsigned long long_perms;
/*  char str_perms[64];*/
  char * endptr;

  ptr = command_line;
  mode = strtok_r(command_line," \t\r\n",&ptr);
  if (!mode) {
    do_site_help("chmod",context);
    return 1;
  }
  /* TODO check that mode is ok */
  if (strlen(mode) > 15) {
    do_site_help("chmod",context);
    return 1;
  }
  long_perms = strtoul(mode,&endptr,8);
/*  if (endptr != mode) {
    snprintf(str_perms,63,"%c%c%c",
      (long_perms & 01) ? 'r' : '-',
      (long_perms & 02) ? 'w' : '-',
      (long_perms & 04) ? 'x' : '-'
    );
  } else
    strncpy(str_perms,mode,63);*/

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
/*    _setPerm(buffer,username,0,0,str_perms,0,context);*/
    _setPerm(buffer,0,0,0,0,long_perms,context);
  }

  snprintf(buffer,BUFFER_LEN,"mode changed to '%o'",long_perms);
  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/********************* do_site_chown ***********************/
/** chown: user file1 [file2 ...]
 */

int do_site_chown(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * username, *filename;
  int ret;
  wzd_user_t user;
  int uid;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("chown",context);
    return 1;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return 1;
  }

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
    _setPerm(buffer,0,username,0,0,0,context);
  }

  snprintf(buffer,BUFFER_LEN,"owner changed to '%s'",username);
  ret = send_message_with_args(200,context,buffer);

  return 0;
}

/********************* do_site_chpass **********************/
/** chpass: user new_pass
 */
int do_site_chpass(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * username, *new_pass;
  int ret;
  wzd_user_t user, *me;
  int uid;
  short is_gadmin;
  unsigned long mod_type;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;
  
  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("chpass",context);
    return 1;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return 1;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0]) {
      ret = send_message_with_args(501,context,"You can't change this user");
      return 1;
    }
  }

  new_pass = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_pass) {
    do_site_help("chpass",context);
    return 1;
  }

  mod_type = _USER_USERPASS;
  strncpy(user.userpass,new_pass,sizeof(user.userpass));

  /* commit to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_user("plaintext",username,&user,mod_type);

  if (ret)
    ret = send_message_with_args(501,context,"An error occurred during password change");
  else
    ret = send_message_with_args(200,context,"Password changed, don't forget to commit changes");
  return 0;
}

/********************* do_site_checkperm *******************/
int do_site_checkperm(char * commandline, wzd_context_t * context)
{
  unsigned long word;
  char buffer[BUFFER_LEN];
  char *username, *filename, *perms;
  char *ptr;
  wzd_user_t userstruct, *userptr;
  int uid;

  strncpy(buffer,commandline,BUFFER_LEN-1);
  ptr = &buffer[0];
  
  username = strtok_r(buffer," \t\r\n",&ptr);
  if (!username) { do_site_help("checkperm",context); return 1; }
  filename = strtok_r(NULL," \t\r\n",&ptr);
  if (!filename) { do_site_help("checkperm",context); return 1; }
  perms = strtok_r(NULL,"\r\n",&ptr);
  if (!perms) { do_site_help("checkperm",context); return 1; }

  word = right_text2word(perms);
  if (word == 0) {
    send_message_with_args(501,context,"Invalid permission");
    return 1;
  }

  if (backend_find_user(username,&userstruct,&uid)) {
    send_message_with_args(501,context,"User does not exist");
    return 1;
  }
  if (uid == -1) userptr = &userstruct;
  else userptr = GetUserByID(uid);

  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(filename,buffer,context)) {
    send_message_with_args(501,context,"file does not exist");
    return 1;
  }
 
/*  buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */

  if (_checkPerm(buffer,word,userptr)==0) {
    strcpy(buffer,"right ok");
  } else {
    strcpy(buffer,"refused");
  }
  
  send_message_with_args(200,context,buffer);
  return 0;
}

/********************* do_site_free ************************/
/** free sectionname
 */

int do_site_free(char *command_line, wzd_context_t * context)
{
  char buffer[2048];
  int ret;
/*  char * ptr;
  char * sectionname;
  wzd_user_t user;
  int uid;
  wzd_context_t user_context;*/
  long f_type, f_bsize, f_blocks, f_free;
  float free,total;
  char unit;

/*  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("user",context);
    return;
  }*/

  if (checkpath_new(".",buffer,context)) {
    send_message_with_args(501,context,". does not exist ?!");
    return -1;
  }

  ret = get_device_info(buffer,&f_type, &f_bsize, &f_blocks, &f_free);

  unit='k';
  free = f_free*(f_bsize/1024.f);
  total = f_blocks*(f_bsize/1024.f);

  if (total > 1000.f) {
    unit='M';
    free /= 1024.f;
    total /= 1024.f;
  }
  if (total > 1000.f) {
    unit='G';
    free /= 1024.f;
    total /= 1024.f;
  }

  snprintf(buffer,2047,"[FREE] + [current dir: %.2f / %.2f %c] -",free,total,unit);

  ret = send_message_with_args(200,context,buffer);

  return 0;
}

/********************* do_site_invite **********************/
/** invite: ircnick
 */
int do_site_invite(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * ircnick;
  int ret;
  wzd_user_t *user;
  wzd_group_t *group;
  char buffer[2048], path[2048];

  ptr = command_line;
  ircnick = strtok_r(command_line," \t\r\n",&ptr);
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
  return 0;
}

/********************* do_site_link ************************/
/** link: create dir linkname
  * link: remove linkname
  */

int do_site_link(char *command_line, wzd_context_t * context)
{
  char buffer_dir[BUFFER_LEN], buffer_link[BUFFER_LEN];
  char * ptr;
  char * dirname, *linkname;
  char * command;
  int ret;

  ptr = command_line;
  command = read_token(command_line, &ptr);
  if (!command) {
    do_site_help("link",context);
    return 1;
  }
  dirname = read_token(NULL, &ptr);
  if (!dirname) {
    do_site_help("link",context);
    return 1;
  }
 
  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(dirname,buffer_dir,context)) {
    ret = send_message_with_args(501,context,"dirname is invalid");
    return 0;
  }
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */

  if (strcasecmp(command,"CREATE")==0)
  {
    linkname = read_token(NULL, &ptr);
    if (!linkname) {
      do_site_help("link",context);
      return 1;
    }
    if (checkpath(linkname,buffer_link,context)) {
      ret = send_message_with_args(501,context,"linkname is invalid");
      return 0;
    }
    ret = symlink_create(buffer_dir, buffer_link);
  }
  else if (strcasecmp(command,"REMOVE")==0)
  {
    ret = symlink_remove(buffer_dir);
  }
  else {
    do_site_help("link",context);
    return 1;
  }

  ret ? send_message_with_args(501,context,"command_failed") : send_message_with_args(200,context,"command ok");

  return 0;
}


/********************* do_site_msg *************************/
/** msg: show
 *       new msg_line
 *       append msg_line
 *       convert filename
 *       delete
 */
int do_site_msg(char *command_line, wzd_context_t * context)
{
/*  int ret;*/
  char * command, * ptr, * filename;
  char msg_file[2048];
  char other_file[2048];
  unsigned int length;
  struct stat s;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help("msg",context);
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

  if (strcasecmp(command,"show")==0)
  {
    do_site_print_file_raw(msg_file,context);
    return 0;
  }
  else if (strcasecmp(command,"convert")==0)
  {
    filename = strtok_r(NULL,"\r\n",&ptr);
    if (!filename) {
      do_site_help("msg",context);
      return 1;
    }
    strncpy(other_file+length,filename,2048-length-1);
    if (stat(other_file,&s) || !S_ISREG(s.st_mode))
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
  else if (strcasecmp(command,"delete")==0)
  {
    unlink(msg_file);
    send_message_with_args(200,context,"message file deleted");
    return 0;
  }
  else if (strcasecmp(command,"new")==0)
  {
    FILE * fp;
    char * buf;
    unsigned int length;
    buf = strtok_r(NULL,"\r\n",&ptr);
    if (!buf) {
      do_site_help("msg",context);
      return 1;
    }
    fp = fopen(msg_file,"w");
    if (!fp) {
      send_message_with_args(501,context,"unable to open message file for writing");
      return 1;
    }
    length = strlen(buf);
    if (length != fwrite(buf,1,length,fp)) {
      fclose(fp);
      send_message_with_args(501,context,"unable to write message");
      return 1;
    }
    fclose(fp);
    send_message_with_args(200,context,"message file written");
    return 0;
  }
  else if (strcasecmp(command,"append")==0)
  {
    FILE * fp;
    char * buf;
    unsigned int length;
    buf = strtok_r(NULL,"\r\n",&ptr);
    if (!buf) {
      do_site_help("msg",context);
      return 1;
    }
    fp = fopen(msg_file,"a");
    if (!fp) {
      send_message_with_args(501,context,"unable to open message file for writing");
      return 1;
    }
    length = strlen(buf);
    if (length != fwrite(buf,1,length,fp)) {
      fclose(fp);
      send_message_with_args(501,context,"unable to write message");
      return 1;
    }
    fclose(fp);
    send_message_with_args(200,context,"message file written");
    return 0;
  }

  do_site_help("msg",context);
  return 0;
}

/********************* do_site_perm ************************/
/** perm: show  (show all permissions)
 *        show perm_name  (show permissions for all commands starting with perm_name)
 *        add perm_name perms
 *        change perm_name perms
 *        remove perm_name
 */
int do_site_perm(char *command_line, wzd_context_t * context)
{
/*  int ret;*/
  char * command, * ptr;
  char * perm_name;
  char perm_buffer[256];
  char buffer[2048];
  wzd_command_perm_t * current;
  int ret;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help("perm",context);
    return 1;
  }
  perm_name = strtok_r(NULL," \t\r\n",&ptr);

  if (strcasecmp(command,"show")==0)
  {
    send_message_raw("200-\r\n",context);
    current = mainConfig->perm_list;
    if ( !perm_name ) {
      /* no argument: print all perms */
      while (current) {
        if ( !perm2str(current,perm_buffer,sizeof(perm_buffer)) )
        {
          snprintf( buffer, sizeof(buffer), " %s%s\r\n", current->command_name, perm_buffer);
          send_message_raw(buffer,context);
        }
        current = current->next_perm;
      }
    } else {
      /* search on perms name */
      int found=0;
      while (current) {
        if ( !strncasecmp(perm_name,current->command_name,strlen(perm_name)) )
        {
          found=1;
          if ( !perm2str(current,perm_buffer,sizeof(perm_buffer)) )
          {
            snprintf( buffer, sizeof(buffer), " %s%s\r\n", current->command_name, perm_buffer);
            send_message_raw(buffer,context);
          }
        }
        current = current->next_perm;
      }
      if (!found)
        send_message_raw(" permission not found\r\n",context);
    }
    send_message_raw("200 \r\n",context);
    return 0;
  }
  else if (strcasecmp(command,"change")==0)
  {
    ptr = strtok_r(NULL,"\r\n",&ptr);
    if (!perm_name || !ptr) {
      do_site_help("perm",context);
      return 1;
    }
    ret = perm_is_valid_perm(perm_name);
    if (ret) { send_message_with_args(501,context,"perm_name is invalid"); return 1; }
    if ( perm_remove(perm_name, mainConfig) ) {
      send_message_with_args(501,context,"error, permission NOT deleted");
      return 1;
    }
    ret = perm_add_perm(perm_name,ptr,mainConfig);
    if (ret) { send_message_with_args(501,context,"error adding permission"); return 1; }
    send_message_with_args(200,context,"command ok, permission changed");
    return -1;
  }
  else if (strcasecmp(command,"remove")==0)
  {
    if (!perm_name) {
      do_site_help("perm",context);
      return 1;
    }
    if ( perm_remove(perm_name, mainConfig) )
      send_message_with_args(501,context,"error, permission NOT deleted");
    else
      send_message_with_args(200,context,"command ok, permission deleted");
    return 0;
  }
  else if (strcasecmp(command,"add")==0)
  {
    ptr = strtok_r(NULL,"\r\n",&ptr);
    if (!perm_name || !ptr) {
      do_site_help("perm",context);
      return 1;
    }
    ret = perm_is_valid_perm(perm_name);
    if (ret) { send_message_with_args(501,context,"perm_name is invalid"); return 1; }
    ret = perm_add_perm(perm_name,ptr,mainConfig);
    if (ret) { send_message_with_args(501,context,"error adding permission"); return 1; }
    send_message_with_args(200,context,"command ok, permission added");
    return 0;
  }

  do_site_help("perm",context);
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
  fp = wzd_cache_open(filename,O_RDONLY,0644);
  if (!fp) {
    send_message_with_args(501,context,"Inexistant file");
    return;
  }
  filesize = wzd_cache_getsize(fp);
  file_buffer = malloc(filesize+1);
  if ( (size=wzd_cache_read(fp,file_buffer,filesize))!=filesize )
  {
    fprintf(stderr,"Could not read file %s read %u instead of %u (%s:%d)\n",filename,size,filesize,__FILE__,__LINE__);
    free(file_buffer);
    wzd_cache_close(fp);
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

int do_site_reload(char * ignored, wzd_context_t * context)
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
  server_restart();
  return 1;
#endif
  return 0;
}

/********************* do_site_rusage **********************/

int do_site_rusage(char * ignored, wzd_context_t * context)
{
#ifndef _MSC_VER
  int ret;
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
int do_site_savecfg(char *command_line, wzd_context_t * context)
{
  if( wzd_savecfg() )
    send_message_with_args(501,context,"Cannot save server config");
  else
    send_message_with_args(200,context,"Server config saved");
  return 0;
}

/********************* do_site_unlock **********************/
/** unlock: file1 [file2 ...]
 */

int do_site_unlock(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * filename;
  int ret;

  ptr = command_line;
  filename = strtok_r(command_line," \t\r\n",&ptr);
  if (!filename) {
    do_site_help("unlock",context);
    return 1;
  }

  do
  {
    /* convert file to absolute path, remember file_unlock wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */

    /* we need to use open() directly because file_open uses file_islocked ... */
    ret = file_force_unlock(buffer);
    if (ret < 0) {
      break;
    }
  }
  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) );

  if (ret == 0) {
    ret = send_message_with_args(200,context,"file(s) unlocked");
  } else {
    snprintf(buffer,BUFFER_LEN,"UNLOCK FAILED on file: '%s'",filename);
    ret = send_message_with_args(501,context,buffer);
  }

  return 0;
}
/********************* do_site_user ************************/
/** user username
 */

void do_site_user(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * username;
  int ret;
  wzd_user_t user;
  int uid;
  wzd_context_t user_context;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("user",context);
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }
  /* needed, because do_site_print_file writes directly to context->controlfd */
/*  user_context.controlfd = context->controlfd;*/
/*  memcpy(&user_context.userinfo,&user,sizeof(wzd_user_t));*/
  user_context.userid = uid;
  user_context.magic = CONTEXT_MAGIC;

/*#if BACKEND_STORAGE*/
  do_site_print_file(mainConfig->site_config.file_user,&user,NULL,context);
/*#endif
  do_site_print_file(mainConfig->site_config.file_user,GetUserByID(uid),NULL,context);*/
  user_context.magic = 0;
}

/********************* do_site_utime ***********************/
/** utime filename YYYYMMDDhhmmss YYYYMMDDhhmmss YYYYMMDDhhmmss UTC
 * change acess time, modification time, modification of status of a file
 */

int do_site_utime(char *command_line, wzd_context_t * context)
{
#ifdef HAVE_STRPTIME
  extern char *strptime (__const char *__restrict __s,
    __const char *__restrict __fmt, struct tm *__tp);
#endif
  char buffer[BUFFER_LEN];
  char * ptr;
  char * filename;
  char * new_atime, * new_mtime, * new_ctime;
  struct tm tm_atime, tm_mtime, tm_ctime;
  struct utimbuf utime_buf;
  char * timezone;
  int ret;
  wzd_user_t * user;

  user = GetUserByID(context->userid);

  ptr = command_line;
  filename = strtok_r(command_line," \t\r\n",&ptr);
  if (!filename) {
    do_site_help("utime",context);
    return 1; 
  }
  new_atime = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_atime) {
    do_site_help("utime",context);
    return 1;
  }
  new_mtime = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_mtime) {
    do_site_help("utime",context);
    return 1;
  }
  new_ctime = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_ctime) {
    do_site_help("utime",context);
    return 1;
  }
  timezone = strtok_r(NULL," \t\r\n",&ptr);
  if (!timezone) {
    do_site_help("utime",context);
    return 1;
  }
  /* TODO check that timezone is UTC */
  ptr=strptime(new_atime,"%Y%m%d%H%M%S",&tm_atime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    return 1;
  }
  ptr=strptime(new_mtime,"%Y%m%d%H%M%S",&tm_mtime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    return 1;
  }
  /* TODO ctime is useless in *nix systems ... */
  ptr=strptime(new_ctime,"%Y%m%d%H%M%S",&tm_ctime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    return 1;
  }
  utime_buf.actime = mktime(&tm_atime);
  utime_buf.modtime = mktime(&tm_mtime);
  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(filename,buffer,context)) { /* path is NOT ok ! */
    ret = send_message_with_args(501,context,"File does not exists");
    return 1;
  }
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

/********************* do_site_version *********************/

int do_site_version(char * ignored, wzd_context_t * context)
{
  char str[256];
  snprintf(str,256,"%s build %s (%s)\n",
      WZD_VERSION_STR,(unsigned long)WZD_BUILD_NUM,WZD_BUILD_OPTS);
  send_message_with_args(200,context,str);
  return 0;
}

/********************* do_site_vfsls ***********************/

/* XXX : just send last vfs */

int do_site_vfsls(char * ignored, wzd_context_t * context)
{
  do_site_print_file(mainConfig->site_config.file_vfs,NULL,NULL,context);

  return 0;
}

/********************* do_site_vfsadd **********************/
/** vfsadd |/home/vfsroot|/physical/path| +O =user
 */

int do_site_vfsadd(char * command_line, wzd_context_t * context)
{
  char *vpath, *ppath, *target;
/*  int i;*/
  int ret;
  char sep;
  const char *ptr;
  char * dstptr;
  unsigned int dstlen, length;
  char buffer[1024];

  strncpy(buffer,command_line,1024);

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

int do_site_vfsdel(char * command_line, wzd_context_t * context)
{
  int ret;

  if (command_line[0]!=0)
    ret = vfs_remove( &mainConfig->vfs, command_line );
  else ret = 1;

  if (ret==1)
    send_message_with_args(501,context,"site vfsdel /home/vfsroot");
  else if (ret==2)
  {
    char tmp[80];
    snprintf( tmp, 80, "vfs %s does not exist", command_line );
    send_message_with_args(501,context,tmp);
  } else
    send_message_with_args(200,context,"VFSDEL command ok");
  
  return 0;
}

/* TODO XXX FIXME tests missing
 */
static int do_internal_wipe(const char *filename, wzd_context_t * context)
{
  struct stat s;
  int ret;
#ifndef _MSC_VER
  DIR * dir;
  struct dirent * entry;
#else
  HANDLE dir;
  WIN32_FIND_DATA fileData;
  int finished;
  char dirfilter[MAX_PATH];
#endif
  char *dir_filename;
  char buffer[1024];
  char path[1024];
  char * ptr;

  split_filename(filename,path,NULL,1024,0);

  if (stat(filename,&s)) return -1;
  
  if (S_ISREG(s.st_mode) || S_ISLNK(s.st_mode)) {
    ret = file_remove(filename,context);
    if (ret) return 1;
  }
  if (S_ISDIR(s.st_mode))
  {
    strncpy(buffer,filename,sizeof(buffer));
    ptr = buffer + strlen(buffer);
    *ptr++ = '/';
#ifndef _MSC_VER
    dir = opendir(filename);
#else
    snprintf(dirfilter,2048,"%s/*",filename);
    if ((dir = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return 0;
#endif

#ifndef _MSC_VER
    while ( (entry=readdir(dir)) )
    {
      dir_filename = entry->d_name;
#else
    finished = 0;
    while (!finished)
    {
      dir_filename = fileData.cFileName;
#endif
      if (strcmp(dir_filename,".")==0 || strcmp(dir_filename,"..")==0)
        DIR_CONTINUE
      if (strlen(buffer)+strlen(dir_filename)>=1024) { closedir(dir); return 1; }
      strncpy(ptr,dir_filename,256);

      if (stat(buffer,&s)) { closedir(dir); return -1; }
      if (S_ISREG(s.st_mode) || S_ISLNK(s.st_mode)) {
        ret = file_remove(buffer,context);
        if (ret) { closedir(dir); return 1; }
      }
      if (S_ISDIR(s.st_mode)) {
        ret = do_internal_wipe(buffer,context);
        if (ret) { closedir(dir); return 1; }
      }
#ifdef _MSC_VER
      if (!FindNextFile(dir,&fileData))
      {
        if (GetLastError() == ERROR_NO_MORE_FILES)
          finished = 1;
      }
#endif
    }

    closedir(dir);
    ret = rmdir(filename);
    if (ret) return 1;
  }

  return 0;
}

/********************* do_site_wipe ************************/
/** wipe: [-r] file1 [file2 ...]
 */

int do_site_wipe(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * firstarg, *filename;
  int is_recursive;
  int ret;
/*  wzd_user_t user;*/
/*  int uid;*/
/*  struct stat s;*/

  ptr = command_line;
  firstarg = strtok_r(command_line," \t\r\n",&ptr);
  if (!firstarg) {
    do_site_help("wipe",context);
    return 1;
  }
  /* check if wiping is recursive */
  if ( strcasecmp(firstarg,"-r")==0 ) {
    is_recursive=1;
    filename = strtok_r(NULL," \t\r\n",&ptr);
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
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
    /* wipe file | if_recursive dir/file */
    ret = do_internal_wipe(buffer,context);
    if (ret) {
      ret = send_message_with_args(501,context,"WIPE failed");
      return 1;
    }
  }
  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) );

  ret = send_message_with_args(200,context,"File(s) wiped");

  return 0;
}

/********************* site_init ***************************/
int site_command_add(wzd_site_fct_t **site_list, const char *name, site_fct_t fct)
{
  wzd_site_fct_t * new_site, *current;

  new_site = malloc(sizeof(wzd_site_fct_t));
  if (!new_site) return 1;
  new_site->name = strdup(name);
  new_site->fct = fct;
  new_site->next_site_fct = NULL;

  current = *site_list;

  if (!current) {
    *site_list = new_site;
    return 0;
  }

  /* tail insertion */
  while (current->next_site_fct)
    current = current->next_site_fct;

  current->next_site_fct = new_site;

  return 0;
}

void site_cleanup(wzd_config_t * config)
{
  wzd_site_fct_t * next, *current;

  current = mainConfig->site_list;

  while (current)
  {
    next = current->next_site_fct;
    free(current->name);
    free(current);
    current = next;
  }
  mainConfig->site_list = NULL;
}

site_fct_t site_find(const char *name)
{
  wzd_site_fct_t * current;

  current = mainConfig->site_list;
  while(current)
  {
    if (strcasecmp(current->name,name)==0) return current->fct;
    current = current->next_site_fct;
  }

  return NULL;
}

int site_init(wzd_config_t * config)
{
  if (site_command_add(&config->site_list,"ADDIP",&do_site_addip)) return 1;
  if (site_command_add(&config->site_list,"ADDUSER",&do_site_adduser)) return 1;
  if (site_command_add(&config->site_list,"BACKEND",&do_site_backend)) return 1;
  if (site_command_add(&config->site_list,"CHACL",&do_site_chacl)) return 1;
  if (site_command_add(&config->site_list,"CHANGE",&do_site_change)) return 1;
  if (site_command_add(&config->site_list,"CHANGEGRP",&do_site_changegrp)) return 1;
  if (site_command_add(&config->site_list,"CHECKPERM",&do_site_checkperm)) return 1;
  if (site_command_add(&config->site_list,"CHGRP",&do_site_chgrp)) return 1;
  if (site_command_add(&config->site_list,"CHMOD",&do_site_chmod)) return 1;
  if (site_command_add(&config->site_list,"CHOWN",&do_site_chown)) return 1;
  if (site_command_add(&config->site_list,"CHPASS",&do_site_chpass)) return 1;
  if (site_command_add(&config->site_list,"CHRATIO",&do_site_chratio)) return 1;
  /* do_site_close ? */
  if (site_command_add(&config->site_list,"COLOR",&do_site_color)) return 1;
  if (site_command_add(&config->site_list,"DELIP",&do_site_delip)) return 1;
  if (site_command_add(&config->site_list,"DELUSER",&do_site_deluser)) return 1;
  if (site_command_add(&config->site_list,"FLAGS",&do_site_flags)) return 1;
  if (site_command_add(&config->site_list,"FREE",&do_site_free)) return 1;
  if (site_command_add(&config->site_list,"GINFO",&do_site_ginfo)) return 1;
  if (site_command_add(&config->site_list,"GIVE",&do_site_give)) return 1;
  if (site_command_add(&config->site_list,"GROUP",&do_site_group)) return 1;
  if (site_command_add(&config->site_list,"GRPADD",&do_site_grpadd)) return 1;
  if (site_command_add(&config->site_list,"GRPADDIP",&do_site_grpaddip)) return 1;
  if (site_command_add(&config->site_list,"GRPCHANGE",&do_site_grpchange)) return 1;
  if (site_command_add(&config->site_list,"GRPDEL",&do_site_grpdel)) return 1;
  if (site_command_add(&config->site_list,"GRPDELIP",&do_site_grpdelip)) return 1;
  if (site_command_add(&config->site_list,"GRPKILL",&do_site_grpkill)) return 1;
  if (site_command_add(&config->site_list,"GRPRATIO",&do_site_grpratio)) return 1;
  if (site_command_add(&config->site_list,"GRPREN",&do_site_grpren)) return 1;
  if (site_command_add(&config->site_list,"GSINFO",&do_site_gsinfo)) return 1;
  if (site_command_add(&config->site_list,"IDLE",&do_site_idle)) return 1;
  if (site_command_add(&config->site_list,"INVITE",&do_site_invite)) return 1;
  if (site_command_add(&config->site_list,"KICK",&do_site_kick)) return 1;
  if (site_command_add(&config->site_list,"KILL",&do_site_kill)) return 1;
  if (site_command_add(&config->site_list,"LINK",&do_site_link)) return 1;
  if (site_command_add(&config->site_list,"MSG",&do_site_msg)) return 1;
  if (site_command_add(&config->site_list,"PERM",&do_site_perm)) return 1;
  if (site_command_add(&config->site_list,"PURGE",&do_site_purgeuser)) return 1;
  if (site_command_add(&config->site_list,"READD",&do_site_readduser)) return 1;
  if (site_command_add(&config->site_list,"RELOAD",&do_site_reload)) return 1;
  /* reopen */
  /* rules */
  if (site_command_add(&config->site_list,"RUSAGE",&do_site_rusage)) return 1;
  /* savecfg */
  if (site_command_add(&config->site_list,"SAVECFG",&do_site_savecfg)) return 1;
  /* swho */
  if (site_command_add(&config->site_list,"TAGLINE",&do_site_tagline)) return 1;
  if (site_command_add(&config->site_list,"TAKE",&do_site_take)) return 1;
  if (site_command_add(&config->site_list,"TEST",&do_site_test)) return 1;
  if (site_command_add(&config->site_list,"UNLOCK",&do_site_unlock)) return 1;
  /* user */
  /* users */
  if (site_command_add(&config->site_list,"UTIME",&do_site_utime)) return 1;
  if (site_command_add(&config->site_list,"VERSION",&do_site_version)) return 1;
  /* vfs */
  if (site_command_add(&config->site_list,"VFSLS",&do_site_vfsls)) return 1;
  if (site_command_add(&config->site_list,"VFSADD",&do_site_vfsadd)) return 1;
  if (site_command_add(&config->site_list,"VFSDEL",&do_site_vfsdel)) return 1;
  /* who */
  if (site_command_add(&config->site_list,"WIPE",&do_site_wipe)) return 1;
  /* uptime */
  /* shutdown */
  return 0;
}

/********************* do_site *****************************/

int do_site(char *command, char *command_line, wzd_context_t * context)
{
  char buffer[4096];
  char *token, *ptr;
  int ret=0;
  site_fct_t fct;
  wzd_hook_reply_t hook_reply;
  int first_reply;
  
  token = ptr = command_line;
  token = strtok_r(command_line," \t\r\n",&ptr);

  if (!token || strlen(token)==0) {
    ret = send_message_with_args(501,context,"SITE command failed");
    return 1;
  }

  /* check general site permission */
  {
    char permname_buf[256];

#ifdef DEBUG
    if (strlen(token)>255) {
      fprintf(stderr,"*** WARNING *** permissions name too long > 255 - truncated : '%s'\n",token);
    }
#endif
    strcpy(permname_buf,"site_");
    strncpy(permname_buf+5,token,250); /* 250 = 256 - strlen("site_") - 1 */

    if (perm_check(permname_buf,context,mainConfig) == 1) {
      ret = send_message_with_args(501,context,"Permission Denied");
      return 1;
    }
  }

  fct = site_find(token);

  if (fct)
    return (*fct)(command_line+strlen(token)+1,context);

/******************** CLOSE *********************/
  if (strcasecmp(token,"CLOSE")==0) {
    mainConfig->site_closed = 1;
    ret = send_message_with_args(250,context,"SITE: ","server is now closed");
    return 0;
  } else
/******************* GINFO **********************/
  if (strcasecmp(token,"GROUPS")==0) {
    do_site_print_file(mainConfig->site_config.file_groups,NULL,NULL,context);
    return 0;
  } else
/******************* HELP ***********************/
  if (strcasecmp(token,"HELP")==0) {
    /* TODO check if there are arguments, and call specific help */
    do_site_print_file(mainConfig->site_config.file_help,NULL,NULL,context);
    return 0;
  } else
/******************** REOPEN ********************/
  if (strcasecmp(token,"REOPEN")==0) {
    mainConfig->site_closed = 0;
    ret = send_message_with_args(250,context,"SITE: ","server is now opened");
    return 0;
  } else
/******************* RULES **********************/
  if (strcasecmp(token,"RULES")==0) {
    do_site_print_file(mainConfig->site_config.file_rules,NULL,NULL,context);
    return 0;
  } else
/******************* SWHO ***********************/
  if (strcasecmp(token,"SWHO")==0) {
    do_site_print_file(mainConfig->site_config.file_swho,NULL,NULL,context);
    return 0;
  } else
/******************* USER ***********************/
  if (strcasecmp(token,"USER")==0) {
    do_site_user(command_line+5,context); /* 5 = strlen("user")+1 */
    return 0;
  } else
/******************* USERS **********************/
  if (strcasecmp(token,"USERS")==0) {
    do_site_print_file(mainConfig->site_config.file_users,NULL,NULL,context);
    return 0;
  } else
/******************* WHO ************************/
  if (strcasecmp(token,"WHO")==0) {
    do_site_print_file(mainConfig->site_config.file_who,NULL,NULL,context);
    return 0;
  } else
/******************* UPTIME *********************/
  if (strcasecmp(token,"UPTIME")==0) {
    time_t t;
    time(&t);
    t = t - mainConfig->server_start;
    snprintf(buffer,4096,"Uptime: %s",time_to_str(t));
    ret = send_message_with_args(200,context,buffer);
    return 0;
  }
/******************* SHUTDOWN *******************/
#ifndef WZD_MULTITHREAD
  else if (strcasecmp(token,"SHUTDOWN")==0) {
    mainConfig->serverstop = 1;
    ret = send_message_with_args(250,context,"SITE: ","server will shutdown after you logout");
    return 0;
  }
#endif /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
  else if (strcasecmp(token,"SHUTDOWN")==0) {
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
      hook_reply = (*(site_hook)hook->hook)(EVENT_SITE,context,token,command_line+strlen(token)+1);
      /** \todo implement and use constants: HANDLED, NEXT, ERROR or something like .. */
      if (hook_reply != EVENT_IGNORED && hook_reply != EVENT_NEXT) break;
    }
    /* custom site commands */
    if (hook->opt && hook->external_command && strcasecmp(hook->opt,token)==0) {
      if (first_reply) { send_message_raw("200-\r\n",context); first_reply=0; }
      ret = hook_call_custom(context, hook, 200, command_line+strlen(token)+1);
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
    out_log(LEVEL_INFO, "Someone reported errors for site command %s\n", token);
    ret = send_message_with_args(200,context,"SITE command failed");
    break;
  case EVENT_NEXT:
    /* we do not know how to reply .. trying 200 */
    out_log(LEVEL_INFO, "Received only EVENT_NEXT for site command %s\n", token);
    out_log(LEVEL_INFO, "The last handler should send EVENT_CATCHED\n");
    ret = send_message_with_args(200,context,"SITE command executed (with warnings)");
    break;
  case EVENT_IGNORED:
    ret = send_message_with_args(250,context,"SITE ","command unknown");
    break;
  }

  return 0;
}
