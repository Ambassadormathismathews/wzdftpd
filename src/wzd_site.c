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
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <signal.h>
#include <utime.h>
#include <fcntl.h>
#include <dirent.h> /* opendir, readdir, closedir */

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_site.h"
#include "wzd_site_group.h"
#include "wzd_site_user.h"
#include "wzd_vfs.h"
#include "wzd_file.h"
#include "wzd_perm.h"
#include "wzd_mod.h"
#include "wzd_cache.h"


extern int serverstop;
extern time_t server_start;

#define	BUFFER_LEN	4096

typedef int (*site_fct_t)(char *cl, wzd_context_t *context);

struct wzd_site_fct_t {
  char *name;
  site_fct_t fct;

  struct wzd_site_fct_t * next_site_fct;
};

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

/*  libtest();*/

  ret = 0;

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
    send_message_raw("501-operations on backend\r\n",context);
    send_message_raw("501-site backend command backend_name\r\n",context);
    send_message_raw("501-command can be one of:\r\n",context);
    send_message_raw("501- close   (unloads backend)\r\n",context);
    send_message_raw("501- commit  (commits changes synchronously)\r\n",context);
    send_message_raw("501- init    (loads new backend)\r\n",context);
    send_message_raw("501- reload  (close and init)\r\n",context);
    send_message_raw("501-\r\n",context);
    send_message_raw("501-e.g: site backend commit plaintext\r\n",context);
    send_message_raw("501-\r\n",context);
    send_message_raw("501- THIS IS A DANGEROUS COMMAND\r\n",context);
  } else
  if (strcasecmp(site_command,"checkperm")==0) {
    send_message_raw("501-checks access for a user on a file/dir\r\n",context);
    send_message_raw("501-site checkperm user file rights\r\n",context);
    send_message_raw("501- rights can be one of:\r\n",context);
    send_message_raw("501- RIGHT_LIST\r\n",context);
    send_message_raw("501- RIGHT_CWD\r\n",context);
    send_message_raw("501- RIGHT_RETR\r\n",context);
    send_message_raw("501- RIGHT_STOR\r\n",context);
    send_message_raw("501- RIGHT_RNFR\r\n",context);
    send_message_raw("501-e.g: site checkperm toto dir RIGHT_CWD\r\n",context);
  } else
  if (strcasecmp(site_command,"chmod")==0) {
    send_message_raw("501-change permissions of a file or directory\r\n",context);
    send_message_raw("501-usage: site chmod mode file1 [file2 ...]\r\n",context);
    send_message_raw("501-e.g: site chmod 644 file1\r\n",context);
  } else
  if (strcasecmp(site_command,"chown")==0) {
    send_message_raw("501-change the owner of a file or directory\r\n",context);
    send_message_raw("501-usage: site chown user file1 [file2 ...]\r\n",context);
    send_message_raw("501-e.g: site chown toto file1\r\n",context);
  } else
  if (strcasecmp(site_command,"chpass")==0) {
    send_message_raw("501-change the password of a user\r\n",context);
    send_message_raw("501-site chpass user new_pass\r\n",context);
  } else
  if (strcasecmp(site_command,"grpkill")==0) {
    send_message_raw("501-kill all connected users from a group\r\n",context);
    send_message_raw("501-site grpkill groupname\r\n",context);
  } else
  if (strcasecmp(site_command,"user")==0) {
    send_message_raw("501-show user info\r\n",context);
    send_message_raw("501-site user username\r\n",context);
  } else
  {
    snprintf(buffer,BUFFER_LEN,"501-Syntax error in command %s\r\n",site_command);
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

  snprintf(buffer,BUFFER_LEN,"CHACL: '%s'",command_line);
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

  snprintf(buffer,BUFFER_LEN,"CHMOD: '%s'",command_line);
  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/********************* do_site_chown ***********************/
/** chown: user file1 [file2 ...]
 */

void do_site_chown(char *command_line, wzd_context_t * context)
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
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
/*    buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
    _setPerm(buffer,0,username,0,0,0,context);
  }

  snprintf(buffer,BUFFER_LEN,"CHOWN: '%s'",command_line);
  ret = send_message_with_args(200,context,buffer);
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

  ret = backend_chpass(username,new_pass);

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

  if (checkpath(".",buffer,context)) {
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

  snprintf(buffer,2047,"[FREE] + [home: %.2f / %.2f %c] -",free,total,unit);

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

  strcpy(buffer,context->currentpath);
  stripdir(buffer,path,2047);

  log_message("INVITE","\"%s\" \"%s\" \"%s\" \"%s\"",
      path, /* ftp-absolute path */
      user->username,
      (group->groupname)?group->groupname:"No Group",
      ircnick);

  ret = send_message_with_args(200,context,"SITE INVITE command ok");
  return 0;
}



/********************* do_site_print_file ******************/
void do_site_print_file(const char *filename, wzd_user_t *user, wzd_group_t *group, wzd_context_t *context)
{
  wzd_cache_t * fp;
  char * file_buffer;
  unsigned int size, filesize;
  fp = wzd_cache_open(filename,O_RDONLY,0644);
  filesize = wzd_cache_getsize(fp);
  file_buffer = malloc(filesize+1);
  if ( (size=wzd_cache_read(fp,file_buffer,filesize)!=filesize) )
  {
    fprintf(stderr,"Could not read file %s read %u instead of %u (%s:%d)\n",filename,size,filesize,__FILE__,__LINE__);
    wzd_cache_close(fp);
    return;
  }
  file_buffer[filesize]='\0';

  /* send header */
  send_message_raw("200-\r\n",context);

  cookie_parse_buffer(file_buffer,user,group,context);

  wzd_cache_close(fp);

  send_message_raw("200 \r\n",context);

  free(file_buffer);
}

/********************* do_site_reload **********************/

int do_site_reload(char * ignored, wzd_context_t * context)
{
  int ret;
  pid_t pid;
  char buffer[256];

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

  ret = send_message_raw("200-Sending SIGHUP to main server, waiting for result\r\n",context);
  ret = kill(pid,SIGHUP);
  if (ret)
    snprintf(buffer,255,"200 ERROR kill returned %d (%s)\r\n",ret,strerror(errno));
  else
    snprintf(buffer,255,"200 kill returned ok\r\n");
  ret = send_message_raw(buffer,context);
  return 0;
}

/********************* do_site_rusage **********************/

int do_site_rusage(char * ignored, wzd_context_t * context)
{
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
  return 0;
}

#if 0
/********************* do_site_sfv *************************/
/* sfv: add / check / create
 */
void do_site_sfv(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * command, *name;
  int ret;
  wzd_sfv_file sfv;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help("sfv",context);
    return;
  }
  name = strtok_r(NULL," \t\r\n",&ptr);

  if (!name) {
    do_site_help("sfv",context);
    return;
  }

  /* convert file to absolute path, remember sfv wants ABSOLUTE paths ! */
  if ( (ret = checkpath(name,buffer,context)) != 0 ) {
    do_site_help("sfv",context);
    return;
  }
/*  buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
  sfv_init(&sfv);

  if (strcasecmp(command,"add")==0) {
    ret = send_message_with_args(200,context,"Site SFV add successfull");
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
    ret = send_message_with_args(200,context,"Site SFV create successfull");
  }
  
  sfv_free(&sfv);
}
#endif /* 0 */

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
  extern char *strptime (__const char *__restrict __s,
    __const char *__restrict __fmt, struct tm *__tp);
  char buffer[BUFFER_LEN];
  char * ptr;
  char * filename;
  char * new_atime, * new_mtime, * new_ctime;
  struct tm tm_atime, tm_mtime, tm_ctime;
  struct utimbuf utime_buf;
  char * timezone;
  int ret;
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
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
  send_message_with_args(200,context,WZD_VERSION_STR);
  return 0;
}

int do_internal_wipe(const char *filename, wzd_context_t * context)
{
  struct stat s;
  int ret;
  DIR * dir;
  struct dirent * entry;
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
    strcpy(buffer,filename);
    ptr = buffer + strlen(buffer);
    *ptr++ = '/';
    dir = opendir(filename);

    while ( (entry=readdir(dir)) )
    {
      if (strcmp(entry->d_name,".")==0 || strcmp(entry->d_name,"..")==0)
	continue;
      if (strlen(buffer)+strlen(entry->d_name)>=1024) return 1;
      strncpy(ptr,entry->d_name,256);

      if (stat(buffer,&s)) return -1;
      if (S_ISREG(s.st_mode) || S_ISLNK(s.st_mode)) {
	ret = file_remove(buffer,context);
	if (ret) return 1;
      }
      if (S_ISDIR(s.st_mode)) {
	ret = do_internal_wipe(buffer,context);
	if (ret) return 1;
      }
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
  wzd_user_t user;
  int uid;
  struct stat s;

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
    /* TODO XXX FIXME wipe file | if_recursive dir/file */
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
  if (site_command_add(&config->site_list,"ADDUSER",&do_site_adduser)) return 1;
  if (site_command_add(&config->site_list,"ADDIP",&do_site_addip)) return 1;
  if (site_command_add(&config->site_list,"BACKEND",&do_site_backend)) return 1;
  if (site_command_add(&config->site_list,"CHANGE",&do_site_change)) return 1;
  if (site_command_add(&config->site_list,"CHACL",&do_site_chacl)) return 1;
  if (site_command_add(&config->site_list,"CHECKPERM",&do_site_checkperm)) return 1;
  if (site_command_add(&config->site_list,"CHGRP",&do_site_chgrp)) return 1;
  if (site_command_add(&config->site_list,"CHMOD",&do_site_chmod)) return 1;
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
  if (site_command_add(&config->site_list,"GRPADD",&do_site_grpadd)) return 1;
  if (site_command_add(&config->site_list,"GRPADDIP",&do_site_grpaddip)) return 1;
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
  if (site_command_add(&config->site_list,"PURGE",&do_site_purgeuser)) return 1;
  if (site_command_add(&config->site_list,"READD",&do_site_readduser)) return 1;
  if (site_command_add(&config->site_list,"RELOAD",&do_site_reload)) return 1;
  /* reopen */
  /* rules */
  if (site_command_add(&config->site_list,"RUSAGE",&do_site_rusage)) return 1;
  /* swho */
  if (site_command_add(&config->site_list,"TAGLINE",&do_site_tagline)) return 1;
  if (site_command_add(&config->site_list,"TAKE",&do_site_take)) return 1;
  if (site_command_add(&config->site_list,"TEST",&do_site_test)) return 1;
  /* user */
  /* users */
  if (site_command_add(&config->site_list,"UTIME",&do_site_utime)) return 1;
  if (site_command_add(&config->site_list,"VERSION",&do_site_version)) return 1;
  /* who */
  if (site_command_add(&config->site_list,"WIPE",&do_site_wipe)) return 1;
  /* uptime */
  /* shutdown */
  return 0;
}

/********************* do_site *****************************/

int do_site(char *command_line, wzd_context_t * context)
{
  char buffer[4096];
  char *token, *ptr;
  int ret=0;
  site_fct_t fct;
  
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

    if (perm_check(permname_buf,context,mainConfig)) {
      ret = send_message_with_args(501,context,"Permission Denied");
      return 1;
    }
  }

  fct = site_find(token);

  if (fct)
    return (*fct)(command_line+strlen(token)+1,context);

#if 0
/******************* ADDUSER ********************/
  if (strcasecmp(token,"ADDUSER")==0) {
    return do_site_adduser(command_line+8,context); /* 8 = strlen("adduser")+1 */
  } else
/******************** ADDIP *********************/
  if (strcasecmp(token,"ADDIP")==0) {
    return do_site_addip(command_line+6,context); /* 6 = strlen("addip")+1 */
  } else
/******************* BACKEND ********************/
  if (strcasecmp(token,"BACKEND")==0) {
    do_site_backend(command_line+8,context); /* 8 = strlen("backend")+1 */
    return 0;
  } else
/******************* CHANGE *********************/
  if (strcasecmp(token,"CHANGE")==0) {
    return do_site_change(command_line+7,context); /* 7 = strlen("change")+1 */
  } else
/******************* CHACL **********************/
  if (strcasecmp(token,"CHACL")==0) {
    do_site_chacl(command_line+6,context); /* 6 = strlen("chacl")+1 */
    return 0;
  } else
/****************** CHECKPERM *******************/
  if (strcasecmp(token,"CHECKPERM")==0) {
    do_site_checkperm(command_line+10,context); /* 10 = strlen("checkperm")+1 */
    return 0;
  } else
/******************* CHGRP **********************/
  if (strcasecmp(token,"CHGRP")==0) {
    return do_site_chgrp(command_line+6,context); /* 6 = strlen("chgrp")+1 */
  } else
/******************* CHMOD **********************/
  if (strcasecmp(token,"CHMOD")==0) {
    do_site_chmod(command_line+6,context); /* 6 = strlen("chmod")+1 */
    return 0;
  } else
/******************* CHOWN **********************/
  if (strcasecmp(token,"CHOWN")==0) {
    do_site_chown(command_line+6,context); /* 6 = strlen("chown")+1 */
    return 0;
  } else
/******************* CHPASS *********************/
  if (strcasecmp(token,"CHPASS")==0) {
    do_site_chpass(command_line+7,context); /* 7 = strlen("chpass")+1 */
    return 0;
  } else
/******************** RATIO *********************/
  if (strcasecmp(token,"CHRATIO")==0) {
    return do_site_chratio(command_line+8,context); /* 8 = strlen("chratio")+1 */
  } else
#endif
/******************** CLOSE *********************/
  if (strcasecmp(token,"CLOSE")==0) {
    mainConfig->site_closed = 1;
    ret = send_message_with_args(250,context,"SITE:","server is now closed");
    return 0;
  } else
#if 0
/******************** DELIP *********************/
  if (strcasecmp(token,"DELIP")==0) {
    return do_site_delip(command_line+6,context); /* 6 = strlen("delip")+1 */
  } else
/******************* DELUSER ********************/
  if (strcasecmp(token,"DELUSER")==0) {
    return do_site_deluser(command_line+8,context); /* 8 = strlen("deluser")+1 */
  } else
/******************* FLAGS **********************/
  if (strcasecmp(token,"FLAGS")==0) {
    return do_site_flags(command_line+6,context); /* 6 = strlen("flags")+1 */
  } else
/******************* FREE ***********************/
  if (strcasecmp(token,"FREE")==0) {
    return do_site_free(command_line+5,context); /* 5 = strlen("free")+1 */
  } else
/******************* GINFO **********************/
  if (strcasecmp(token,"GINFO")==0) {
    return do_site_ginfo(command_line+6,context); /* 6 = strlen("ginfo")+1 */
  } else
/******************* GRPADD *********************/
  if (strcasecmp(token,"GRPADD")==0) {
    return do_site_grpadd(command_line+7,context); /* 7 = strlen("grpadd")+1 */
  } else
/******************* GRPADDIP *******************/
  if (strcasecmp(token,"GRPADDIP")==0) {
    return do_site_grpaddip(command_line+9,context); /* 9 = strlen("grpaddip")+1 */
  } else
/******************* GRPDEL *********************/
  if (strcasecmp(token,"GRPDEL")==0) {
    return do_site_grpdel(command_line+7,context); /* 7 = strlen("grpdel")+1 */
  } else
/******************* GRPDELIP *******************/
  if (strcasecmp(token,"GRPDELIP")==0) {
    return do_site_grpdelip(command_line+9,context); /* 9 = strlen("grpdelip")+1 */
  } else
/******************* GRPRATIO *******************/
  if (strcasecmp(token,"GRPRATIO")==0) {
    return do_site_grpratio(command_line+9,context); /* 9 = strlen("grpratio")+1 */
  } else
/******************* GSINFO *********************/
  if (strcasecmp(token,"GSINFO")==0) {
    return do_site_gsinfo(command_line+7,context); /* 7 = strlen("gsinfo")+1 */
  } else
#endif
/******************* HELP ***********************/
  if (strcasecmp(token,"HELP")==0) {
    /* TODO check if there are arguments, and call specific help */
    do_site_print_file(mainConfig->site_config.file_help,NULL,NULL,context);
    return 0;
  } else
#if 0
/******************* IDLE ***********************/
  if (strcasecmp(token,"IDLE")==0) {
    return do_site_idle(command_line+5,context); /* 5 = strlen("idle")+1 */
  } else
/******************** INVITE ********************/
  if (strcasecmp(token,"INVITE")==0) {
    do_site_invite(command_line+7,context); /* 7 = strlen("invite")+1 */
    return 0;
  } else
/******************* KICK ***********************/
  if (strcasecmp(token,"KICK")==0) {
    return do_site_kick(command_line+5,context); /* 5 = strlen("kick")+1 */
  } else
/******************* KILL ***********************/
  if (strcasecmp(token,"KILL")==0) {
    return do_site_kill(command_line+5,context); /* 5 = strlen("kill")+1 */
  } else
/******************** PURGE *********************/
  if (strcasecmp(token,"PURGE")==0) {
    return do_site_purgeuser(command_line+6,context); /* 6 = strlen("purge")+1 */
  } else
/******************** READD *********************/
  if (strcasecmp(token,"READD")==0) {
    return do_site_readduser(command_line+6,context); /* 6 = strlen("readd")+1 */
  } else
/******************* RELOAD *********************/
  if (strcasecmp(token,"RELOAD")==0) {
    do_site_reload(context); /* 7 = strlen("reload")+1 */
    return 0;
  } else
#endif
/******************** REOPEN ********************/
  if (strcasecmp(token,"REOPEN")==0) {
    mainConfig->site_closed = 0;
    ret = send_message_with_args(250,context,"SITE:","server is now opened");
    return 0;
  } else
/******************* RULES **********************/
  if (strcasecmp(token,"RULES")==0) {
    do_site_print_file(mainConfig->site_config.file_rules,NULL,NULL,context);
    return 0;
  } else
#if 0
/********************* SFV **********************/
  if (strcasecmp(token,"SFV")==0) {
    do_site_sfv(command_line+4,context); /* 4 = strlen("sfv")+1 */
    return 0;
  } else
#endif /* 0 */
/******************* SWHO ***********************/
  if (strcasecmp(token,"SWHO")==0) {
    do_site_print_file(mainConfig->site_config.file_swho,NULL,NULL,context);
    return 0;
  } else
#if 0
/******************** TAGLINE *******************/
  if (strcasecmp(token,"TAGLINE")==0) {
    return do_site_tagline(command_line+8,context); /* 8 = strlen("tagline")+1 */
  } else
/******************* TEST ***********************/
  if (strcasecmp(token,"TEST")==0) {
    do_site_test(command_line+5,context); /* 5 = strlen("test")+1 */
    return 0;
  } else
#endif /* 0 */
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
#if 0
/******************* UTIME **********************/
  if (strcasecmp(token,"UTIME")==0) {
    do_site_utime(command_line+6,context); /* 6 = strlen("utime")+1 */
    return 0;
  } else
/******************* VERSION ********************/
  if (strcasecmp(token,"VERSION")==0) {
    do_site_version(NULL,context); /* 8 = strlen("version")+1 */
    return 0;
  } else
#endif /* 0 */
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
    ret = send_message_with_args(250,context,"SITE:","server will shutdown after you logout");
    return 0;
  }
#endif /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
  else if (strcasecmp(token,"SHUTDOWN")==0) {
    ret = send_message_with_args(250,context,"SITE:","server will shutdown NOW");
    mainConfig->serverstop = 1;
    return 0;
  }
#endif /* WZD_MULTITHREAD */


  FORALL_HOOKS(EVENT_SITE)
    typedef int (*site_hook)(unsigned long, wzd_context_t *, const char*,const char *);
    if (hook->hook)
      ret = (*(site_hook)hook->hook)(EVENT_SITE,context,token,command_line+strlen(token)+1);
    /* custom site commands */
    if (hook->opt && hook->external_command && strcasecmp(hook->opt,token)==0) {
      send_message_raw("200-\r\n",context);
      ret = hook_call_custom(context,hook,command_line+strlen(token)+1);
      if (!ret) {
	ret = send_message_with_args(200,context,"SITE command ok");
      } else {
	ret = send_message_with_args(200,context,"SITE command failed");
      }
      return 0; /* there can be only one site command ! */
    }
  END_FORALL_HOOKS

  if (ret)
    ret = send_message_with_args(250,context,"SITE","command unknown, ok");

  return 0;
}
