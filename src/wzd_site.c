#include "wzd.h"

extern int serverstop;
extern time_t server_start;

#define	BUFFER_LEN	4096

/********************* do_site_test ************************/

void do_site_test(const char *command, wzd_context_t * context)
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
}

/********************* do_site_help ************************/

void do_site_help(const char *site_command, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];

  snprintf(buffer,BUFFER_LEN,"Syntax error in command %s",site_command);
  send_message_with_args(501,context,buffer);
}

/********************* do_site_backend *********************/
/* backend: close / reload / init / commit
 */
void do_site_backend(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * command, *name;
  int ret;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help("backend",context);
    return;
  }
  name = strtok_r(NULL," \t\r\n",&ptr);
  if (!name) {
    do_site_help("backend",context);
    return;
  }
  if (strcasecmp(command,"close")==0) {
    ret = backend_close(name);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not close backend");
    } else {
      ret = send_message_with_args(200,context,"Backend close successfully");
    }
    return;
  } /* close */
  if (strcasecmp(command,"init")==0) {
    int backend_storage;
    ret = backend_init(name,&backend_storage,mainConfig->user_list,HARD_DEF_USER_MAX,mainConfig->group_list,HARD_DEF_GROUP_MAX);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not init backend");
    } else {
      ret = send_message_with_args(200,context,"Backend loaded successfully");
    }
    return;
  } /* init */
  if (strcasecmp(command,"reload")==0) {
    ret = backend_reload(name);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not reload backend ** WARNING you could have NO backend NOW");
    } else {
      ret = send_message_with_args(200,context,"Backend reloaded successfully");
    }
    return;
  } /* reload */
  if (strcasecmp(command,"commit")==0) {
    ret = backend_commit_changes(name);
    if (ret) {
      ret = send_message_with_args(501,context,"Could not commit backend");
    } else {
      ret = send_message_with_args(200,context,"Backend commited successfully");
    }
    return;
  } /* commit */
  do_site_help("backend",context);
}

/********************* do_site_chown ***********************/
/* chown: user file1 [file2 ...]
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
    buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
    _setPerm(buffer,0,username,0,0,context);
  }

  snprintf(buffer,BUFFER_LEN,"CHOWN: '%s'",command_line);
  ret = send_message_with_args(200,context,buffer);
}

/********************* do_site_chmod ***********************/
/* chmod: user mode file1 [file2 ...]
 */

void do_site_chmod(char *command_line, wzd_context_t * context)
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
    do_site_help("chmod",context);
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }
  mode = strtok_r(NULL," \t\r\n",&ptr);
  if (!mode) {
    do_site_help("chmod",context);
    return;
  }
  /* TODO check that mode is ok */
  if (strlen(mode) > 15) {
    do_site_help("chmod",context);
    return;
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
    buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
    _setPerm(buffer,username,0,0,str_perms,context);
  }

  snprintf(buffer,BUFFER_LEN,"CHMOD: '%s'",command_line);
  ret = send_message_with_args(200,context,buffer);
}

/********************* do_site_chpass **********************/
/* chpass: user new_pass
 */

void do_site_chpass(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * username, *new_pass;
  int ret;
  wzd_user_t user;
  int uid;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("chpass",context);
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }

  new_pass = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_pass) {
    do_site_help("chpass",context);
    return;
  }

  ret = backend_chpass(username,new_pass);

  if (ret)
    ret = send_message_with_args(501,context,"An error occurred during password change");
  else
    ret = send_message_with_args(200,context,"Password changed, don't forget to commit changes");
}

/********************* do_site_checkperm *******************/
void do_site_checkperm(const char * commandline, wzd_context_t * context)
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
  if (!username) { send_message_with_args(501,context,"SITE CHECKPERM user file rights"); return; }
  filename = strtok_r(NULL," \t\r\n",&ptr);
  if (!filename) { send_message_with_args(501,context,"SITE CHECKPERM user file rights"); return; }
  perms = strtok_r(NULL,"\r\n",&ptr);
  if (!perms) { send_message_with_args(501,context,"SITE CHECKPERM user file rights"); return; }

  word = right_text2word(perms);
  if (word == 0) {
    send_message_with_args(501,context,"Invalid permission");
    return;
  }

  if (backend_find_user(username,&userstruct,&uid)) {
    send_message_with_args(501,context,"User does not exist");
    return;
  }
  if (uid == -1) userptr = &userstruct;
  else userptr = &mainConfig->user_list[uid];

  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(filename,buffer,context)) {
    send_message_with_args(501,context,"file does not exist");
    return;
  }
 
  buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */

  if (_checkPerm(buffer,word,userptr)==0) {
    strcpy(buffer,"right ok");
  } else {
    strcpy(buffer,"refused");
  }
  
  send_message_with_args(200,context,buffer);
}

/********************* do_site_print_file ******************/
void do_site_print_file(const char * filename, void * param, wzd_context_t * context)
{
  struct stat s;
  char buffer[1024];
  int ret;
  FILE * fp;

  if (strlen(filename)==0) {
    ret = send_message_with_args(501,context,"Tell the admin to configure his site correctly");
    return;
  }

  if (stat(filename,&s)==-1) {
    ret = send_message_with_args(501,context,"Problem reading the rules file - inexistant ? - check your config");
    return;
  }

  fp = fopen(filename,"r");
  if (!fp) {
    ret = send_message_with_args(501,context,"Problem reading the file - check your config");
    return;
  }

  if ( (fgets(buffer,1022,fp)) == NULL) {
    ret = send_message_with_args(501,context,"File is empty");
    return;
  }

  /* send header */
  send_message_raw("200-\r\n",context);

  do {
    if (strncmp(buffer,"%forallusersconnected",strlen("%forallusersconnected"))==0) {
      char * tab_line[256];
      int i, j;
      wzd_context_t * tab_context = context_list;
      for (i=0; i<256; i++) tab_line[i] = NULL;
      i=0;
      while ( (fgets(buffer,1022,fp)) && strncmp(buffer,"%endfor",strlen("%endfor")) ) {
	tab_line[i] = malloc(1024);
	strcpy(tab_line[i],buffer);
	i++;
      } /* while */
      i=0;
      while (i<HARD_USERLIMIT) {
	if (tab_context[i].magic == CONTEXT_MAGIC) {
#if 0
#if BACKEND_STORAGE
          if (tab_context[i].userinfo.flags &&
              strchr(tab_context[i].userinfo.flags,FLAG_HIDDEN) &&
              strcmp(tab_context[i].userinfo.username,context->userinfo.username)!=0 /* do not hide to self ! */
#endif
#endif
          if (mainConfig->user_list[tab_context[i].userid].flags &&
            strchr(mainConfig->user_list[tab_context[i].userid].flags,FLAG_HIDDEN) &&
            tab_context[i].userid != context->userid /* do not hide to self ! */
              )
          { i++; continue; }
	  j=0;
	  while (tab_line[j]) {
	    memcpy(buffer,tab_line[j],1024);
            ret = cookies_replace(buffer,1024,tab_context+i,context); /* TODO test ret */
            send_message_raw(buffer,context);
	    j++;
	  }
	}
	i++;
      } /* while */
      j=0;
      while (tab_line[j]) {
	free(tab_line[j]);
	tab_line[j] = NULL;
      }
      continue;
    } else /* forallusersconnected */
    if (strncmp(buffer,"%forallusers",strlen("%forallusers"))==0) {
      char * tab_line[256];
      int i, j;
      wzd_context_t dummy_context;
      for (i=0; i<256; i++) tab_line[i] = NULL;
      i=0;
      while ( (fgets(buffer,1022,fp)) && strncmp(buffer,"%endfor",strlen("%endfor")) ) {
	tab_line[i] = malloc(1024);
	strcpy(tab_line[i],buffer);
	i++;
      } /* while */
      i=0;
      while (i<HARD_DEF_USER_MAX) {
	if (mainConfig->user_list[i].username[0] != '\0') {
#if 0
#if BACKEND_STORAGE
          if (tab_context[i].userinfo.flags &&
              strchr(tab_context[i].userinfo.flags,FLAG_HIDDEN) &&
              strcmp(tab_context[i].userinfo.username,context->userinfo.username)!=0 /* do not hide to self ! */
#endif
#endif
#if 0
          if (mainConfig->user_list[i].flags &&
            strchr(mainConfig->user_list[i].flags,FLAG_HIDDEN)
            /* XXX do not hide to self ! */
              )
          { i++; continue; }
#endif
	  dummy_context.userid = i;
	  j=0;
	  while (tab_line[j]) {
	    memcpy(buffer,tab_line[j],1024);
            ret = cookies_replace(buffer,1024,&dummy_context,context); /* TODO test ret */
            send_message_raw(buffer,context);
	    j++;
	  }
	}
	i++;
      } /* while */
      j=0;
      while (tab_line[j]) {
	free(tab_line[j]);
	tab_line[j] = NULL;
      }
      continue;
    } /* forallusers */
    ret = cookies_replace(buffer,1024,param,context); /* TODO test ret */
    send_message_raw(buffer,context);
  } while ( (fgets(buffer,1022,fp)) != NULL);

  fclose(fp);
  send_message_raw("200 \r\n",context);
}

void do_site_reload(wzd_context_t * context)
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
    return;
  }
  out_log(LEVEL_CRITICAL,"Target pid: %d\n",pid);

  ret = send_message_raw("200-Sending SIGHUP to main server, waiting for result\r\n",context);
  ret = kill(pid,SIGHUP);
  if (ret)
    snprintf(buffer,255,"200 ERROR kill returned %d (%s)\r\n",ret,strerror(errno));
  else
    snprintf(buffer,255,"200 kill returned ok\r\n");
  ret = send_message_raw(buffer,context);
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
  buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
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
/* user username
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

/*#if BACKEND_STORAGE*/
  do_site_print_file(mainConfig->site_config.file_user,&user_context,context);
/*#endif
  do_site_print_file(mainConfig->site_config.file_user,&mainConfig->user_list[uid],context);*/
}

/********************* do_site_utime ***********************/
/* utime filename YYYYMMDDhhmmss YYYYMMDDhhmmss YYYYMMDDhhmmss UTC
 * change acess time, modification time, modification of status of a file
 */

void do_site_utime(char *command_line, wzd_context_t * context)
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
    user = &mainConfig->user_list[context->userid];

  ptr = command_line;
  filename = strtok_r(command_line," \t\r\n",&ptr);
  if (!filename) {
    do_site_help("utime",context);
    return;
  }
  new_atime = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_atime) {
    do_site_help("utime",context);
    return;
  }
  new_mtime = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_mtime) {
    do_site_help("utime",context);
    return;
  }
  new_ctime = strtok_r(NULL," \t\r\n",&ptr);
  if (!new_ctime) {
    do_site_help("utime",context);
    return;
  }
  timezone = strtok_r(NULL," \t\r\n",&ptr);
  if (!timezone) {
    do_site_help("utime",context);
    return;
  }
  /* TODO check that timezone is UTC */
  ptr=strptime(new_atime,"%Y%m%d%H%M%S",&tm_atime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    return;
  }
  ptr=strptime(new_mtime,"%Y%m%d%H%M%S",&tm_mtime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    return;
  }
  /* TODO ctime is useless in *nix systems ... */
  ptr=strptime(new_ctime,"%Y%m%d%H%M%S",&tm_ctime);
  if (ptr == NULL || *ptr != '\0') {
    do_site_help("utime",context);
    return;
  }
  utime_buf.actime = mktime(&tm_atime);
  utime_buf.modtime = mktime(&tm_mtime);
  /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
  if (checkpath(filename,buffer,context)) { /* path is NOT ok ! */
    ret = send_message_with_args(501,context,"File does not exists");
    return;
  }
  buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
  ret = _checkPerm(buffer,RIGHT_RNFR,user);  
  if (ret) {
    ret = send_message_with_args(501,context,"Access denied");
    return;
  }

  ret = utime(buffer,&utime_buf);

  ret = send_message_with_args(200,context,"UTIME command ok");
}

/********************* do_site_version *********************/

void do_site_version(wzd_context_t * context)
{
  send_message_with_args(200,context,WZD_VERSION_STR);
}

/********************* do_site *****************************/

int do_site(char *command_line, wzd_context_t * context)
{
  char buffer[4096];
  char *token, *ptr;
  int ret=0;
  
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
/******************* HELP ***********************/
  if (strcasecmp(token,"HELP")==0) {
    do_site_print_file(mainConfig->site_config.file_help,NULL,context);
    return 0;
  } else
/******************* IDLE ***********************/
  if (strcasecmp(token,"IDLE")==0) {
    return do_site_idle(command_line+5,context); /* 5 = strlen("idle")+1 */
  } else
#ifdef WZD_MULTIPROCESS
/******************* KICK ***********************/
  if (strcasecmp(token,"KICK")==0) {
    return do_site_kick(command_line+5,context); /* 5 = strlen("kick")+1 */
  } else
/******************* KILL ***********************/
  if (strcasecmp(token,"KILL")==0) {
    return do_site_kill(command_line+5,context); /* 5 = strlen("kill")+1 */
  } else
#endif /* WZD_MULTIPROCESS */
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
/******************* RULES **********************/
  if (strcasecmp(token,"RULES")==0) {
    do_site_print_file(mainConfig->site_config.file_rules,NULL,context);
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
    do_site_print_file(mainConfig->site_config.file_swho,NULL,context);
    return 0;
  } else
/******************** TAGLINE *******************/
  if (strcasecmp(token,"TAGLINE")==0) {
    return do_site_tagline(command_line+8,context); /* 8 = strlen("tagline")+1 */
  } else
/******************* TEST ***********************/
  if (strcasecmp(token,"TEST")==0) {
    do_site_test(command_line+5,context); /* 5 = strlen("test")+1 */
    return 0;
  } else
/******************* USER ***********************/
  if (strcasecmp(token,"USER")==0) {
    do_site_user(command_line+5,context); /* 5 = strlen("user")+1 */
    return 0;
  } else
/******************* USERS **********************/
  if (strcasecmp(token,"USERS")==0) {
    do_site_print_file(mainConfig->site_config.file_users,NULL,context);
    return 0;
  } else
/******************* UTIME **********************/
  if (strcasecmp(token,"UTIME")==0) {
    do_site_utime(command_line+6,context); /* 6 = strlen("utime")+1 */
    return 0;
  } else
/******************* VERSION ********************/
  if (strcasecmp(token,"VERSION")==0) {
    do_site_version(context); /* 8 = strlen("version")+1 */
    return 0;
  } else
/******************* WHO ************************/
  if (strcasecmp(token,"WHO")==0) {
    do_site_print_file(mainConfig->site_config.file_who,NULL,context);
    return 0;
  } else
/******************* UPTIME *********************/
  if (strcasecmp(token,"UPTIME")==0) {
    time_t t;
    time(&t);
    t = t - server_start;
    snprintf(buffer,4096,"Uptime: %s",time_to_str(t));
    ret = send_message_with_args(200,context,buffer);
    return 0;
/******************* SHUTDOWN *******************/
  } else
  if (strcasecmp(token,"SHUTDOWN")==0) {
    mainConfig->serverstop = 1;
    ret = send_message_with_args(250,context,"SITE:","server will shutdown after you logout");
    return 0;
  }

  FORALL_HOOKS(EVENT_SITE)
    typedef int (*site_hook)(unsigned long, wzd_context_t *, const char*,const char *);
    ret = (*(site_hook)hook->hook)(EVENT_SITE,context,token,command_line+strlen(token)+1);
  END_FORALL_HOOKS

  if (ret)
    ret = send_message_with_args(250,context,"SITE","command unknown, ok");

  return 0;
}
