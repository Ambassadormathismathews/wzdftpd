#include "wzd.h"

void do_site_help_adduser(wzd_context_t * context)
{
  send_message_with_args(501,context,"site adduser <user> <password> <homedir> [<backend>]");
}

/* site adduser: adds a new user
 * adduser <user> <password> <homedir> [<backend>]
 */
int do_site_adduser(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username, *password, *homedir;
  int ret;
  wzd_user_t user;
  int uid;
  int i;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_adduser(context);
    return 0;
  }
  password = strtok_r(NULL," \t\r\n",&ptr);
  if (!password) {
    do_site_help_adduser(context);
    return 0;
  }
  homedir = strtok_r(NULL," \t\r\n",&ptr);
  if (!homedir) {
    do_site_help_adduser(context);
    return 0;
  }
  /* TODO read backend */

  /* check if user already exists */
  if ( !backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User already exists");
    return 0;
  }
  /* check if homedir exist */
  {
    struct stat s;
    if (stat(homedir,&s) || !S_ISDIR(s.st_mode)) {
      ret = send_message_with_args(501,context,"Homedir does not exist");
      return 0;
    }
  }

  /* create new user */
  strncpy(user.username,username,255);
  strncpy(user.userpass,password,255);
  strncpy(user.rootpath,homedir,1023);
  user.tagline[0]='\0';
  user.uid=0;
  user.group_num=0;
  user.max_idle_time=0;
  user.userperms=0xffffffff;
  user.flags[0]='\0';
  user.max_ul_speed=0;
  user.max_dl_speed=0;
  user.num_logins=0;
  for (i=0; i<HARD_IP_PER_USER; i++)
    user.ip_allowed[i][0]='\0';
  user.bytes_ul_total=0;
  user.bytes_dl_total=0;

  /* add it to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user,_USER_ALL);

  ret = send_message_with_args(200,context,"User added");
  return 0;
}

void do_site_help_deluser(wzd_context_t * context)
{
  send_message_with_args(501,context,"site deluser <user> [<backend>]");
}

/* site deluser: delete user
 * deluser <user> [<backend>]
 */
int do_site_deluser(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username;
  int ret;
  wzd_user_t user;
  int uid;
  int length;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_deluser(context);
    return 0;
  }
  /* TODO read backend */

  /* check if user already exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* mark user as deleted */
  if (strchr(user.flags,FLAG_DELETED)) {
    ret = send_message_with_args(501,context,"User already marked as deleted");
    return 0;
  }
  length = strlen(user.flags);
  if (length+1 >= MAX_FLAGS_NUM) {
    ret = send_message_with_args(501,context,"Too many flags for user");
    return 0;
  }
  user.flags[length] = FLAG_DELETED;
  user.flags[length+1] = '\0';

  /* commit changes to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user,_USER_FLAGS);

  ret = send_message_with_args(200,context,"User deleted");
  return 0;
}

void do_site_help_readduser(wzd_context_t * context)
{
  send_message_with_args(501,context,"site readduser <user> [<backend>]");
}

/* site readduser: undelete user
 * readduser <user> [<backend>]
 */
int do_site_readduser(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username;
  int ret;
  wzd_user_t user;
  int uid;
  int length;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_readduser(context);
    return 0;
  }
  /* TODO read backend */

  /* check if user already exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* unmark user as deleted */
  if ( (ptr = strchr(user.flags,FLAG_DELETED)) == NULL ) {
    ret = send_message_with_args(501,context,"User is not marked as deleted");
    return 0;
  }
  if (*(ptr+1)) {
    length = strlen(ptr+1);
    memmove(ptr,ptr+1,length);
    *(ptr+length) = '\0';
  } else {
    *ptr = '\0';
  }

  /* commit changes to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user,_USER_FLAGS);

  ret = send_message_with_args(200,context,"User undeleted");
  return 0;
}

/* site purge: delete user permanently
 * purge [<user>] [<backend>]
 */
int do_site_purgeuser(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username;
  int ret;
  wzd_user_t user;
  int uid;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);

  /* TODO read backend */

  if (username) { /* case 1: name was given */
    /* check if user already exists */
    if ( backend_find_user(username,&user,&uid) ) {
      ret = send_message_with_args(501,context,"User does not exist");
      return 0;
    }

    /* unmark user as deleted */
    if ( (ptr = strchr(user.flags,FLAG_DELETED)) == NULL ) {
      ret = send_message_with_args(501,context,"User is not marked as deleted");
      return 0;
    }

    /* commit changes to backend */
    /* FIXME backend name hardcoded */
    backend_mod_user("plaintext",username,NULL,_USER_ALL);
  } else { /* if (username) */
    /* TODO iterate users and purge those marked as deleted */
    ret = send_message_with_args(501,context,"Not yet implemented - you must give a name");
    return 0;
  } /* if (username) */

  ret = send_message_with_args(200,context,"User purged");
  return 0;
}

void do_site_help_addip(wzd_context_t * context)
{
  send_message_with_args(501,context,"site addip <user> <ip>");
}

/* site addip: adds an ip to a user
 * addip <user> <ip>
 */
int do_site_addip(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username, *ip;
  int ret;
  wzd_user_t user;
  int uid;
  int i;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_addip(context);
    return 0;
  }
  ip = strtok_r(NULL," \t\r\n",&ptr);
  if (!ip) {
    do_site_help_addip(context);
    return 0;
  }

  /* check if user  exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* check if ip is already present or included in list, or if it shadows one present */
  for (i=0; i<HARD_IP_PER_USER; i++)
  {
    if (user.ip_allowed[i][0]=='\0') continue;
    if (my_str_compare(ip,user.ip_allowed[i])==1) { /* ip is already included in list */
      ret = send_message_with_args(501,context,"ip is already included in list");
      return 0;
    }
    if (my_str_compare(user.ip_allowed[i],ip)==1) { /* ip will shadow one ore more ip in list */
      ret = send_message_with_args(501,context,"ip will shadow some ip in list, remove them before");
      return 0;
    }
  }

  /* update user */
  for (i=0; i<HARD_IP_PER_USER; i++)
    if (user.ip_allowed[i][0]=='\0') break;

  /* no more slots ? */
  if (i==HARD_IP_PER_USER) {
    ret = send_message_with_args(501,context,"No more slots available - either recompile with more slots, or use them more cleverly !");
    return 0;
  }
  /* TODO check ip validity */
  strncpy(user.ip_allowed[i],ip,MAX_IP_LENGTH-1);

  /* commit to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user,_USER_IP);

  ret = send_message_with_args(200,context,"User ip added");
  return 0;
}

void do_site_help_delip(wzd_context_t * context)
{
  send_message_raw("501-Usage: site delip <user> <ip>\r\n",context);
  send_message_raw("501  or: site delip <user> <slot_number> (get it with site user <user>)\r\n",context);
}

/* site delip: removes ip from user
 * delip <user> <ip>
 * delip <user> <slot_number>
 */
int do_site_delip(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username, *ip;
  int ret;
  wzd_user_t user;
  int uid;
  int i;
  unsigned long ul;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_delip(context);
    return 0;
  }
  ip = strtok_r(NULL," \t\r\n",&ptr);
  if (!ip) {
    do_site_help_delip(context);
    return 0;
  }

  /* check if user  exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* try to take argument as a slot number */
  ul = strtoul(ip,&ptr,0);
  if (*ptr=='\0') {
    if (ul < 0 || ul >= HARD_IP_PER_USER) {
      ret = send_message_with_args(501,context,"Invalid ip slot number");
      return 0;
    }
    if (user.ip_allowed[ul][0] == '\0') {
      ret = send_message_with_args(501,context,"Slot is already empty");
      return 0;
    }
    user.ip_allowed[ul][0] = '\0';
    backend_mod_user("plaintext",username,&user,_USER_IP);
    ret = send_message_with_args(200,context,"User ip removed");
    return 0;
  } /* if (*ptr=='\0') */

  /* try to find ip in list */
  for (i=0; i<HARD_IP_PER_USER; i++)
  {
    if (user.ip_allowed[i][0]=='\0') continue;
    if (strcmp(ip,user.ip_allowed[i])==0) {
      user.ip_allowed[i][0] = '\0';
      /* commit to backend */
      /* FIXME backend name hardcoded */
      backend_mod_user("plaintext",username,&user,_USER_IP);
      ret = send_message_with_args(200,context,"User ip removed");
      return 0;
    }
  }

  ret = send_message_with_args(501,context,"IP not found");
  return 0;
}

void do_site_help_change(wzd_context_t * context)
{
  send_message_raw("501-site change <user> <field> <value>\r\n",context);
  send_message_raw("field can be one of:\r\n",context);
  send_message_raw(" name       changes the user login name\r\n",context);
  send_message_raw(" pass       changes user password\r\n",context);
  send_message_raw(" homedir    changes user chroot's dir\r\n",context);
  send_message_raw(" tagline    changes user tagline\r\n",context);
  send_message_raw(" group      add/remove user from group\r\n",context);
  send_message_raw(" max_idle   changes idle time\r\n",context);
  send_message_raw(" perms      changes default user permissions\r\n",context);
  send_message_raw(" flags      changes user flags\r\n",context);
  send_message_raw(" max_ul     changes maximum upload speed\r\n",context);
  send_message_raw(" max_dl     changes maximum download speed\r\n",context);
  send_message_raw(" num_logins changes maximum simultaneous logins allowed\r\n",context);

  send_message_raw("501 site change aborted\r\n",context);
}

/* site change: change a field for a user
 * change <user> <field> <value>
 */
int do_site_change(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username, * field, * value;
  unsigned long mod_type;
  unsigned long ul;
  int ret;
  wzd_user_t user;
  int uid;
  int i;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_change(context);
    return 0;
  }
  field = strtok_r(NULL," \t\r\n",&ptr);
  if (!field) {
    do_site_help_change(context);
    return 0;
  }
  value = strtok_r(NULL,"\r\n",&ptr);
  if (!value) {
    do_site_help_change(context);
    return 0;
  }

  /* check if user  exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* find modification type */
  mod_type = _USER_NOTHING;

  /** username (?) **/
  if (strcmp(field,"name")==0) {
    mod_type = _USER_USERNAME;
    strncpy(user.username,value,255);
  }
  /** pass **/
  else if (strcmp(field,"pass")==0) {
    mod_type = _USER_USERPASS;
    strncpy(user.userpass,value,255);
  }
  /** homedir **/
  else if (strcmp(field,"homedir")==0) {
    /* check if homedir exist */
    {
      struct stat s;
      if (stat(value,&s) || !S_ISDIR(s.st_mode)) {
	ret = send_message_with_args(501,context,"Homedir does not exist");
	return 0;
      }
    }
    mod_type = _USER_ROOTPATH;
    strncpy(user.rootpath,value,1023);
  }
  /** tagline **/
  else if (strcmp(field,"tagline")==0) {
    mod_type = _USER_TAGLINE;
    strncpy(user.tagline,value,255);
  }
  /** uid **/ /* FIXME useless ? */
  /** group **/ /* add or remove group */
  else if (strcmp(field,"group")==0) {
    wzd_group_t group;
    int groupid;
    int newgroupid=-1;
    /* find corresponding id */
    for (i=0; i<HARD_DEF_GROUP_MAX; i++) {
      if (backend_find_group(i,&group,&groupid)!=-1) {
	if (strcmp(group.groupname,value)==0) { newgroupid = groupid; break; } 
      }
    }
    if (newgroupid != -1) {
      ret=0;
      for (i=0; i<user.group_num; i++)
	if (newgroupid == user.groups[i]) { ret=1; break; } 
      if (ret) { /* remove from group, shift them */
	user.groups[i] = 0;
	for (;i<user.group_num-1; i++)
	  user.groups[i] = user.groups[i+1];
	user.group_num -= 1;
      } else { /* add user to group */
	user.groups[user.group_num] = newgroupid;
	user.group_num++;
      }
    } /* if (newgroupid != -1) */
    mod_type = _USER_GROUP | _USER_GROUPNUM;
  }
  /** max_idle **/
  else if (strcmp(field,"max_idle")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _USER_IDLE; user.max_idle_time = ul; }
  }
  /** perms **/
  else if (strcmp(field,"perms")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _USER_IDLE; user.userperms = ul;} 
  }
  /** flags **/ /* TODO accept modifications style +f or -f */
  else if (strcmp(field,"flags")==0) {
    mod_type = _USER_FLAGS;
    strncpy(user.flags,value,MAX_FLAGS_NUM-1);
  }
  /** max_ul **/
  else if (strcmp(field,"max_ul")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _USER_MAX_ULS; user.max_ul_speed = ul; }
  }
  /** max_dl **/
  else if (strcmp(field,"max_dl")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _USER_MAX_DLS; user.max_dl_speed = ul; }
  }
  /** num_logins **/
  else if (strcmp(field,"num_logins")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _USER_NUMLOGINS; user.num_logins = ul; }
  }
  /** bytes_ul and bytes_dl should never be changed ... */

  /* commit to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user,mod_type);

  ret = send_message_with_args(200,context,"User field change successfull");
  return 0;
}

void do_site_help_chgrp(wzd_context_t * context)
{
  send_message_raw("501-site chgrp <user> <group1> [<group2> ...]\r\n",context);
  send_message_raw(" Add user to group, or remove it if already in group\r\n",context);

  send_message_raw("501 site chgrp aborted\r\n",context);
}

/* site chgrp: add/remove user from group
 * chgrp <user> <group1> [<group2> ...]
 */
int do_site_chgrp(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * username, * group_name;
  unsigned long mod_type;
  int ret;
  wzd_user_t user;
  int uid;
  int i;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help_chgrp(context);
    return 0;
  }
  group_name = strtok_r(NULL," \t\r\n",&ptr);
  if (!group_name) {
    do_site_help_chgrp(context);
    return 0;
  }

  /* check if user  exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* find modification type */
  mod_type = _USER_NOTHING;

  /** group **/ /* add or remove group */
  while (group_name) {
    wzd_group_t group;
    int groupid;
    int newgroupid=-1;
    /* find corresponding id */
    for (i=0; i<HARD_DEF_GROUP_MAX; i++) {
      if (backend_find_group(i,&group,&groupid)!=-1) {
	if (strcmp(group.groupname,group_name)==0) { newgroupid = groupid; break; } 
      }
    }
    if (newgroupid != -1) {
      ret=0;
      for (i=0; i<user.group_num; i++)
	if (newgroupid == user.groups[i]) { ret=1; break; } 
      if (ret) { /* remove from group, shift them */
	user.groups[i] = 0;
	for (;i<user.group_num-1; i++)
	  user.groups[i] = user.groups[i+1];
	user.group_num -= 1;
      } else { /* add user to group */
	user.groups[user.group_num] = newgroupid;
	user.group_num++;
      }
    } else { /* if (newgroupid != -1) */
      char buffer[1024];
      snprintf(buffer,1023,"Group %s is invalid",group_name);
      ret = send_message_with_args(501,context,buffer);
      return 0;
    }
    mod_type = _USER_GROUP | _USER_GROUPNUM;

    group_name = strtok_r(NULL," \t\r\n",&ptr);
  } /* while (group_name) */

  /* commit to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user,mod_type);

  ret = send_message_with_args(200,context,"User field change successfull");
  return 0;
}

/* site flags: display a user's flags
 * flags <user>
 */
int do_site_flags(char *command_line, wzd_context_t * context)
{
  char buffer[1024];
  char *ptr;
  char * username;
  int ret;
  wzd_user_t user;
  int uid;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    username = context->userinfo.username;
  } else 
#endif
    username = mainConfig->user_list[context->userid].username;
  }

  /* check if user exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  snprintf(buffer,1023,"Flags for %s:  %s",username,user.flags);

  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/* site idle: display/set your idle time (per-session only, unless commited)
 * idle [<idletime>]
 * NOTE: you need to be siteop to change your idletime
 */
int do_site_idle(char *command_line, wzd_context_t * context)
{
  char buffer[1024];
  char *ptr;
  char * username;
  int ret;
  wzd_user_t user;
  int uid;
  unsigned long idletime;

  /* get our info */
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    username = context->userinfo.username;
  } else 
#endif
    username = mainConfig->user_list[context->userid].username;
  /* check if user exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"Mama says I don't exist ?!");
    return 0;
  }

  if (*command_line != '\0') {
    if (!user.flags || !strchr(user.flags,FLAG_SITEOP)) {
      ret = send_message_with_args(501,context,"You do not have the rights to do that !");
      return 0;
    }
    idletime = strtoul(command_line,&ptr,0);
    if (*ptr!='\0' || idletime > 7200) { /* XXX hard max idle value of 7200s */
      ret = send_message_with_args(501,context,"Invalid value - Usage: site idle [<idletime>]");
      return 0;
    }
    user.max_idle_time = idletime;
    /* commit to backend */
    /* FIXME backend name hardcoded */
    backend_mod_user("plaintext",username,&user,_USER_IDLE);
    snprintf(buffer,1023,"%s","Command ok");
  } else { /* if (*command_line != '\0') */

    snprintf(buffer,1023,"Your idle time is %ld",user.max_idle_time);
  } /* if (*command_line != '\0') */

  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/* site tagline: display/set your tagline (per-session only, unless commited)
 * tagline [<tagline>]
 */
int do_site_tagline(char *command_line, wzd_context_t * context)
{
  char buffer[1024];
  char *ptr;
  char * username;
  char * tagline;
  int ret;
  wzd_user_t user;
  int uid;

  /* get our info */
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    username = context->userinfo.username;
  } else 
#endif
    username = mainConfig->user_list[context->userid].username;
  /* check if user exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"Mama says I don't exist ?!");
    return 0;
  }

  if (*command_line != '\0') {
    ptr = command_line;
    tagline = strtok_r(command_line,"\r\n",&ptr);
    if (!tagline) {
      ret = send_message_with_args(501,context,"Usage: site tagline [<tagline>]");
      return 0;
    }
    strncpy(user.tagline,tagline,255);
    /* commit to backend */
    /* FIXME backend name hardcoded */
    backend_mod_user("plaintext",username,&user,_USER_TAGLINE);
    snprintf(buffer,1023,"%s","Command ok");
  } else { /* if (*command_line != '\0') */

    snprintf(buffer,1023,"Your tagline is %s",user.tagline);
  } /* if (*command_line != '\0') */

  ret = send_message_with_args(200,context,buffer);
  return 0;
}


/* site kill: kill a PID
 * kill <pid>
 */
#ifdef WZD_MULTIPROCESS
int do_site_kill(char *command_line, wzd_context_t * context)
{
  char *ptr;
  int ret;
  unsigned long pid;
  int found = 0;

  pid = strtoul(command_line,&ptr,0);
  if (*ptr!='\0') {
    ret = send_message_with_args(501,context,"Usage: site kill <pid>");
    return 0;
  }

  /* preliminary check: i can't kill myself */
  if (pid==getpid()) { ret = send_message_with_args(501,context,"My religion forbids me suicide !"); return 0; }

  /* checks that pid is really one of the users */
  {
    int i=0;
    while (i<HARD_USERLIMIT) {
      if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) { found = 1; break; }
      i++;
    }
  }
  if (!found) { ret = send_message_with_args(501,context,"Invalid PID"); return 0; }

  /* send TERM message to child, it will trap signal and exit */
  kill (pid,SIGTERM);

  ret = send_message_with_args(200,context,"TERM signal sent");
  return 0;
}

/* site kick: kick off a user from the site (killing all its connections)
 * kick <user>
 */
int do_site_kick(char *command_line, wzd_context_t * context)
{
  char *username, *test_username;
  char *ptr;
  int ret;
  int found = 0;
  wzd_user_t user;
  int uid;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    ret = send_message_with_args(501,context,"Usage: site kick <user>");
    return 0;
  }
  /* check if user  exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* preliminary check: i can't kill myself */
#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    test_username = context->userinfo.username;
  } else 
#endif
    test_username = mainConfig->user_list[context->userid].username;
  if (strcmp(username,test_username)==0) { ret = send_message_with_args(501,context,"My religion forbids me suicide !"); return 0; }

  /* kill'em all ! */
  {
    int i=0;
    while (i<HARD_USERLIMIT) {
      if (context_list[i].magic == CONTEXT_MAGIC) {
#if BACKEND_STORAGE
	if (mainConfig->backend.backend_storage==0) {
	  test_username = context_list[i].userinfo.username;
	} else 
#endif
	  test_username = mainConfig->user_list[context_list[i].userid].username;
	if (strcmp(username,test_username)==0) {
	  found = 1;
	  kill (context_list[i].pid_child,SIGTERM);
	}
      }
      i++;
    }
  }
  if (!found) { ret = send_message_with_args(501,context,"User is not logged !"); }
  else { ret = send_message_with_args(200,context,"TERM signal sent"); }

  return 0;
}
#endif /* WZD_MULTIPROCESS */
