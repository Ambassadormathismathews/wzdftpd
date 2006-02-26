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
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h> /* gethostbyaddr */

#include <pthread.h>
#endif

#include <errno.h>
#include <signal.h>

#include "wzd_structs.h"

#include "wzd_fs.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_site_user.h"
#include "wzd_vfs.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */



static int _user_changeflags(wzd_user_t * user, const char *newflags);
static void _flags_simplify(char *flags, size_t length);



void do_site_help_adduser(wzd_context_t * context)
{
  send_message_with_args(501,context,"site adduser <user> <password> [<group>] [<ip1> <ip2> <...>]");
}

/** site adduser: adds a new user
 *
 * adduser &lt;user&gt; &lt;password&gt; [&lt;group&gt;] [&lt;ip1&gt; &lt;ip2&gt; &lt;...&gt;]
 */
int do_site_adduser(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * username, *password, *groupname, *ip=NULL;
  const char * homedir;
  int ret;
  wzd_user_t user, *me;
  wzd_group_t * group=NULL;
  int uid;
  int i;
  unsigned int ratio = 3; /* TODO XXX FIXME default ratio value hardcoded */
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_adduser(context);
    return 0;
  }
  password = str_tok(command_line," \t\r\n");
  if (!password) {
    do_site_help_adduser(context);
    str_deallocate(username);
    return 0;
  }

  /* check users limit -> backend will do that !! */

  groupname = str_tok(command_line," \t\r\n");
  group = GetGroupByName(str_tochar(groupname));

  if (!group) ip = groupname; /* it is not a valid group, assume it is an ip */
  else str_deallocate(groupname);

  groupname = NULL;

  /* check if user already exists */
  if ( !backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User already exists");
    str_deallocate(username); str_deallocate(password); str_deallocate(ip);
    return 0;
  }
  /* find user group or take current user */
  if (!group) {
    if (me && me->group_num>0) {
      group = GetGroupByID(me->groups[0]);
    } else {
      ret = send_message_with_args(501,context,"You cannot add users due to your own groups");
      str_deallocate(username); str_deallocate(password); str_deallocate(ip);
      return 0;
    }
  } else {
    if (is_gadmin)
    {
      /* GAdmins cannot add user to different group */
      if (me->group_num==0 || me->groups[0]!=GetGroupIDByName(str_tochar(groupname)))
      {
        ret = send_message_with_args(501,context,"You are not allowed to add users to this group");
        str_deallocate(username); str_deallocate(password); str_deallocate(ip);
        return 0;
      }
    }
  }
  /* Gadmin ? */
  if (is_gadmin)
  {
    if (me->user_slots == 0) {
      ret = send_message_with_args(501,context,"No more slots available");
      str_deallocate(username); str_deallocate(password); str_deallocate(ip);
      return 0;
    }
  }
  if (group) {
    homedir = group->defaultpath;
    groupname = STR(group->groupname);
    ratio = group->ratio;
  } else {
    /* XXX FIXME we should abort here */
    ret = send_message_with_args(501,context,"I can't find a default_home in your groups - contact the sysadmin");
    str_deallocate(username); str_deallocate(password); str_deallocate(ip);
    return 0;
  }
  /* check if homedir exist */
  {
    fs_filestat_t s;
    if (fs_file_stat(homedir,&s) || !S_ISDIR(s.mode)) {
      ret = send_message_with_args(501,context,"Homedir does not exist");
      str_deallocate(username); str_deallocate(password); str_deallocate(ip);
      return 0;
    }
  }

  /* create new user */
  strncpy(user.username,str_tochar(username),HARD_USERNAME_LENGTH);
  strncpy(user.userpass,str_tochar(password),MAX_PASS_LENGTH);
  strncpy(user.rootpath,homedir,WZD_MAX_PATH);
  user.tagline[0]='\0';
  user.uid=-1; /* will be changed by backend */
  user.group_num=0;
  if (groupname) {
    user.groups[0] = GetGroupIDByName(str_tochar(groupname));
    if (user.groups[0]) user.group_num=1;
  }
  user.max_idle_time=0;
  user.userperms=0xffffffff;
  user.flags[0]='\0';
  user.max_ul_speed=0;
  user.max_dl_speed=0;
  user.num_logins=0;
  for (i=0; i<HARD_IP_PER_USER; i++)
    user.ip_allowed[i][0]='\0';
  user.stats.bytes_ul_total=0;
  user.stats.bytes_dl_total=0;
  user.stats.files_ul_total=0;
  user.stats.files_dl_total=0;
  user.credits = 0;
  user.ratio = ratio;
  user.user_slots=0;
  user.leech_slots=0;
  user.last_login = 0;

  i = 0;
  if (ip) {
    wzd_strncpy(user.ip_allowed[i++],str_tochar(ip),MAX_IP_LENGTH);
    str_deallocate(ip);
  };
  while ( (ip = str_tok(command_line," \t")) ) {
    wzd_strncpy(user.ip_allowed[i++],str_tochar(ip),MAX_IP_LENGTH);
    str_deallocate(ip);
  }

  /* add it to backend */
  ret = backend_mod_user(mainConfig->backend.filename,str_tochar(username),&user,_USER_ALL);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem adding user");
  } else {
    if (is_gadmin) me->user_slots--; /* decrement user slots counter */
    ret = send_message_with_args(200,context,"User added");
  }
  str_deallocate(username); str_deallocate(password); str_deallocate(ip);
  return 0;
}

void do_site_help_deluser(wzd_context_t * context)
{
  send_message_with_args(501,context,"site deluser <user> [<backend>]");
}

/** site deluser: delete user
 *
 * deluser &lt;user&gt;
 */
int do_site_deluser(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * username;
  int ret;
  wzd_user_t *user, *me;
  int length;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_deluser(context);
    return 0;
  }
  /* TODO read backend */

  /* check if user already exists */
  user = GetUserByName(str_tochar(username));
  str_deallocate(username);
  if ( !user ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user->group_num==0 || me->groups[0]!=user->groups[0])
    {
      ret = send_message_with_args(501,context,"You can't delete this user");
      return 0;
    }
  }

  /* mark user as deleted */
  if (strchr(user->flags,FLAG_DELETED)) {
    ret = send_message_with_args(501,context,"User already marked as deleted");
    return 0;
  }
  length = strlen(user->flags);
  if (length+1 >= MAX_FLAGS_NUM) {
    ret = send_message_with_args(501,context,"Too many flags for user");
    return 0;
  }
  user->flags[length] = FLAG_DELETED;
  user->flags[length+1] = '\0';

  /* commit changes to backend */
  backend_mod_user(mainConfig->backend.filename,user->username,user,_USER_FLAGS);

  ret = send_message_with_args(200,context,"User deleted");
  return 0;
}

void do_site_help_readduser(wzd_context_t * context)
{
  send_message_with_args(501,context,"site readduser <user> [<backend>]");
}

/** site readduser: undelete user
 *
 * readduser &lt;user&gt;
 */
int do_site_readduser(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * username;
  int ret;
  wzd_user_t user, *me;
  int uid;
  int length;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_readduser(context);
    return 0;
  }

  /* check if user already exists */
  if ( backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    str_deallocate(username);
    return 0;
  }
  str_deallocate(username);

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0]) {
      ret = send_message_with_args(501,context,"You can't change this user");
      return 0;
    }
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
  backend_mod_user(mainConfig->backend.filename,user.username,&user,_USER_FLAGS);

  ret = send_message_with_args(200,context,"User undeleted");
  return 0;
}

/** site purge: delete user permanently
 *
 * purge [&lt;user&gt;] [&lt;backend&gt;]
 */
int do_site_purgeuser(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context)
{
  wzd_string_t * username;
  int ret;
  wzd_user_t user, * me;
  int uid;
  short is_gadmin;
  const char *ptr;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(param," \t\r\n");

  /* TODO read backend */

  if (username) { /* case 1: name was given */
    /* check if user already exists */
    if ( backend_find_user(str_tochar(username),&user,&uid) ) {
      ret = send_message_with_args(501,context,"User does not exist");
      str_deallocate(username);
      return 0;
    }

    /* unmark user as deleted */
    if ( (ptr = strchr(user.flags,FLAG_DELETED)) == NULL ) {
      ret = send_message_with_args(501,context,"User is not marked as deleted");
      str_deallocate(username);
      return 0;
    }

    /* gadmin ? */
    if (is_gadmin)
    {
      if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0]) {
        ret = send_message_with_args(501,context,"You can't purge this user (GAdmin limits)");
        str_deallocate(username);
        return 0;
      }
    }

    /* commit changes to backend */
    backend_mod_user(mainConfig->backend.filename,str_tochar(username),NULL,_USER_ALL);
    str_deallocate(username);
  } else { /* if (username) */
    /* TODO iterate users and purge those marked as deleted */
    unsigned int i;
    wzd_user_t * user;
    int * uid_list;
    uid_list = (int*)backend_get_user(-2);

    if (uid_list)
    {
      for (i=0; uid_list[i] >= 0; i++)
      {
        user = GetUserByID(uid_list[i]);
        if (user && user->flags && strchr(user->flags,FLAG_DELETED))
        {
          /* gadmin ? */
          if (is_gadmin)
          {
            if (me->group_num==0 || user->group_num==0 || me->groups[0]!=user->groups[0]) {
              continue;
            }
          }
          /* commit changes to backend */
          backend_mod_user(mainConfig->backend.filename,user->username,NULL,_USER_ALL);
        }
      }
      wzd_free (uid_list);
    } /* if (uid_list) */
    ret = send_message_with_args(200,context,"All deleted users have been purged");
    return 0;
  } /* if (username) */

  ret = send_message_with_args(200,context,"User purged");
  return 0;
}

void do_site_help_addip(wzd_context_t * context)
{
  send_message_with_args(501,context,"site addip <user> <ip1> [<ip2> ...]");
}

/** site addip: adds an ip to a user
 *
 * addip &lt;user&gt; &lt;ip1&gt; [&lt;ip2&gt; ...]
 */
int do_site_addip(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * username, *ip;
  int ret;
  wzd_user_t *user, *me;
  int i;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_addip(context);
    return 0;
  }

  /* check if user  exists */
  user = GetUserByName( str_tochar(username) );
  str_deallocate(username);
  if ( !user ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  ip = str_tok(command_line," \t\r\n");
  if (!ip) {
    do_site_help_addip(context);
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user->group_num==0 || me->groups[0]!=user->groups[0]) {
      ret = send_message_with_args(501,context,"You can't change this user");
      str_deallocate(ip);
      return 0;
    }
  }

  do {

    /* check if ip is already present or included in list, or if it shadows one present */
    for (i=0; i<HARD_IP_PER_USER; i++)
    {
      if (user->ip_allowed[i][0]=='\0') continue;
      if (my_str_compare(str_tochar(ip),user->ip_allowed[i])==1) { /* ip is already included in list */
        ret = send_message_with_args(501,context,"ip is already included in list");
        str_deallocate(ip);
        return 0;
      }
      if (my_str_compare(user->ip_allowed[i],str_tochar(ip))==1) { /* ip will shadow one ore more ip in list */
        ret = send_message_with_args(501,context,"ip will shadow some ip in list, remove them before");
        str_deallocate(ip);
        return 0;
      }
    }

    /* update user */
    for (i=0; i<HARD_IP_PER_USER; i++)
      if (user->ip_allowed[i][0]=='\0') break;

    /* no more slots ? */
    if (i==HARD_IP_PER_USER) {
      ret = send_message_with_args(501,context,"No more slots available - either recompile with more slots, or use them more cleverly !");
      str_deallocate(ip);
      return 0;
    }
    /* TODO check ip validity */
    strncpy(user->ip_allowed[i],str_tochar(ip),MAX_IP_LENGTH-1);

    str_deallocate(ip);

    ip = str_tok(command_line," \t\r\n");
  } while (ip);

  /* commit to backend */
  backend_mod_user(mainConfig->backend.filename,user->username,user,_USER_IP);

  ret = send_message_with_args(200,context,"User ip(s) added");
  return 0;
}

void do_site_help_delip(wzd_context_t * context)
{
  send_message_raw("501-Usage: site delip <user> <ip1> [<ip2> ...]\r\n",context);
  send_message_raw("501  ip can be replaced by the slot_number (get it with site user <user>)\r\n",context);
}

/** site delip: removes ip from user
 *
 * delip &lt;user&gt; &lt;ip1&gt; [&lt;ip2&gt; ...]
 *
 * ip can be replaced by the slot_number
 */
int do_site_delip(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr_ul;
  wzd_string_t * username, *ip;
  int ret;
  wzd_user_t *user, *me;
  int i;
  unsigned long ul;
  short is_gadmin;
  int found;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_delip(context);
    return 0;
  }
  /* check if user  exists */
  user = GetUserByName(str_tochar(username));
  str_deallocate(username);
  if ( !user ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user->group_num==0 || me->groups[0]!=user->groups[0]) {
      ret = send_message_with_args(501,context,"You can't change this user");
      return 0;
    }
  }

  ip = str_tok(command_line," \t\r\n");
  if (!ip) {
    do_site_help_delip(context);
    return 0;
  }

  do {

    /* try to take argument as a slot number */
    ul = strtoul(str_tochar(ip),&ptr_ul,0);
    if (*ptr_ul=='\0') {
      if (ul <= 0 || ul > HARD_IP_PER_USER) {
        ret = send_message_with_args(501,context,"Invalid ip slot number");
        str_deallocate(ip);
        return 0;
      }
      str_deallocate(ip);
      ul--; /* to index slot number from 1 */
      if (user->ip_allowed[ul][0] == '\0') {
        ret = send_message_with_args(501,context,"Slot is already empty");
        return 0;
      }
      user->ip_allowed[ul][0] = '\0';
    } else { /* if (*ptr=='\0') */

      /* try to find ip in list */
      found = 0;
      for (i=0; i<HARD_IP_PER_USER; i++)
      {
        if (user->ip_allowed[i][0]=='\0') continue;
        if (strcmp(str_tochar(ip),user->ip_allowed[i])==0) {
          user->ip_allowed[i][0] = '\0';
          found = 1;
        }
      }

      if (!found) {
        char buffer[256];
        snprintf(buffer,256,"IP %s not found",str_tochar(ip));
        ret = send_message_with_args(501,context,buffer);
        str_deallocate(ip);
        return 0;
      }
      str_deallocate(ip);
    } /* if (*ptr=='\0') */

    ip = str_tok(command_line," \t\r\n");
  } while (ip);

  /* commit to backend */
  backend_mod_user(mainConfig->backend.filename,user->username,user,_USER_IP);
  ret = send_message_with_args(200,context,"User ip(s) removed");
  return 0;
}


/** site color: toggle color user (for self only)
 *
 * change color
 */
int do_site_color(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context)
{
  wzd_user_t * me;
  char * src_ptr, *dst_ptr;
  char new_flags[MAX_FLAGS_NUM];
  int i, found, ret;

  me = GetUserByID(context->userid);
  
  found=0;
  src_ptr = me->flags;
  dst_ptr = new_flags;
  for (i=0; *src_ptr && i<MAX_FLAGS_NUM; i++,src_ptr++)
  {
    if ( *src_ptr==FLAG_COLOR) { found=1; continue; }
    *dst_ptr++ = *src_ptr;
  }
  if (!found) {
    *dst_ptr++ = FLAG_COLOR;
    *dst_ptr='\0';
    memcpy(me->flags,new_flags,MAX_FLAGS_NUM);
    ret = backend_mod_user(mainConfig->backend.filename,me->username,me,_USER_FLAGS);
    ret = send_message_with_args(200,context,"color mode ON");
  } else {
    *dst_ptr='\0';
    memcpy(me->flags,new_flags,MAX_FLAGS_NUM);
    ret = backend_mod_user(mainConfig->backend.filename,me->username,me,_USER_FLAGS);
    ret = send_message_with_args(200,context,"color mode OFF");
  }
  return 0;
}


void do_site_help_change(wzd_context_t * context)
{
  send_message_raw("501-site change <user> <field> <value>\r\n",context);
  send_message_raw("field can be one of:\r\n",context);
  send_message_raw(" name        changes the user login name\r\n",context);
  send_message_raw(" pass        changes user password\r\n",context);
  send_message_raw(" homedir     changes user chroot's dir\r\n",context);
  send_message_raw(" tagline     changes user tagline\r\n",context);
  send_message_raw(" group       add/remove user from group\r\n",context);
  send_message_raw(" max_idle    changes idle time\r\n",context);
  send_message_raw(" perms       changes default user permissions\r\n",context);
  send_message_raw(" flags       changes user flags\r\n",context);
  send_message_raw(" max_ul      changes maximum upload speed\r\n",context);
  send_message_raw(" max_dl      changes maximum download speed\r\n",context);
  send_message_raw(" credits     changes user credits\r\n",context);
  send_message_raw(" ratio       changes user ratio\r\n",context);
  send_message_raw(" num_logins  changes maximum simultaneous logins allowed\r\n",context);
  send_message_raw(" user_slots  changes allowed user slots (for GAdmins)\r\n",context);
  send_message_raw(" leech_slots changes allowed leech slots (for GAdmins)\r\n",context);

  send_message_raw("501 site change aborted\r\n",context);
}

/** site change: change a field for a user
 *
 * change &lt;user&gt; &lt;field&gt; &lt;value&gt;
 */
int do_site_change(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * username, * field, * value;
  unsigned long mod_type;
  unsigned long ul;
  unsigned int oldratio=0;
  int ret;
  wzd_user_t * user, *me;
  unsigned int i;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_change(context);
    return 0;
  }
  /* check if user  exists */
  user = GetUserByName( str_tochar(username) );
  str_deallocate(username);
  if ( !user) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }
  field = str_tok(command_line," \t\r\n");
  if (!field) {
    do_site_help_change(context);
    return 0;
  }
  value = str_tok(command_line,"\r\n");
  if (!value) {
    do_site_help_change(context);
    str_deallocate(field);
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    if (me->group_num==0 || user->group_num==0 || me->groups[0]!=user->groups[0]) {
      ret = send_message_with_args(501,context,"You can't change this user");
      str_deallocate(field); str_deallocate(value);
      return 0;
    }
  }

  /* find modification type */
  mod_type = _USER_NOTHING;

  /* username (?) */
  if (strcmp(str_tochar(field),"name")==0) {
    mod_type = _USER_USERNAME;
    strncpy(user->username,str_tochar(value),HARD_USERNAME_LENGTH);
  }
  /* pass */
  else if (strcmp(str_tochar(field),"pass")==0) {
    mod_type = _USER_USERPASS;
    strncpy(user->userpass,str_tochar(value),MAX_PASS_LENGTH);
  }
  /* homedir */
  else if (strcmp(str_tochar(field),"homedir")==0) {
    /* check if homedir exist */
    {
      fs_filestat_t s;
      if (fs_file_stat(str_tochar(value),&s) || !S_ISDIR(s.mode)) {
        ret = send_message_with_args(501,context,"Homedir does not exist");
        str_deallocate(field); str_deallocate(value);
        return 0;
      }
    }
    mod_type = _USER_ROOTPATH;
    strncpy(user->rootpath,str_tochar(value),WZD_MAX_PATH);
  }
  /* tagline */
  else if (strcmp(str_tochar(field),"tagline")==0) {
    mod_type = _USER_TAGLINE;
    strncpy(user->tagline,str_tochar(value),MAX_TAGLINE_LENGTH-1);
  }
  /* uid */ /* FIXME useless ? */
  /* group */ /* add or remove group */
  else if (strcmp(str_tochar(field),"group")==0) {
    unsigned int newgroupid=(unsigned int)-1;

    /* GAdmin ? */
    if (is_gadmin) {
       ret = send_message_with_args(501,context,"You can't change that field");
       str_deallocate(field); str_deallocate(value);
       return 0;
    }

    /* find corresponding id */
    newgroupid = GetGroupIDByName(str_tochar(value));

    if (newgroupid != (unsigned int)-1) {
      ret=0;
      for (i=0; i<user->group_num; i++)
        if (newgroupid == user->groups[i]) { ret=1; break; } 
      if (ret) { /* remove from group, shift them */
        user->groups[i] = 0;
        for (;i<user->group_num-1; i++)
          user->groups[i] = user->groups[i+1];
        user->group_num -= 1;
      } else { /* add user to group */
        user->groups[user->group_num] = newgroupid;
        user->group_num++;
      }
    } /* if (newgroupid != -1) */
    mod_type = _USER_GROUP | _USER_GROUPNUM;
  }
  /* max_idle */
  else if (strcmp(str_tochar(field),"max_idle")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _USER_IDLE; user->max_idle_time = ul; }
  }
  /* perms */
  else if (strcmp(str_tochar(field),"perms")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _USER_PERMS; user->userperms = ul;} 
  }
  /* flags */ /* TODO accept modifications style +f or -f */
  else if (strcmp(str_tochar(field),"flags")==0) {
    /* GAdmin ? */
    if (is_gadmin) {
       ret = send_message_with_args(501,context,"You can't change that field");
       str_deallocate(field); str_deallocate(value);
       return 0;
    }

    if (_user_changeflags(user,str_tochar(value))) {
       ret = send_message_with_args(501,context,"Error occurred when changing flags");
       str_deallocate(field); str_deallocate(value);
      return 0;
    }
    mod_type = _USER_FLAGS;
  }
  /* max_ul */
  else if (strcmp(str_tochar(field),"max_ul")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _USER_MAX_ULS; user->max_ul_speed = ul; }
  }
  /* max_dl */
  else if (strcmp(str_tochar(field),"max_dl")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _USER_MAX_DLS; user->max_dl_speed = ul; }
  }
  /* credits */
  else if (strcmp(str_tochar(field),"credits")==0) {
    u64_t ull;

    ull=strtoull(str_tochar(value),&ptr,0);

    if (!*ptr) { mod_type = _USER_CREDITS; user->credits = ull; }
  }
  /* num_logins */
  else if (strcmp(str_tochar(field),"num_logins")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _USER_NUMLOGINS; user->num_logins = (unsigned short)ul; }
  }
  /* ratio */
  else if (strcmp(str_tochar(field),"ratio")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) {
      if (is_gadmin && ul==0) { /* GAdmin wants to add a leech access */
        if (me->leech_slots == 0) {
          ret = send_message_with_args(501,context,"No more leech slots available");
          str_deallocate(field); str_deallocate(value);
          return 0;
        }
      }
      oldratio = user->ratio;
      mod_type = _USER_RATIO; user->ratio = ul;
    }
  }
  /* user_slots */
  else if (strcmp(str_tochar(field),"user_slots")==0) {
    /* GAdmin ? */
    if (is_gadmin) {
       ret = send_message_with_args(501,context,"You can't change that field");
       str_deallocate(field); str_deallocate(value);
       return 0;
    }
    if ( ! strchr(user->flags,FLAG_GADMIN) ) {
       ret = send_message_with_args(501,context,"User is not a gadmin");
       str_deallocate(field); str_deallocate(value);
       return 0;
    }
    ul=strtoul(str_tochar(value),&ptr,0);
    /* TODO compare with USHORT_MAX */
    if (!*ptr) { mod_type = _USER_USERSLOTS; user->user_slots = (unsigned short)ul; }
  }
  /* leech_slots */
  else if (strcmp(str_tochar(field),"leech_slots")==0) {
    /* GAdmin ? */
    if (is_gadmin) {
       ret = send_message_with_args(501,context,"You can't change that field");
       str_deallocate(field); str_deallocate(value);
       return 0;
    }
    if ( ! strchr(user->flags,FLAG_GADMIN) ) {
       ret = send_message_with_args(501,context,"User is not a gadmin");
       str_deallocate(field); str_deallocate(value);
       return 0;
    }
    ul=strtoul(str_tochar(value),&ptr,0);
    /* TODO compare with USHORT_MAX */
    if (!*ptr) { mod_type = _USER_LEECHSLOTS; user->leech_slots = (unsigned short)ul; }
  }
  /* bytes_ul and bytes_dl should never be changed ... */
  else {
    ret = send_message_with_args(501,context,"field does not exist");
    str_deallocate(field); str_deallocate(value);
    return 0;
  }

  /* save uid */
  i = user->uid;

  /* commit to backend */
  ret = backend_mod_user(mainConfig->backend.filename,user->username,user,mod_type);

  /* user has been modified, we have to refresh cache entry */
  user = GetUserByID(i);

  if (!ret && is_gadmin) {
    if ( mod_type & _USER_RATIO ) {
      if (user->ratio==0) {
        /* gadmin added a leech access */
        me->leech_slots--;
      }
      if (oldratio==0 && user->ratio) {
        /* gadmin removed a leech access */
        me->leech_slots++;
      }
    }
  }

  if ( (user->flags && strchr(user->flags,FLAG_GADMIN)) &&
      (user->flags && strchr(user->flags,FLAG_SITEOP)))
  {
    ret = send_message_with_args(200,context,"Change ok - You have set flags G and O, THIS IS NOT WHAT YOU WANT - repeat: THIS IS STUPID !!");
  }
  else
    ret = send_message_with_args(200,context,"User field change successfull");

  str_deallocate(field); str_deallocate(value);

  return 0;
}

void do_site_help_changegrp(wzd_context_t * context)
{
  send_message_raw("501-site changegrp <user> <group1> [<group2> ...]\r\n",context);
  send_message_raw(" Add user to group, or remove it if already in group\r\n",context);

  send_message_raw("501 site changegrp aborted\r\n",context);
}

/** site changegrp: add/remove user from group
 *
 * changegrp &lt;user&gt; &lt;group1&gt; [&lt;group2&gt; ...]
 */
int do_site_changegrp(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * username, * group_name;
  unsigned long mod_type;
  int ret;
  wzd_user_t * user;
  unsigned int i;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_changegrp(context);
    return 0;
  }

  /* check if user  exists */
  user=GetUserByName(str_tochar(username));
  str_deallocate(username);
  if ( !user ) {
    ret = send_message_with_args(501,context,"User does not exist");
    return 0;
  }

  group_name = str_tok(command_line," \t\r\n");
  if (!group_name) {
    do_site_help_changegrp(context);
    return 0;
  }

  /* find modification type */
  mod_type = _USER_NOTHING;

  /** group **/ /* add or remove group */
  while (group_name) {
    unsigned int newgroupid=(unsigned int)-1;

    newgroupid = GetGroupIDByName(str_tochar(group_name));

    if (newgroupid != (unsigned int)-1) {
      ret=0;
      for (i=0; i<user->group_num; i++)
        if (newgroupid == user->groups[i]) { ret=1; break; } 
      if (ret) { /* remove from group, shift them */
        user->groups[i] = 0;
        for (;i<user->group_num-1; i++)
          user->groups[i] = user->groups[i+1];
        user->group_num -= 1;
      } else { /* add user to group */
        user->groups[user->group_num] = newgroupid;
        user->group_num++;
      }
    } else { /* if (newgroupid != -1) */
      char buffer[1024];
      snprintf(buffer,1023,"Group %s is invalid",str_tochar(group_name));
      ret = send_message_with_args(501,context,buffer);
      str_deallocate(group_name);
      return 0;
    }
    mod_type = _USER_GROUP | _USER_GROUPNUM;

    str_deallocate(group_name);
    group_name = str_tok(command_line," \t\r\n");
  } /* while (group_name) */

  /* commit to backend */
  backend_mod_user(mainConfig->backend.filename,user->username,user,mod_type);

  ret = send_message_with_args(200,context,"User field change successfull");
  return 0;
}



void do_site_help_chratio(wzd_context_t * context)
{
  send_message_with_args(501,context,"site chratio <user> <ratio>");
}

/** site chratio: change user ratio
 *
 * chratio user ratio
 */
int do_site_chratio(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr=NULL;
  wzd_string_t * str_ratio, *username;
  int ret;
  wzd_user_t user, *me;
  int uid;
  unsigned int ratio, oldratio;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_chratio(context);
    return 0;
  }
  str_ratio = str_tok(command_line," \t\r\n");
  if (!str_ratio) {
    do_site_help_chratio(context);
    str_deallocate(username);
    return 0;
  }

  /* check if user already exists */
  if ( backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    str_deallocate(username); str_deallocate(str_ratio);
    return 0;
  }

  ratio = strtoul(str_tochar(str_ratio),&ptr,0);

  if (*ptr!='\0') {
    do_site_help_chratio(context);
    str_deallocate(username);
    return 0;
  }
  str_deallocate(str_ratio);

  /* TODO find user group or take current user */
  if (is_gadmin)
  {
    /* GAdmins cannot change user from different group */
    if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0])
    {
      ret = send_message_with_args(501,context,"You are not allowed to change users from this group");
      str_deallocate(username);
      return 0;
    }
  }

  /* Gadmin ? */
  if (is_gadmin && ratio==0)
  {
    if (me->leech_slots == 0) {
      ret = send_message_with_args(501,context,"No more slots available");
      str_deallocate(username); str_deallocate(str_ratio);
      return 0;
    }
  }
  oldratio = user.ratio;
  user.ratio = ratio;

  /* add it to backend */
  ret = backend_mod_user(mainConfig->backend.filename,str_tochar(username),&user,_USER_RATIO);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem changing value");
  } else {
    /* adjust slot counter for gadmin */
    if (is_gadmin) {
      if (!ratio)
        me->leech_slots--;
      if (!oldratio && ratio)
        me->leech_slots++;
    }
    ret = send_message_with_args(200,context,"User ratio changed");
  }
  str_deallocate(username);
  return 0;
}



/** site flags: display a user's flags
 *
 * flags &lt;user&gt; &lt;newflags&gt;
 */
int do_site_flags(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[1024];
  wzd_string_t *newflags = NULL;
  wzd_string_t * username = NULL;
  int ret;
  wzd_user_t user;
  int uid;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    username = STR(GetUserByID(context->userid)->username);
  }
  if (username) {
    newflags = str_tok(command_line," \t\r\n");
  }

  /* check if user exists */
  if ( backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    str_deallocate(username); str_deallocate(newflags);
    return 0;
  }

  if (!newflags) {
    snprintf(buffer,1023,"Flags for %s: %s",str_tochar(username),user.flags);

    ret = send_message_with_args(200,context,buffer);
  } else {
    unsigned int is_gadmin;
    wzd_user_t * me = GetUserByID(context->userid);

    is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

    /* GAdmin ? */
    if (is_gadmin)
    {
      if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0]) {
        ret = send_message_with_args(501,context,"You can't change this user");
        str_deallocate(username); str_deallocate(newflags);
        return 0;
      }
    }
    /* authorized ? */
    if (!strchr(me->flags,FLAG_SITEOP)) {
      ret = send_message_with_args(501,context,"You can't change flags for other users");
      str_deallocate(username); str_deallocate(newflags);
      return 0;
    }

    if (_user_changeflags(&user,str_tochar(newflags))) {
      ret = send_message_with_args(501,context,"Error occurred changing flags");
      str_deallocate(username); str_deallocate(newflags);
      return 0;
    }
    /* commit to backend */
    ret = backend_mod_user(mainConfig->backend.filename,str_tochar(username),&user,_USER_FLAGS);
    if (!ret)
      ret = send_message_with_args(200,context,"Flags changed");
    else
      ret = send_message_with_args(501,context,"Flags changed, but error committing changes to backend");
  }

  str_deallocate(username); str_deallocate(newflags);
  return 0;
}

/** site idle: display/set your idle time (per-session only, unless commited)
 *
 * idle [&lt;idletime&gt;]
 *
 * NOTE: you need to be siteop to change your idletime
 */
int do_site_idle(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[1024];
  char *ptr;
  int ret;
  wzd_user_t * user;
  unsigned long idletime;

  /* get our info */
  user = GetUserByID(context->userid);
  /* check if user exists */
  if ( !user ) {
    ret = send_message_with_args(501,context,"Mama says I don't exist ?!");
    return 0;
  }

  if (command_line && strlen(str_tochar(command_line))>0) {
    if (!user->flags || !strchr(user->flags,FLAG_SITEOP)) {
      ret = send_message_with_args(501,context,"You do not have the rights to do that !");
      return 0;
    }
    idletime = strtoul(str_tochar(command_line),&ptr,0);
    if (*ptr!='\0' || idletime > 7200) { /* XXX hard max idle value of 7200s */
      ret = send_message_with_args(501,context,"Invalid value - Usage: site idle [<idletime>]");
      return 0;
    }
    user->max_idle_time = idletime;
    /* commit to backend */
    backend_mod_user(mainConfig->backend.filename,user->username,user,_USER_IDLE);
    snprintf(buffer,1023,"%s","Command ok");
  } else { /* if (*command_line != '\0') */

    snprintf(buffer,1023,"Your idle time is %u",user->max_idle_time);
  } /* if (*command_line != '\0') */

  ret = send_message_with_args(200,context,buffer);
  return 0;
}

/** site tagline: display/set your tagline (per-session only, unless commited)
 *
 * tagline [&lt;tagline&gt;]
 */
int do_site_tagline(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char buffer[1024];
  int ret;
  wzd_user_t * user;

  /* get our info */
  user = GetUserByID(context->userid);
  /* check if user exists */
  if ( !user ) {
    ret = send_message_with_args(501,context,"Mama says I don't exist ?!");
    return 0;
  }

  if (command_line && strlen(str_tochar(command_line))>0) {
    strncpy(user->tagline,str_tochar(command_line),255);
    /* commit to backend */
    backend_mod_user(mainConfig->backend.filename,user->username,user,_USER_TAGLINE);
    snprintf(buffer,1023,"%s","Command ok");
  } else { /* if (*command_line != '\0') */

    snprintf(buffer,1023,"Your tagline is %s",user->tagline);
  } /* if (*command_line != '\0') */

  ret = send_message_with_args(200,context,buffer);
  return 0;
}


/** site kill: kill a PID
 *
 * kill &lt;pid&gt;
 */
int do_site_kill(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context)
{
  char *ptr;
  int ret;
  unsigned long pid;

  pid = strtoul(str_tochar(param),&ptr,0);
  if (*ptr!='\0') {
    ret = send_message_with_args(501,context,"Usage: site kill <pid>");
    return 0;
  }

  switch(kill_child(pid,context)) {
  case 0:
    ret = send_message_with_args(200,context,"KILL signal sent");
    break;
  case 1:
    ret = send_message_with_args(501,context,"My religion forbids me suicide !");
    break;
  case -1:
    ret = send_message_with_args(501,context,"Invalid PID");
    break;
  default:
    ret = send_message_with_args(501,context,"We should NOT have passed here - NEVER !");
    break;
  }

  return 0;
}

/** site kick: kick off a user from the site (killing all its connections)
 *
 * kick &lt;user&gt;
 */
int do_site_kick(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context)
{
  wzd_string_t *_username;
  const char *username, *test_username;
  int ret;
  int found = 0;
  wzd_user_t user;
  int uid;

  _username = str_tok(param," \t\r\n");
  if (!_username) {
    ret = send_message_with_args(501,context,"Usage: site kick <user>");
    return 0;
  }
  username = str_tochar(_username);
  /* check if user  exists */
  if ( backend_find_user(username,&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exist");
    str_deallocate(_username);
    return 0;
  }

  /* preliminary check: i can't kill myself */
  test_username = GetUserByID(context->userid)->username;
  if (strcmp(username,test_username)==0) {
    ret = send_message_with_args(501,context,"My religion forbids me suicide !");
    str_deallocate(_username);
    return 0;
  }

  /* kill'em all ! */
  {
    ListElmt * elmnt;
    wzd_context_t * loop_context;
    for (elmnt=list_head(context_list); elmnt; elmnt=list_next(elmnt)) {
      loop_context = list_data(elmnt);
      if (loop_context && loop_context->magic == CONTEXT_MAGIC) {
        test_username = GetUserByID(loop_context->userid)->username;
        if (strcmp(username,test_username)==0) {
          found = 1;
          kill_child_new(loop_context->pid_child,context);
        }
      }
    } /* for all contexts */
  }
  if (!found) { ret = send_message_with_args(501,context,"User is not logged !"); }
  else { ret = send_message_with_args(200,context,"KILL signal sent"); }

  str_deallocate(_username);
  return 0;
}


/** site killpath: kick off all users inside a directory
 *
 * killpath &lt;path&gt;
 */
int do_site_killpath(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *realpath;
  wzd_string_t *path;
  int ret;

  path = str_tok(command_line,"\r\n");
  if (!path) {
    ret = send_message_with_args(501,context,"Usage: site killpath <path>");
    return 0;
  }

  realpath = malloc(WZD_MAX_PATH+1);
  if (checkpath_new(str_tochar(path),realpath,context)) {
    ret = E_FILE_NOEXIST;
  } else {
    ret = killpath(realpath,context);
  }
  free(realpath);
  str_deallocate(path);

  switch (ret) {
    case E_FILE_NOEXIST:
      ret = send_message_with_args(501,context,"path does not exist !");
      break;
    case E_USER_IDONTEXIST:
      ret = send_message_with_args(501,context,"Where am I ? My path does not exist !");
      break;
    case E_USER_ICANTSUICIDE:
      ret = send_message_with_args(501,context,"My religion forbids me suicide !");
      break;
    case E_USER_NOBODY:
      ret = send_message_with_args(200,context,"Nobody in this path");
      break;
    case E_OK:
      ret = send_message_with_args(200,context,"KILL signal sent");
      break;
    default:
      ret = send_message_with_args(501,context,"Unknown error");
      break;
  };
  
  return 0;
}

void do_site_help_give(wzd_context_t * context)
{
  send_message_with_args(501,context,"site give <user> <kbytes>");
}

/** site give: gives credits to user
 *
 * give user kbytes
 */
int do_site_give(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * str_give, *username;
  int ret;
  wzd_user_t user, *me;
  int uid;
  u64_t kbytes;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_give(context);
    return 0;
  }
  str_give = str_tok(command_line," \t\r\n");
  if (!str_give) {
    do_site_help_give(context);
    str_deallocate(username);
    return 0;
  }

  /* check if user already exists */
  if ( backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    str_deallocate(username); str_deallocate(str_give);
    return 0;
  }

  kbytes = strtoull(str_tochar(str_give),&ptr,0);
  if (*ptr!='\0') {
    do_site_help_give(context);
    str_deallocate(username); str_deallocate(str_give);
    return 0;
  }
  str_deallocate(str_give);
  kbytes *= 1024;

#if 0
  /* TODO find user group or take current user */
  if (is_gadmin)
  {
    /* GAdmins cannot change user from different group */
    if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0])
    {
      ret = send_message_with_args(501,context,"You are not allowed to change users from this group");
      return 0;
    }
  }
#endif /* 0 */

  /* check user credits */
  if (me->credits && me->credits < kbytes) {
    ret = send_message_with_args(501,context,"You don't have enough credits !");
    str_deallocate(username);
    return 0;
  }

  user.credits += kbytes;
  if (me->credits)
    me->credits -= kbytes;

  /* add it to backend */
  ret = backend_mod_user(mainConfig->backend.filename,str_tochar(username),&user,_USER_CREDITS);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem changing value");
  } else {
    ret = send_message_with_args(200,context,"Credits given");
  }
  str_deallocate(username);
  return 0;
}

void do_site_help_take(wzd_context_t * context)
{
  send_message_with_args(501,context,"site take <user> <kbytes>");
}

/** site take: removes credits to user
 *
 * take user kbytes
 */
int do_site_take(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * str_take, *username;
  int ret;
  wzd_user_t user, *me;
  int uid;
  u64_t kbytes;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_take(context);
    return 0;
  }
  str_take = str_tok(command_line," \t\r\n");
  if (!str_take) {
    do_site_help_take(context);
    str_deallocate(username);
    return 0;
  }

  /* check if user already exists */
  if ( backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    str_deallocate(username); str_deallocate(str_take);
    return 0;
  }

  kbytes = strtoull(str_tochar(str_take),&ptr,0);
  if (*ptr!='\0') {
    do_site_help_take(context);
    str_deallocate(username); str_deallocate(str_take);
    return 0;
  }
  str_deallocate(str_take);
  kbytes *= 1024;

#if 0
  /* TODO find user group or take current user */
  if (is_gadmin)
  {
    /* GAdmins cannot change user from different group */
    if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0])
    {
      ret = send_message_with_args(501,context,"You are not allowed to change users from this group");
      return 0;
    }
  }
#endif /* 0 */

  /* check user credits */
  if (user.ratio==0) {
    ret = send_message_with_args(501,context,"User has unlimited credits !");
    str_deallocate(username);
    return 0;
  }

  if (user.credits > kbytes)
    user.credits -= kbytes;
  else
    user.credits = 0;

  /* add it to backend */
  ret = backend_mod_user(mainConfig->backend.filename,str_tochar(username),&user,_USER_CREDITS);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem changing value");
  } else {
    ret = send_message_with_args(200,context,"Credits removed");
  }
  str_deallocate(username);
  return 0;
}


void do_site_help_su(wzd_context_t * context)
{
  send_message_with_args(501,context,"site su <user>");
}

/** site su: become another user
 *
 * su user
 */
int do_site_su(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t *username;
  int ret;
  wzd_user_t user, *me;
  int uid;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  username = str_tok(command_line," \t\r\n");
  if (!username) {
    do_site_help_su(context);
    return 0;
  }

  /* check if user already exists */
  if ( backend_find_user(str_tochar(username),&user,&uid) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    str_deallocate(username);
    return 0;
  }
  str_deallocate(username);

  /* for now, this command is strictly restricted to siteops */
  if (!me || !me->flags || !strchr(me->flags,FLAG_SITEOP)) {
    ret = send_message_with_args(501,context,"You can't use this command, you are not siteop!");
    return 0;
  }


  /* if user is a gadmin, he can only steal identify from its group members */
  if (is_gadmin)
  {
    /* GAdmins cannot change user from different group */
    if (me->group_num==0 || user.group_num==0 || me->groups[0]!=user.groups[0])
    {
      ret = send_message_with_args(501,context,"You are not allowed to become a user from this group");
      return 0;
    }
  }


  /* check user perms */
  if (user.flags && strchr(user.flags,FLAG_SITEOP)) {
    ret = send_message_with_args(501,context,"You can't steal a siteop's identity!");
    return 0;
  }

  /** \todo XXX there is a problem with homedirs here, SU does not check if new
   * homedir is even allowed for new identity.
   */
  context->userid = GetUserIDByName(user.username);
  ret = 0;

  out_log(LEVEL_NORMAL,"Doppelganger: %s usurpated %s's identity\n", me->username, user.username);

  {
    const char * groupname = NULL;
    const char * remote_host;
    struct hostent *h;
    char inet_str[256];
    int af = (context->family == WZD_INET6) ? AF_INET6 : AF_INET;
    if (me->group_num > 0) groupname = GetGroupByID(me->groups[0])->groupname;
    inet_str[0] = '\0';
    inet_ntop(af,context->hostip,inet_str,sizeof(inet_str));
    h = gethostbyaddr((char*)&context->hostip,sizeof(context->hostip),af);
    if (h==NULL)
      remote_host = inet_str;
    else
      remote_host = h->h_name;
    log_message("DOPPEL","%s (%s) \"%s\" \"%s\" \"%s\"",
        (remote_host)?remote_host:"no host !",
        inet_str,
        me->username,
        (groupname)?groupname:"No Group",
        user.username
        );
  }

  if (ret) {
    ret = send_message_with_args(501,context,"Command Failed");
  } else {
    ret = send_message_with_args(200,context,"Command OK");
  }
  return 0;
}







static int _user_changeflags(wzd_user_t * user, const char *newflags)
{
  size_t length;
  char * ptr;

  if (!user || !newflags) return -1;

  if (newflags[0] == '+') {
    /* flag addition */
    length = strlen(user->flags);
    if (length+strlen(newflags) >= MAX_FLAGS_NUM) return -1;

    wzd_strncpy(user->flags+length,newflags+1,MAX_FLAGS_NUM-length-1);
    /* remove duplicate flags */
    _flags_simplify(user->flags,MAX_FLAGS_NUM);

    return 0;
  }
  else if (newflags[0] == '-') {
    /* flag removal */
    /** remove all flags from newflags */
    while ( (++newflags)[0] != '\0') {
      if ( (ptr = strchr(user->flags,newflags[0])) == NULL ) {
        continue;
      }
      if (*(ptr+1)) {
        length = strlen(ptr+1);
        memmove(ptr,ptr+1,length);
        *(ptr+length) = '\0';
      } else {
        *ptr = '\0';
      }
    }

    return 0;
  }
  else {
    /* replace flags */
    strncpy(user->flags,newflags,MAX_FLAGS_NUM-1);
    _flags_simplify(user->flags,MAX_FLAGS_NUM);
    return 0;
  }

  return -1;
}

static void _flags_simplify(char *flags, size_t length)
{
  char * ptr, * test;
  size_t l;

  l = strlen(flags);

  for (test=flags; (length > 0) && (*test) ; test++,l--)
  {
    while ( (ptr = strchr(test+1,*test)) ) {
      /* replace duplicate flag with last one */
      *ptr = flags[l-1];
      flags[l-1] = '\0';
      l--;
    }
  }
}
