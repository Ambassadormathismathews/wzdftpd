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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <signal.h>
#include <pthread.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_site_group.h"


/* prototypes */
void do_site_help(const char *site_command, wzd_context_t * context);



void do_site_help_grpadd(wzd_context_t * context)
{
  send_message_with_args(501,context,"site grpadd <group> [<backend>]");
}

/** site grpadd: adds a new group
 *
 * grpadd &lt;group&gt; [&lt;backend&gt;]
 */
int do_site_grpadd(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char *groupname, *homedir;
  int ret;
  wzd_user_t *me;
  wzd_group_t *mygroup=NULL, newgroup;
  int i;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpadd(context);
    return 0;
  }
  /* TODO read backend */

  /* check if group already exists */
  if ( GetGroupIDByName(groupname) ) {
    ret = send_message_with_args(501,context,"Group already exists");
    return 0;
  }

  /* Gadmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmins can't add groups !");
    return 0;
  }
  mygroup = GetGroupByID(me->groups[0]);
  if (mygroup) {
    homedir = mygroup->defaultpath;
  } else {
    homedir = me->rootpath;
  }
  /* check if homedir exist */
  {
    struct stat s;
    if (stat(homedir,&s) || !S_ISDIR(s.st_mode)) {
      ret = send_message_with_args(501,context,"Homedir does not exist");
      return 0;
    }
  }

  /* create new group */
  strncpy(newgroup.groupname,groupname,128);
  strncpy(newgroup.defaultpath,homedir,1023);
  newgroup.groupperms = 0;
  newgroup.max_idle_time = 0;
  newgroup.max_dl_speed = 0;
  newgroup.max_ul_speed = 0;
  newgroup.ratio = 0;
  for (i=0; i<HARD_IP_PER_GROUP; i++)
    newgroup.ip_allowed[i][0]='\0';

  /* add it to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_group("plaintext",groupname,&newgroup,_GROUP_ALL);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem adding group");
  } else {
    ret = send_message_with_args(200,context,"Group added");
  }
  return 0;
}

void do_site_help_grpdel(wzd_context_t * context)
{
  send_message_with_args(501,context,"site grpdel <group> [<backend>]");
}


/** site grpdel: delete group
 *
 * grpdel &lt;group&gt; [&lt;backend&gt;]
 */
int do_site_grpdel(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * groupname;
  int ret;
  wzd_user_t *me, *user;
  short is_gadmin;
  int gid,i;
  int users_maingroup_changed[HARD_DEF_USER_MAX];
  int num_users_maingroup_changed=0;
  int users_without_group[HARD_DEF_USER_MAX];
  int num_users_without_group=0;
  char buffer[256];

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpdel(context);
    return 0;
  }
  /* TODO read backend */

  /* check if group already exists */
  if ( !(gid=GetGroupIDByName(groupname)) ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmin can't delete groups");
    return 0;
  }

  /* commit changes to backend */
  /* FIXME backend name hardcoded */
  backend_mod_group("plaintext",groupname,NULL,_GROUP_ALL);

  send_message_raw("200-\r\n",context);
  /* iterate through user list and delete all references to group */
  for (i=0; i<HARD_DEF_USER_MAX; i++)
  {
    user = GetUserByID(i);
    if (user->username[0]=='\0') continue;
    if (is_user_in_group(user,gid))
    {
      /* warn for users with no groups and / or primary group
       * changed
       */ 
      if (user->groups[0] == gid) {
	snprintf(buffer,256,"200-WARNING %s main group is changed !\r\n",user->username);
	send_message_raw(buffer,context);
      }
      group_remove_user(user,gid);
      if (user->group_num == 0) {
	snprintf(buffer,256,"200-WARNING %s has no group now !\r\n",user->username);
	send_message_raw(buffer,context);
      }
    }
  }
  /* TODO XXX FIXME delete users belonging only to this group ? */

  ret = send_message_raw("200 Group deleted\r\n",context);
  return 0;
}

void do_site_help_grpren(wzd_context_t * context)
{
  send_message_with_args(501,context,"site grpren <groupname> <newgroupname>");
}
/** site grpren: rename group
 *
 * grpren oldname newname
 */
int do_site_grpren(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * groupname, *newgroupname;
  int ret;
  wzd_user_t *me;
  wzd_group_t group;
  int gid;
  unsigned int ratio;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpren(context);
    return 0;
  }
  newgroupname = strtok_r(NULL," \t\r\n",&ptr);
  if (!newgroupname) {
    do_site_help_grpren(context);
    return 0;
  }

  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  /* check if group exists */
  if ( (GetGroupIDByName(newgroupname))!=0 ) {
    ret = send_message_with_args(501,context,"New group already exists");
    return 0;
  }

  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"GAdmins can't do that !");
    return 0;
  }

  strcpy(group.groupname,newgroupname);

  /* add it to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_group("plaintext",groupname,&group,_GROUP_GROUPNAME);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem changing value");
  } else {
    ret = send_message_with_args(200,context,"Group name changed");
  }
  return 0;
}

int do_site_ginfo(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * groupname;
  int ret;
  wzd_group_t group;
  int gid;
  wzd_context_t user_context;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help("ginfo",context);
    return 0;
  }
  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }
  /* needed, because do_site_print_file writes directly to context->controlfd */
  user_context.userid = gid;
  user_context.magic = CONTEXT_MAGIC;

  /* TODO XXX FIXME gadmins can see ginfo only on their primary group ? */
  do_site_print_file(mainConfig->site_config.file_ginfo,NULL,&group,context);
  user_context.magic = 0;

  return 0;
}

int do_site_gsinfo(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * groupname;
  int ret;
  wzd_group_t group;
  int gid;
  wzd_context_t user_context;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help("gsinfo",context);
    return 0;
  }
  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }
  /* needed, because do_site_print_file writes directly to context->controlfd */
  user_context.userid = gid;
  user_context.magic = CONTEXT_MAGIC;

/*#if BACKEND_STORAGE*/
  do_site_print_file(mainConfig->site_config.file_group,NULL,&group,context);
/*#endif
  do_site_print_file(mainConfig->site_config.file_user,NULL,GetGroupByID(uid),context);*/
  user_context.magic = 0;

  return 0;
}

void do_site_help_grpaddip(wzd_context_t * context)
{
  send_message_with_args(501,context,"site grpaddip <group> <ip>");
}

/** site grpaddip: adds an ip to a group
 *
 * grpaddip &lt;group&gt; &lt;ip&gt;
 */
int do_site_grpaddip(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * groupname, *ip;
  int ret;
  wzd_user_t *me;
  wzd_group_t group;
  int gid;
  int i;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpaddip(context);
    return 0;
  }
  ip = strtok_r(NULL," \t\r\n",&ptr);
  if (!ip) {
    do_site_help_grpaddip(context);
    return 0;
  }

  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmins can't do that !");
    return 0;
  }

  /* check if ip is already present or included in list, or if it shadows one present */
  for (i=0; i<HARD_IP_PER_GROUP; i++)
  {
    if (group.ip_allowed[i][0]=='\0') continue;
    if (my_str_compare(ip,group.ip_allowed[i])==1) { /* ip is already included in list */
      ret = send_message_with_args(501,context,"ip is already included in list");
      return 0;
    }
    if (my_str_compare(group.ip_allowed[i],ip)==1) { /* ip will shadow one ore more ip in list */
      ret = send_message_with_args(501,context,"ip will shadow some ip in list, remove them before");
      return 0;
    }
  }

  /* update group */
  for (i=0; i<HARD_IP_PER_GROUP; i++)
    if (group.ip_allowed[i][0]=='\0') break;

  /* no more slots ? */
  if (i==HARD_IP_PER_GROUP) {
    ret = send_message_with_args(501,context,"No more slots available - either recompile with more slots, or use them more cleverly !");
    return 0;
  }
  /* TODO check ip validity */
  strncpy(group.ip_allowed[i],ip,MAX_IP_LENGTH-1);

  /* commit to backend */
  /* FIXME backend name hardcoded */
  backend_mod_group("plaintext",groupname,&group,_GROUP_IP);

  ret = send_message_with_args(200,context,"Group ip added");
  return 0;
}

void do_site_help_grpdelip(wzd_context_t * context)
{
  send_message_raw("501-Usage: site grpdelip <group> <ip>\r\n",context);
  send_message_raw("501  or: site grpdelip <grp> <slot_number> (get it with site ginfo <group>)\r\n",context);
}

/** site grpdelip: removes ip from group
 *
 * grpdelip &lt;group&gt; &lt;ip&gt;
 *
 * grpdelip &lt;group&gt; &lt;slot_number&gt;
 */
int do_site_grpdelip(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * groupname, *ip;
  int ret;
  wzd_user_t *me;
  wzd_group_t group;
  int gid;
  int i;
  unsigned long ul;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpdelip(context);
    return 0;
  }
  ip = strtok_r(NULL," \t\r\n",&ptr);
  if (!ip) {
    do_site_help_grpdelip(context);
    return 0;
  }

  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmins can't do that !");
    return 0;
  }

  /* try to take argument as a slot number */
  ul = strtoul(ip,&ptr,0);
  if (*ptr=='\0') {
    if (ul <= 0 || ul >= HARD_IP_PER_GROUP) {
      ret = send_message_with_args(501,context,"Invalid ip slot number");
      return 0;
    }
    ul--; /* to index slot number from 1 */
    if (group.ip_allowed[ul][0] == '\0') {
      ret = send_message_with_args(501,context,"Slot is already empty");
      return 0;
    }
    group.ip_allowed[ul][0] = '\0';
    backend_mod_group("plaintext",groupname,&group,_GROUP_IP);
    ret = send_message_with_args(200,context,"Group ip removed");
    return 0;
  } /* if (*ptr=='\0') */

  /* try to find ip in list */
  for (i=0; i<HARD_IP_PER_GROUP; i++)
  {
    if (group.ip_allowed[i][0]=='\0') continue;
    if (strcmp(ip,group.ip_allowed[i])==0) {
      group.ip_allowed[i][0] = '\0';
      /* commit to backend */
      /* FIXME backend name hardcoded */
      backend_mod_group("plaintext",groupname,&group,_USER_IP);
      ret = send_message_with_args(200,context,"Group ip removed");
      return 0;
    }
  }

  ret = send_message_with_args(501,context,"IP not found");
  return 0;
}

void do_site_help_grpratio(wzd_context_t * context)
{
  send_message_with_args(501,context,"site grpratio <group> <ratio>");
}
/** site grpratio: change group ratio
 *
 * grpratio group ratio
 */
int do_site_grpratio(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * str_ratio, *groupname;
  int ret;
  wzd_user_t *me;
  wzd_group_t group;
  int gid;
  unsigned int ratio;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpratio(context);
    return 0;
  }
  str_ratio = strtok_r(NULL," \t\r\n",&ptr);
  if (!str_ratio) {
    do_site_help_grpratio(context);
    return 0;
  }

  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  ratio = strtoul(str_ratio,&ptr,0);
  if (*ptr!='\0') {
    do_site_help_grpratio(context);
    return 0;
  }

  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"GAdmins can't do that !");
    return 0;
  }

  group.ratio = ratio;

  /* add it to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_group("plaintext",groupname,&group,_GROUP_RATIO);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem changing value");
  } else {
    ret = send_message_with_args(200,context,"Group ratio changed");
  }
  return 0;
}

/** site grpkill: kill all connections from a group
 *
 * grpkill group
 */
int do_site_grpkill(char *command_line, wzd_context_t * context)
{
  char * ptr;
  char * groupname;
  int ret;
  wzd_group_t group;
  int i,found;
  wzd_user_t * user, * me;
  int gid;
  wzd_context_t user_context;

  me = GetUserByID(context->userid);
  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help("grpkill",context);
    return 0;
  }
  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC) {
      user = GetUserByID(context_list[i].userid);
      if (strcmp(me->username,user->username) && is_user_in_group(user,gid)) {
	found=1;
	kill_child(context_list[i].pid_child,context);
      }
    }
  }

  if (!found) { ret = send_message_with_args(501,context,"No member found !"); }
  else { ret = send_message_with_args(200,context,"KILL signal sent"); }

  return 0;
}


void do_site_help_grpchange(wzd_context_t * context)
{
  send_message_raw("501-site grpchange <group> <field> <value>\r\n",context);
  send_message_raw("field can be one of:\r\n",context);
  send_message_raw(" name        changes the group name\r\n",context);
  send_message_raw(" homedir     changes group's default dir\r\n",context);
  send_message_raw(" max_idle    changes idle time\r\n",context);
  send_message_raw(" perms       changes default group permissions\r\n",context);
  send_message_raw(" max_ul      changes maximum upload speed\r\n",context);
  send_message_raw(" max_dl      changes maximum download speed\r\n",context);
  send_message_raw(" ratio       changes group default ratio\r\n",context);
  send_message_raw(" num_logins  changes maximum simultaneous logins allowed\r\n",context);

  send_message_raw("501 site grpchange aborted\r\n",context);
}

/** site grpchange: change a field for a group
 *
 * grpchange &lt;group&gt; &lt;field&gt; &lt;value&gt;
 */
int do_site_grpchange(char *command_line, wzd_context_t * context)
{
  char *ptr;
  char * groupname, * field, * value;
  unsigned long mod_type, ul;
  int ret;
  int gid;
  wzd_group_t group;
  wzd_user_t * me;

  me = GetUserByID(context->userid);

  ptr = command_line;
  groupname = strtok_r(command_line," \t\r\n",&ptr);
  if (!groupname) {
    do_site_help_grpchange(context);
    return 0;
  }
  field = strtok_r(NULL," \t\r\n",&ptr);
  if (!field) {
    do_site_help_grpchange(context);
    return 0;
  }
  value = strtok_r(NULL,"\r\n",&ptr);
  if (!value) {
    do_site_help_grpchange(context);
    return 0;
  }

  /* check if group exists */
  if ( (gid=GetGroupIDByName(groupname))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }
  if ( backend_find_group(gid, &group, NULL) ) {
    ret = send_message_with_args(501,context,"Error getting group info");
    return 0;
  }

  /* find modification type */
  mod_type = _USER_NOTHING;

  /* groupname */
  if (strcmp(field,"name")==0) {
    mod_type = _GROUP_GROUPNAME;
    strncpy(group.groupname,value,255);
    /* NOTE: we do not need to iterate through users, group is referenced
     * by id, not by name
     */
  }
  /* homedir */
  else if (strcmp(field,"homedir")==0) {
    /* check if homedir exist */
    {
      struct stat s;
      if (stat(value,&s) || !S_ISDIR(s.st_mode)) {
	ret = send_message_with_args(501,context,"Homedir does not exist");
	return 0;
      }
    }
    mod_type = _GROUP_DEFAULTPATH;
    strncpy(group.defaultpath,value,1023);
  }
  /* max_idle */
  else if (strcmp(field,"max_idle")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_IDLE; group.max_idle_time = ul; }
  }
  /* perms */
  else if (strcmp(field,"perms")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_GROUPPERMS; group.groupperms = ul; }
  }
  /* max_ul */
  else if (strcmp(field,"max_ul")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_MAX_ULS; group.max_ul_speed = ul; }
  }
  /* max_dl */
  else if (strcmp(field,"max_dl")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_MAX_DLS; group.max_dl_speed = ul; }
  }
  /* num_logins */
  else if (strcmp(field,"num_logins")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) { mod_type = _GROUP_NUMLOGINS; group.num_logins = ul; }
  }
  /* ratio */
  else if (strcmp(field,"ratio")==0) {
    ul=strtoul(value,&ptr,0);
    if (!*ptr) {
      if ((!me->flags || !strchr(me->flags,FLAG_SITEOP)) && ul==0) {
	/* wants a leech access for group, but is not siteop */
	ret = send_message_with_args(501,context,"Only siteops can do that");
	return 0;
      }
      mod_type = _GROUP_RATIO; group.ratio = ul;
    }
  }

  /* commit to backend */
  /* FIXME backend name hardcoded */
  ret = backend_mod_group("plaintext",groupname,&group,mod_type);

  if (ret)
    ret = send_message_with_args(501,context,"Problem occured when committing");
  else
    ret = send_message_with_args(200,context,"Group field change successfull");

  return 0;
}

#if 0
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
    username = GetUserByID(context->userid)->username;
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
    username = GetUserByID(context->userid)->username;
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
    username = GetUserByID(context->userid)->username;
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
#endif /* 0 */


