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

#include <pthread.h>
#endif

#include <errno.h>
#include <signal.h>

#include "wzd_structs.h"

#include "wzd_configfile.h"
#include "wzd_fs.h"
#include "wzd_group.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_site.h"
#include "wzd_site_group.h"
#include "wzd_user.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */


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
int do_site_grpadd(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t *groupname;
  char *homedir;
  int ret;
  wzd_user_t *me;
  wzd_group_t *mygroup=NULL, *newgroup;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpadd(context);
    return 0;
  }
  /* TODO read backend */

  /* check if group already exists */
  if ( GetGroupByName(str_tochar(groupname)) ) {
    ret = send_message_with_args(501,context,"Group already exists");
    str_deallocate(groupname);
    return 0;
  }

  /* backend will do that */
  /* check groups limit */

  /* Gadmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmins can't add groups !");
    str_deallocate(groupname);
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
    fs_filestat_t s;
    if (fs_file_stat(homedir,&s) || !S_ISDIR(s.mode)) {
      ret = send_message_with_args(501,context,"Homedir does not exist");
      str_deallocate(groupname);
      return 0;
    }
  }

  /* create new group */
  newgroup = group_allocate();

  strncpy(newgroup->groupname,str_tochar(groupname),sizeof(newgroup->groupname));
  strncpy(newgroup->defaultpath,homedir,WZD_MAX_PATH);

  /* add it to backend */
  ret = backend_mod_group(mainConfig->backends->filename,str_tochar(groupname),newgroup,_GROUP_ALL);

  str_deallocate(groupname);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem adding group");
    group_free(newgroup);
  } else {
    ret = send_message_with_args(200,context,"Group added");
    /* do not free group, it is stored in registry */
  }
  return 0;
}

void do_site_help_grpdel(wzd_context_t * context)
{
  send_message_with_args(501,context,"site grpdel <group> [<backend>]");
}


/** site grpdel: delete group
 *
 * grpdel &lt;group&gt;
 */
int do_site_grpdel(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * groupname;
  int ret;
  wzd_user_t *me, *user;
  short is_gadmin;
  unsigned int gid;
  int i;
/*  int users_maingroup_changed[HARD_DEF_USER_MAX];*/
/*  int num_users_maingroup_changed=0;*/
/*  int users_without_group[HARD_DEF_USER_MAX];*/
/*  int num_users_without_group=0;*/
  char buffer[256];
  int * uid_list;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpdel(context);
    return 0;
  }
  /* TODO read backend */

  /* check if group already exists */
  if ( (gid=GetGroupIDByName(str_tochar(groupname))) == (unsigned int)-1 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    str_deallocate(groupname);
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmin can't delete groups");
    str_deallocate(groupname);
    return 0;
  }

  send_message_raw("200-\r\n",context);
  /* iterate through user list and delete all references to group */
  uid_list = (int*)backend_get_user(GET_USER_LIST);
  if (uid_list) {
    for (i=0; uid_list[i] >= 0; i++)
    {
      user = GetUserByID(uid_list[i]);
      if (!user || user->username[0]=='\0') continue;
      if (is_user_in_group(user,gid))
      {
        /* warn for users with no groups and / or primary group
         * changed
         */
        if (user->groups[0] == gid) {
          snprintf(buffer,sizeof(buffer),"200-WARNING %s main group is changed !\r\n",user->username);
          send_message_raw(buffer,context);
        }
        group_remove_user(user,gid);
        if (user->group_num == 0) {
          snprintf(buffer,sizeof(buffer),"200-WARNING %s has no group now !\r\n",user->username);
          send_message_raw(buffer,context);
        }
      }
    }
    wzd_free(uid_list);
  } /* if (uid_list) */
  /* TODO XXX FIXME delete users belonging only to this group ? */

  /* commit changes to backend */
  backend_mod_group(mainConfig->backends->filename,str_tochar(groupname),NULL,_GROUP_ALL);
  str_deallocate(groupname);

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
int do_site_grpren(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * groupname, *newgroupname;
  int ret;
  wzd_user_t *me;
  wzd_group_t group, *oldgroup;
/*  unsigned int ratio;*/
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpren(context);
    return 0;
  }
  newgroupname = str_tok(command_line," \t\r\n");
  if (!newgroupname) {
    do_site_help_grpren(context);
    str_deallocate(groupname);
    return 0;
  }

  /* check if group exists */
  oldgroup = GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !oldgroup ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    str_deallocate(newgroupname);
    return 0;
  }
  memcpy(&group,oldgroup,sizeof(wzd_group_t));

  /* check if group exists */
  if ( (GetGroupByName(str_tochar(newgroupname))) ) {
    ret = send_message_with_args(501,context,"New group already exists");
    str_deallocate(newgroupname);
    return 0;
  }

  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"GAdmins can't do that !");
    str_deallocate(newgroupname);
    return 0;
  }

  strncpy(group.groupname,str_tochar(newgroupname),sizeof(group.groupname));
  str_deallocate(newgroupname);

  /* add it to backend */
  ret = backend_mod_group(mainConfig->backends->filename,oldgroup->groupname,&group,_GROUP_GROUPNAME);

  if (ret) {
    ret = send_message_with_args(501,context,"Problem changing value");
  } else {
    ret = send_message_with_args(200,context,"Group name changed");
  }
  return 0;
}

int do_site_ginfo(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * str;
  wzd_string_t * groupname;
  int ret;
  wzd_group_t * group;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help("ginfo",context);
    return 0;
  }
  /* check if group exists (note: we rely on cache to avoid memory leak here) */
  group=GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  str = config_get_string(mainConfig->cfg_file,"GLOBAL","sitefile_ginfo",NULL);
  if (!str) {
    ret = send_message_with_args(501,context,"File [GLOBAL] / sitefile_ginfo does not exists");
    return 0;
  }

  /* TODO XXX FIXME gadmins can see ginfo only on their primary group ? */
  do_site_print_file(str_tochar(str),NULL,group,context);

  str_deallocate(str);

  return 0;
}

int do_site_gsinfo(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * str;
  wzd_string_t * groupname;
  int ret;
  wzd_group_t * group;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help("gsinfo",context);
    return 0;
  }
  /* check if group exists */
  group = GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  str = config_get_string(mainConfig->cfg_file,"GLOBAL","sitefile_group",NULL);
  if (!str) {
    ret = send_message_with_args(501,context,"File [GLOBAL] / sitefile_group does not exists");
    return 0;
  }

  do_site_print_file(str_tochar(str),NULL,group,context);

  str_deallocate(str);

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
int do_site_grpaddip(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  wzd_string_t * groupname, *ip;
  int ret;
  wzd_user_t * me;
  wzd_group_t * group;
  int i;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpaddip(context);
    return 0;
  }

  /* check if group exists */
  group=GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmins can't do that !");
    return 0;
  }

  ip = str_tok(command_line," \t\r\n");
  if (!ip) {
    do_site_help_grpaddip(context);
    return 0;
  }

  /* check if ip is already present or included in list, or if it shadows one present */
  for (i=0; i<HARD_IP_PER_GROUP; i++)
  {
    if (group->ip_allowed[i][0]=='\0') continue;
    if (my_str_compare(str_tochar(ip),group->ip_allowed[i])==1) { /* ip is already included in list */
      ret = send_message_with_args(501,context,"ip is already included in list");
      str_deallocate(ip);
      return 0;
    }
    if (my_str_compare(group->ip_allowed[i],str_tochar(ip))==1) { /* ip will shadow one ore more ip in list */
      ret = send_message_with_args(501,context,"ip will shadow some ip in list, remove them before");
      str_deallocate(ip);
      return 0;
    }
  }

  /* update group */
  for (i=0; i<HARD_IP_PER_GROUP; i++)
    if (group->ip_allowed[i][0]=='\0') break;

  /* no more slots ? */
  if (i==HARD_IP_PER_GROUP) {
    ret = send_message_with_args(501,context,"No more slots available - either recompile with more slots, or use them more cleverly !");
    str_deallocate(ip);
    return 0;
  }
  /* TODO check ip validity */
  strncpy(group->ip_allowed[i],str_tochar(ip),MAX_IP_LENGTH-1);

  /* commit to backend */
  backend_mod_group(mainConfig->backends->filename,group->groupname,group,_GROUP_IP);

  ret = send_message_with_args(200,context,"Group ip added");
  str_deallocate(ip);
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
int do_site_grpdelip(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * groupname, *ip;
  int ret;
  wzd_user_t * me;
  wzd_group_t * group;
  int i;
  unsigned long ul;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpdelip(context);
    return 0;
  }
  /* check if group exists */
  group=GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  ip = str_tok(command_line," \t\r\n");
  if (!ip) {
    do_site_help_grpdelip(context);
    return 0;
  }

  /* GAdmin ? */
  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"Gadmins can't do that !");
    str_deallocate(ip);
    return 0;
  }

  /* try to take argument as a slot number */
  ul = strtoul(str_tochar(ip),&ptr,0);
  if (*ptr=='\0') {
    if (ul <= 0 || ul > HARD_IP_PER_GROUP) {
      ret = send_message_with_args(501,context,"Invalid ip slot number");
      str_deallocate(ip);
      return 0;
    }
    str_deallocate(ip);
    ul--; /* to index slot number from 1 */
    if (group->ip_allowed[ul][0] == '\0') {
      ret = send_message_with_args(501,context,"Slot is already empty");
      return 0;
    }
    group->ip_allowed[ul][0] = '\0';
    backend_mod_group(mainConfig->backends->filename,group->groupname,group,_GROUP_IP);
    ret = send_message_with_args(200,context,"Group ip removed");
    return 0;
  } /* if (*ptr=='\0') */

  /* try to find ip in list */
  for (i=0; i<HARD_IP_PER_GROUP; i++)
  {
    if (group->ip_allowed[i][0]=='\0') continue;
    if (strcmp(str_tochar(ip),group->ip_allowed[i])==0) {
      group->ip_allowed[i][0] = '\0';
      /* commit to backend */
      /* FIXME backend name hardcoded */
      backend_mod_group(mainConfig->backends->filename,group->groupname,group,_GROUP_IP);
      ret = send_message_with_args(200,context,"Group ip removed");
      str_deallocate(ip);
      return 0;
    }
  }
  str_deallocate(ip);

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
int do_site_grpratio(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * str_ratio, *groupname;
  int ret;
  wzd_user_t * me;
  wzd_group_t * group;
  unsigned int ratio;
  short is_gadmin;

  me = GetUserByID(context->userid);
  is_gadmin = (me->flags && strchr(me->flags,FLAG_GADMIN)) ? 1 : 0;

  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpratio(context);
    return 0;
  }
  /* check if group exists */
  group=GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  str_ratio = str_tok(command_line," \t\r\n");
  if (!str_ratio) {
    do_site_help_grpratio(context);
    return 0;
  }

  ratio = strtoul(str_tochar(str_ratio),&ptr,0);
  if (*ptr!='\0') {
    do_site_help_grpratio(context);
    str_deallocate(str_ratio);
    return 0;
  }
  str_deallocate(str_ratio);

  if (is_gadmin)
  {
    ret = send_message_with_args(501,context,"GAdmins can't do that !");
    return 0;
  }

  group->ratio = ratio;

  /* add it to backend */
  ret = backend_mod_group(mainConfig->backends->filename,group->groupname,group,_GROUP_RATIO);

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
int do_site_grpkill(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  ListElmt * elmnt;
  wzd_context_t * loop_context;
  wzd_string_t * groupname;
  int ret;
  wzd_group_t * group;
  int found=0;
  wzd_user_t * user, * me;

  me = GetUserByID(context->userid);
  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help("grpkill",context);
    return 0;
  }
  /* check if group exists */
  group=GetGroupByName(str_tochar(groupname));
  str_deallocate(groupname);
  if ( !group ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    return 0;
  }

  for (elmnt=list_head(context_list); elmnt; elmnt=list_next(elmnt))
  {
    loop_context = list_data(elmnt);
    if (loop_context && loop_context->magic == CONTEXT_MAGIC) {
      user = GetUserByID(loop_context->userid);
      if (strcmp(me->username,user->username) && is_user_in_group(user,group->gid)) {
        found=1;
        kill_child(loop_context->pid_child,context);
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
  send_message_raw(" tagline     changes the group tagline\r\n",context);
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
int do_site_grpchange(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{
  char *ptr;
  wzd_string_t * groupname, * field, * value;
  unsigned long mod_type, ul;
  int ret;
  wzd_group_t * group;
  wzd_user_t * me;

  me = GetUserByID(context->userid);

  if (!command_line) {
    do_site_help_grpchange(context);
    return 0;
  }
  groupname = str_tok(command_line," \t\r\n");
  if (!groupname) {
    do_site_help_grpchange(context);
    return 0;
  }
  field = str_tok(command_line," \t\r\n");
  if (!field) {
    do_site_help_grpchange(context);
    str_deallocate(groupname);
    return 0;
  }
  value = str_tok(command_line,"\r\n");
  if (!value) {
    do_site_help_grpchange(context);
    str_deallocate(groupname); str_deallocate(field);
    return 0;
  }

  /* check if group exists */
  if ( (group=GetGroupByName(str_tochar(groupname)))==0 ) {
    ret = send_message_with_args(501,context,"Group does not exist");
    str_deallocate(groupname); str_deallocate(field); str_deallocate(value);
    return 0;
  }

  /* find modification type */
  mod_type = _GROUP_NOTHING;

  /* groupname */
  if (strcmp(str_tochar(field),"name")==0) {
    mod_type = _GROUP_GROUPNAME;
    strncpy(group->groupname,str_tochar(value),255);
    /* NOTE: we do not need to iterate through users, group is referenced
     * by id, not by name
     */
  }
  /* tagline */
  else if (strcmp(str_tochar(field),"tagline")==0) {
    mod_type = _GROUP_TAGLINE;
    strncpy(group->tagline,str_tochar(value),255);
  }
  /* homedir */
  else if (strcmp(str_tochar(field),"homedir")==0) {
    /* check if homedir exist */
    {
      fs_filestat_t s;
      if (fs_file_stat(str_tochar(value),&s) || !S_ISDIR(s.mode)) {
        ret = send_message_with_args(501,context,"Homedir does not exist");
        str_deallocate(groupname); str_deallocate(field); str_deallocate(value);
        return 0;
      }
    }
    mod_type = _GROUP_DEFAULTPATH;
    strncpy(group->defaultpath,str_tochar(value),WZD_MAX_PATH);
  }
  /* max_idle */
  else if (strcmp(str_tochar(field),"max_idle")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _GROUP_IDLE; group->max_idle_time = ul; }
  }
  /* perms */
  else if (strcmp(str_tochar(field),"perms")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _GROUP_GROUPPERMS; group->groupperms = ul; }
  }
  /* max_ul */
  else if (strcmp(str_tochar(field),"max_ul")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _GROUP_MAX_ULS; group->max_ul_speed = ul; }
  }
  /* max_dl */
  else if (strcmp(str_tochar(field),"max_dl")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _GROUP_MAX_DLS; group->max_dl_speed = ul; }
  }
  /* num_logins */
  else if (strcmp(str_tochar(field),"num_logins")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) { mod_type = _GROUP_NUMLOGINS; group->num_logins = (unsigned short)ul; }
  }
  /* ratio */
  else if (strcmp(str_tochar(field),"ratio")==0) {
    ul=strtoul(str_tochar(value),&ptr,0);
    if (!*ptr) {
      if ((!me->flags || !strchr(me->flags,FLAG_SITEOP)) && ul==0) {
        /* wants a leech access for group, but is not siteop */
        ret = send_message_with_args(501,context,"Only siteops can do that");
        str_deallocate(groupname); str_deallocate(field); str_deallocate(value);
        return 0;
      }
      mod_type = _GROUP_RATIO; group->ratio = ul;
    }
  }
  else {
    str_deallocate(groupname); str_deallocate(field); str_deallocate(value);
    ret = send_message_with_args(501,context,"syntax error, unknow field");
    return 0;
  }

  /* commit to backend */
  ret = backend_mod_group(mainConfig->backends->filename,str_tochar(groupname),group,mod_type);

  str_deallocate(groupname); str_deallocate(field); str_deallocate(value);

  if (ret)
    ret = send_message_with_args(501,context,"Problem occured when committing");
  else
    ret = send_message_with_args(200,context,"Group field change successfull");

  return 0;
}


void do_site_help_group(wzd_context_t * context)
{
  send_message_raw("501-site group <action> ...\r\n",context);
  send_message_raw("action can be one of:\r\n",context);
  send_message_raw(" info       give group info\r\n",context);
  send_message_raw(" add        add a new group\r\n",context);
  send_message_raw(" delete     delete a group\r\n",context);
  send_message_raw(" rename     rename a group\r\n",context);
  send_message_raw(" stat       give group statistic\r\n",context);
  send_message_raw(" addip      add an IP for group\r\n",context);
  send_message_raw(" delip      delete an IP for group\r\n",context);
  send_message_raw(" ratio      set group ratio\r\n",context);
  send_message_raw(" kill       kill all group connections\r\n",context);
  send_message_raw(" change     change group fields\r\n",context);
  send_message_raw(" list       list all existing groups\r\n",context);
  send_message_raw("use site <action> for specific action help\r\n",context);
  send_message_raw("501 site group aborted\r\n",context);
}

/* regroup all group administration in one site command */
int do_site_group(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context)
{

  wzd_string_t * cmd;
  int ret;


  cmd = str_tok(command_line," \t\r\n");

  if( cmd == NULL ) {
    do_site_help_group(context);
    return 0;
  }

  if(strcmp("info", str_tochar(cmd)) == 0) {
    do_site_gsinfo( cmd, command_line, context );
  } else if(strcmp( "add", str_tochar(cmd)) == 0) {
    do_site_grpadd( cmd, command_line, context );
  } else if(strcmp( "delete", str_tochar(cmd)) == 0) {
    do_site_grpdel( cmd, command_line, context );
  } else if(strcmp( "rename", str_tochar(cmd)) == 0) {
    do_site_grpren( cmd, command_line, context );
  } else if(strcmp( "stat", str_tochar(cmd)) == 0) {
    do_site_ginfo( cmd, command_line, context );
  } else if(strcmp( "addip", str_tochar(cmd)) == 0) {
    do_site_grpaddip( cmd, command_line, context );
  } else if(strcmp( "delip", str_tochar(cmd)) == 0) {
    do_site_grpdelip( cmd, command_line, context );
  } else if(strcmp( "ratio", str_tochar(cmd)) == 0) {
    do_site_grpratio( cmd, command_line, context );
  } else if(strcmp( "kill", str_tochar(cmd)) == 0) {
    do_site_grpkill( cmd, command_line, context );
  } else if(strcmp( "change", str_tochar(cmd)) == 0) {
    do_site_grpchange( cmd, command_line, context );
    /** \todo FIXME implement SITE GROUP LIST */
/*  } else if(strcmp( "list", str_tochar(cmd)) == 0) {
    do_site_print_file(mainConfig->site_config.file_groups,NULL,NULL,context);*/
  } else {
    ret = send_message_with_args(501,context,"site group action invalid");
  }

  str_deallocate(cmd);

  return 0;
}

