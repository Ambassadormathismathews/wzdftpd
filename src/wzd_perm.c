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

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "wzd_structs.h"

#include "wzd_perm.h"
#include "wzd_misc.h"

#include "wzd_debug.h"


#define BUFFER_LEN	2048


const char * perm_tab[] = {
  "site",
  "delete",
  NULL
};


/***/

wzd_command_perm_t * perm_create_empty_perm(void)
{
  wzd_command_perm_t * perm;

  perm = malloc(sizeof(wzd_command_perm_t));
  memset(perm->command_name,0,256);
  perm->entry_list = NULL;
  perm->next_perm = NULL;

  return perm;
}

/***/

wzd_command_perm_entry_t * perm_create_empty_entry(void)
{
  wzd_command_perm_entry_t * entry;

  entry = malloc(sizeof(wzd_command_perm_entry_t));
  memset(entry->target,0,256);
  entry->next_entry = NULL;

  return entry;
}

/***/

int perm_remove(const char *commandname, wzd_config_t * config)
{
  wzd_command_perm_t * perm, * previous;
  wzd_command_perm_entry_t * entry_current, * entry_next;
  
  if ( ! config->perm_list ) return -1;

  perm = config->perm_list;
  if (strcasecmp(perm->command_name,commandname)==0) {
    /* first element */
    entry_current = perm->entry_list;
    while (entry_current) {
      entry_next = entry_current->next_entry;
      free(entry_current);
      entry_current = entry_next;
    }
    config->perm_list = perm->next_perm;
    free(perm);
    return 0;
  }

  previous = perm;
  perm = perm->next_perm;

  while(perm) {
    if (strcasecmp(perm->command_name,commandname)==0) {
      entry_current = perm->entry_list;
      while (entry_current) {
        entry_next = entry_current->next_entry;
        free(entry_current);
        entry_current = entry_next;
      }
      previous->next_perm = perm->next_perm;
      free(perm);
      return 0;
    }
    previous = perm;
    perm = perm->next_perm;
  };

  return 1; /* not found */
}

/***/

void perm_free_recursive(wzd_command_perm_t * perm)
{
  wzd_command_perm_t * perm_next;
  wzd_command_perm_entry_t * entry_current, * entry_next;

  if (!perm) return;
  do {
    perm_next = perm->next_perm;
    entry_current = perm->entry_list;
    while (entry_current) {
      entry_next = entry_current->next_entry;
      free(entry_current);
      entry_current = entry_next;
    }
    free(perm);
    perm = perm_next;
  } while (perm);
}

/***/

int perm_is_valid_perm(const char *permname)
{
  int i=0;

  while (perm_tab[i]) {
    if (strncasecmp(permname,"site_",5)==0)
      return 0;
    if (strcasecmp(permname,perm_tab[i])==0)
      return 0;
    i++;
  }

  return 1;
}

/***/

int perm2str(wzd_command_perm_t * perm, char * perm_buffer, unsigned int max_length)
{
  char *perm_buffer_ptr;
  unsigned int length;
  wzd_command_perm_entry_t * entry;

  /* parse current->entry_list */
  perm_buffer_ptr = perm_buffer;
  length=0;
  entry = perm->entry_list;
  while (entry) {
    *perm_buffer_ptr++ = ' ';
    length ++;
    if (strcmp(entry->target,"*")!=0) {
      switch(entry->cp) {
        case CPERM_USER: *perm_buffer_ptr++ = '='; break;
        case CPERM_GROUP: *perm_buffer_ptr++ = '-'; break;
        case CPERM_FLAG: *perm_buffer_ptr++ = '+'; break;
      }
      length ++;
    }
    length += strlen(entry->target);
    if (length >= max_length) return 1;
    strncpy(perm_buffer_ptr,entry->target,max_length-length);
/*    perm_buffer_ptr = perm_buffer+length;*/
    perm_buffer_ptr += strlen(entry->target);
    entry = entry->next_entry;
  }
  perm_buffer[length]='\0';
  return 0;
}

/***/

wzd_command_perm_t * perm_find_create(const char *commandname, wzd_config_t * config)
{
  wzd_command_perm_t * perm, * insert_point;

  if ( ! config->perm_list ) {
    perm = config->perm_list = perm_create_empty_perm();
    strncpy(perm->command_name,commandname,256);
    return perm;
  }

  perm = config->perm_list;
  do {
    /* we use strcmp because commandname is lowered in wzd_init_lex.l (readConfigFile, case '-') */
    if (strcmp(perm->command_name,commandname)==0) {
      return perm;
    }
    perm = perm->next_perm;
  } while (perm);

  /* not found, insert a new perm (tail insertion) */
  perm = perm_create_empty_perm();
  strncpy(perm->command_name,commandname,256);
  insert_point = config->perm_list;
  if (insert_point) {
    while (insert_point->next_perm) insert_point = insert_point->next_perm;
    insert_point->next_perm = perm;
  } else {
    config->perm_list = perm;
  }

  return perm;
}

/***/

wzd_command_perm_t * perm_find(const char *commandname, wzd_config_t * config)
{
  wzd_command_perm_t * perm;
  
  if ( ! config->perm_list ) return NULL;

  perm = config->perm_list;
  do {
    if (strcasecmp(perm->command_name,commandname)==0) {
      return perm;
    }
    perm = perm->next_perm;
  } while (perm);

  return NULL;
}

/***/

wzd_command_perm_entry_t * perm_find_create_entry(const char * target, wzd_command_perm_t * command_perm)
{
  wzd_command_perm_entry_t * entry, *insert_point;

  entry = command_perm->entry_list;
  if (!entry) {
    entry = command_perm->entry_list = perm_create_empty_entry();
    strncpy(entry->target,target,256);
    return entry;
  }

  /** \todo TODO compare entries with target (regexp powaa) and if same, simplify or warn */

  do {
    if (strcasecmp(entry->target,target)==0) {
      return entry;
    }
    entry = entry->next_entry;
  } while (entry);

  /* not found, insert a new entry (tail insertion, order is important) */
  entry = perm_create_empty_entry();
  strncpy(entry->target,target,256);
  entry->next_entry = NULL;
  insert_point = command_perm->entry_list;
  if (insert_point == NULL) {
    command_perm->entry_list = entry;
  } else {
    while (insert_point->next_entry != NULL)
      insert_point = insert_point->next_entry;

    insert_point->next_entry = entry;
  }

  return entry;
}

/***/

wzd_command_perm_entry_t * perm_find_entry(const char * target, wzd_cp_t cp, wzd_command_perm_t * command_perm)
{
  wzd_command_perm_entry_t * entry;
  int negate;
  const char * entry_target;

  entry = command_perm->entry_list;
  if (!entry) return NULL;

  /** \todo TODO compare entries with target (regexp powaa) and if same, ok */

  do {
    entry_target = entry->target;
    negate=0;
    if (entry_target[0] == '!') {
      entry_target++;
      negate = 1;
    }
    if (entry_target[0] == '*') return (negate) ? (void*)-1 : entry;
    if (strcasecmp(entry_target,target)==0 && entry->cp == cp) {
      return (negate) ? (void*)-1 : entry;
    }
    entry = entry->next_entry;
  } while (entry);

  return NULL;
}

/***/

int perm_add_perm(const char *permname, const char *permline, wzd_config_t * config)
{
  char * dyn_buffer;
  char * token, * ptr;
  wzd_command_perm_t * command_perm;
  wzd_command_perm_entry_t * perm_entry;
  wzd_cp_t cp;
  char c;
  int negate;
  size_t length;

  if (!permname || !permline) return 1;
  if (!strlen(permname) || !strlen(permline)) return 1;

  if ( (length = strlen(permline)) >= BUFFER_LEN) return 1;
  dyn_buffer = malloc(length+1);
  strncpy(dyn_buffer,permline,length+1);

  /* find the perm */
  command_perm = perm_find_create(permname,config);

  /* for each element of the permline, add it to the entries */
  ptr = dyn_buffer;
  token = strtok_r(dyn_buffer," \t\r\n",&ptr);

  while (token) {
    negate=0;
    /* FIXME split token to find entry type : user, group, flag */
    WZD_ASSERT ( !(token < dyn_buffer) )
    WZD_ASSERT (!(token > (dyn_buffer+length)) )
    c = *token++;
    if (c == '!') {
      negate = 1;
      c = *token++;
    }
    switch (c) {
    case '=':
      cp = CPERM_USER;
      break;
    case '-':
      cp = CPERM_GROUP;
      break;
    case '+':
      cp = CPERM_FLAG;
      break;
    case '*':
      cp = CPERM_USER;
      token--;
      break;
    default:
      /* incorrect format */
#ifdef DEBUG
fprintf(stderr,"Incorrect permission format: %s: %s\n",permname,token);
#endif
      continue;
    }
    if (negate)
      *(--token)='!';
    if (token < dyn_buffer) fprintf(stderr,"token < dyn_buffer !! %s:%d\n",__FILE__,__LINE__);
    /* add entry */
    perm_entry = perm_find_create_entry(token,command_perm);
    perm_entry->cp = cp;

    token = strtok_r(NULL," \t\r\n",&ptr);
  }
  free(dyn_buffer);

  return 0;
}

/***/

/** \return 0 if ok, 1 if denied, -1 otherwise */
int perm_check(const char *permname, const wzd_context_t * context, wzd_config_t * config)
{
  wzd_command_perm_t * command_perm;
  wzd_command_perm_entry_t * entry;
  const wzd_user_t * user;
  wzd_group_t * group;
  unsigned int i;
  int negate;
  const char * entry_target;

  user = GetUserByID(context->userid);

  if (!permname || !context) return -1;
  if (!config->perm_list) return -1;
  if (!strlen(permname)) return -1;

  command_perm = perm_find(permname,config);
  if (!command_perm) return -1;

  entry = command_perm->entry_list;
  if (!entry) return 1;

  /** \todo TODO compare entries with target (regexp powaa) and if same, ok */

  do {
    entry_target = entry->target;
    negate=0;
    if (entry_target[0] == '!') {
      entry_target++;
      negate = 1;
    }
    if (entry_target[0] == '*') return (negate) ? 1 : 0;
    switch (entry->cp) {
      case CPERM_USER:
        if (strcasecmp(entry_target,user->username)==0) return (negate) ? 1 : 0;
        break;
      case CPERM_GROUP:
        for (i=0; i<user->group_num; i++) {
          group = GetGroupByID(user->groups[i]);
          if (strcasecmp(entry_target,group->groupname)==0) return (negate) ? 1 : 0;
        }
        break;
      case CPERM_FLAG:
        if (user->flags && strchr(user->flags,*entry_target)) return (negate) ? 1 : 0;
        break;
    }
    entry = entry->next_entry;
  } while (entry);

  return 1;
}

