#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <malloc.h>
#include <arpa/inet.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void
#define	FILE	void

#include "wzd_structs.h"

#include "wzd_perm.h"
#include "wzd_misc.h"


#define BUFFER_LEN	4096

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

wzd_command_perm_t * perm_find_create(const char *commandname, wzd_config_t * config)
{
  wzd_command_perm_t * perm;

  if ( ! config->perm_list ) {
    perm = config->perm_list = perm_create_empty_perm();
    strncpy(perm->command_name,commandname,256);
    return perm;
  }

  perm = config->perm_list;
  do {
    if (strcasecmp(perm->command_name,commandname)==0) {
      return perm;
    }
    perm = perm->next_perm;
  } while (perm);

  /* not found, insert a new perm (head insertion) */
  perm = perm_create_empty_perm();
  strncpy(perm->command_name,commandname,256);
  perm->next_perm = config->perm_list;
  config->perm_list = perm;

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

  /* TODO compare entries with target (regexp powaa) and if same, simplify or warn */

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

  /* TODO compare entries with target (regexp powaa) and if same, ok */

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
  char buffer[BUFFER_LEN];
  char * token, * ptr;
  wzd_command_perm_t * command_perm;
  wzd_command_perm_entry_t * perm_entry;
  wzd_cp_t cp;
  char c;
  int negate;

  if (!permname || !permline) return 1;
  if (!strlen(permname) || !strlen(permline)) return 1;

  strncpy(buffer,permline,BUFFER_LEN);

  /* find the perm */
  command_perm = perm_find_create(permname,config);

  /* for each element of the permline, add it to the entries */
  ptr = &buffer[0];
  token = strtok_r(buffer," \t\r\n",&ptr);

  while (token) {
    negate=0;
    /* FIXME split token to find entry type : user, group, flag */
    c = *token++;
    if (c == '!') {
      negate = 1;
      c = *token++;
    }
    switch (c) {
    case '=':
      cp = CP_USER;
      break;
    case '-':
      cp = CP_GROUP;
      break;
    case '+':
      cp = CP_FLAG;
      break;
    case '*':
      cp = CP_USER;
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
    /* add entry */
    perm_entry = perm_find_create_entry(token,command_perm);
    perm_entry->cp = cp;

    token = strtok_r(NULL," \t\r\n",&ptr);
  }

  return 0;
}

/***/

/* returns 0 if ok, 1 otherwise */
int perm_check(const char *permname, const wzd_context_t * context, wzd_config_t * config)
{
  wzd_command_perm_t * command_perm;
  wzd_command_perm_entry_t * entry;
  wzd_user_t * user;
  wzd_group_t * group;
  int i;
  int negate;
  const char * entry_target;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = GetUserByID(context->userid);

  if (!permname || !context) return 1;
  if (!config->perm_list) return 1;
  if (!strlen(permname)) return 1;

  command_perm = perm_find(permname,config);
  if (!command_perm) return 1;

  entry = command_perm->entry_list;
  if (!entry) return 1;

  /* TODO compare entries with target (regexp powaa) and if same, ok */

  do {
    entry_target = entry->target;
    negate=0;
    if (entry_target[0] == '!') {
      entry_target++;
      negate = 1;
    }
    if (entry_target[0] == '*') return (negate) ? 1 : 0;
    switch (entry->cp) {
      case CP_USER:
	if (strcasecmp(entry_target,user->username)==0) return (negate) ? 1 : 0;
	break;
      case CP_GROUP:
	for (i=0; i<user->group_num; i++) {
	  group = GetGroupByID(user->groups[i]);
	  if (strcasecmp(entry_target,group->groupname)==0) return (negate) ? 1 : 0;
	}
	break;
      case CP_FLAG:
	if (user->flags && strchr(user->flags,*entry_target)) return (negate) ? 1 : 0;
	break;
    }
    entry = entry->next_entry;
  } while (entry);

  return 1;
}

