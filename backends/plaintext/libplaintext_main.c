#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <crypt.h>
#include <sys/types.h>
#include <regex.h>

#include <wzd_backend.h>

#define	USERS_FILE		"users"

#define	MAX_LINE		1024

wzd_user_t * user_pool;
int user_count;

wzd_group_t * group_pool;
int group_count;

regex_t reg_line;
regmatch_t regmatch[3];

char varname[2048];
char value[2048];

/* directives */
#define	D_NONE		0
#define D_PRIVGROUP	1

#define	D_NUM		1

const char *tab_directives[] = {
  "privgroup"
};

unsigned int find_directive(const char *name)
{
  int i=0;

  while (i<D_NUM) {
    if (strcasecmp(tab_directives[i],name)==0) return i+1;
    i++;
  }
  return D_NONE;
}

#if 0
/* dst can be composed of wildcards */
int my_str_compare(const char * src, const char *dst)
{
  const char * ptr_src;
  const char * ptr_dst;
  char c;

  ptr_src = src;
  ptr_dst = dst;

  while ((c = *ptr_src)) {
    if (*ptr_dst=='*') { /* wildcard * */
      if (*(ptr_dst+1)=='\0') return 1; /* terminated with a *, ok */
      ptr_dst++;
      c = *ptr_dst;
      while (*ptr_src && c!=*ptr_src)
        ptr_src++;
      if (!*ptr_src) break; /* try next ip */
      continue;
    }
    if (*ptr_dst=='?') { /* wildcard ?, match one char and continue */
      ptr_src++;
      ptr_dst++;
      continue;
    }
    if (*ptr_dst!=c) break; /* try next ip */
    ptr_dst++;
    ptr_src++;
  }

  /* test if checking was complete */
  if (*ptr_dst == '\0') return 1;

  return 0;
}
#endif

/* IP allowing */
int ip_add(wzd_ip_t **list, const char *newip)
{
  wzd_ip_t * new_ip_t, *insert_point;
  
  /* of course this should never happen :) */
  if (list == NULL) return -1;
  
  if (strlen(newip) < 1) return -1;
  if (strlen(newip) > 256) return -1; /* upper limit for an hostname */
  
  new_ip_t = malloc(sizeof(wzd_ip_t));
  new_ip_t->regexp = malloc(strlen(newip)+1);
  strcpy(new_ip_t->regexp,newip);
  new_ip_t->next_ip = NULL;
  
  /* tail insertion, be aware that order is important */
  insert_point = *list;
  if (insert_point == NULL) {
    *list = new_ip_t; 
  } else {
    while (insert_point->next_ip != NULL)
      insert_point = insert_point->next_ip;
      
    insert_point->next_ip = new_ip_t;
  } 
  
  return 0;
} 


int write_user_file(void)
{
  char filename[256];
  FILE *file;
  int i,j;
  wzd_ip_t *ip;
  char buffer[4096];
  const char * const file_header[] = {
    "# general considerations:",
    "#",
    "# comment lines begin by #",
    "# empty lines are removed",
    "#",
    "# directives have format: <tagname>=<value>",
    "# with the regexp: ^([a-zA-Z0-9_]+)[ \\t]*=[ \\t]*(.+)",
    "#",
    "# directives are grouped into sections",
    "# section begins by [SECTIONNAME]",
    NULL /* you MUST keep this array NULL-ended ! */
  };

  strcpy(filename,USERS_FILE);
  strcat(filename,".NEW");

  file = fopen(filename,"w+");

  i=0;
  while (file_header[i]) {
    fprintf(file,"%s\n",file_header[i]);
    i++;
  }
  fprintf(file,"\n");

  fprintf(file,"# groups definitions\n");
  fprintf(file,"[GROUPS]\n");
  for (i=0; i<group_count; i++)
  {
    if (strcmp(group_pool[i].groupname,"nogroup")==0) continue;
    fprintf(file,"privgroup\t%s\n",group_pool[i].groupname);
    if (group_pool[i].max_idle_time)
      fprintf(file,"max_idle_time=%ld\n",group_pool[i].max_idle_time);
    fprintf(file,"\n");
  }

  fprintf(file,"# users definitions\n");
  fprintf(file,"# users MUST begin by line name=<>\n");
  fprintf(file,"[USERS]\n");
  for (i=0; i<user_count; i++)
  {
    if (strcmp(user_pool[i].username,"nobody")==0) continue;
    fprintf(file,"name=%s\n",user_pool[i].username);
    fprintf(file,"pass=%s\n",user_pool[i].userpass);
    fprintf(file,"home=%s\n",user_pool[i].rootpath);
    fprintf(file,"uid=%d\n",user_pool[i].uid);
    /* write ALL groups */
    /* TODO check buffer overflow */
    if (user_pool[i].group_num>0) {
      strcpy(buffer,group_pool[user_pool[i].groups[0]].groupname);
      for (j=1; j<user_pool[i].group_num; j++) {
        strcat(buffer,",");
        strcat(buffer,group_pool[user_pool[i].groups[j]].groupname);
      }
      fprintf(file,"groups=%s\n",buffer);
    }
    fprintf(file,"rights=0x%lx\n",user_pool[i].userperms);
    if (strlen(user_pool[i].tagline)>0)
      fprintf(file,"tagline=%s\n",user_pool[i].tagline);
    for (ip=user_pool[i].ip_allowed; ip!=NULL; ip=ip->next_ip)
    {
      fprintf(file,"ip_allowed=%s\n",ip->regexp);
    }
    if (user_pool[i].max_ul_speed)
      fprintf(file,"max_ul_speed=%ld\n",user_pool[i].max_ul_speed);
    if (user_pool[i].max_dl_speed)
      fprintf(file,"max_dl_speed=%ld\n",user_pool[i].max_dl_speed);
    if (user_pool[i].max_idle_time)
      fprintf(file,"max_idle_time=%ld\n",user_pool[i].max_idle_time);
    if (user_pool[i].flags)
      fprintf(file,"flags=%s\n",user_pool[i].flags);
    fprintf(file,"\n");
  }

  fprintf(file,"# per hosts rights\n");
  fprintf(file,"[HOSTS]\n");
  fprintf(file,"all = *\n");
  fprintf(file,"\n");

  fclose(file);

  return 0;
}

int read_section_users(FILE * file_user, char * line)
{
  char c;
  int err;
  long num;
  char *ptr;
  unsigned long i;

fprintf(stderr,"Entering section USERS\n");
  while ( (c = getc(file_user)) != EOF ) {
    if (c=='\n') continue;
    if (c=='#') { fgets(line+1,MAX_LINE-2,file_user); continue; } /* comment */
    if (c == '[') { /* another section */
      ungetc(c,file_user);
      return 0;
    }
    line[0] = c; /* we avoid a stupid ungetc */
    fgets(line+1,MAX_LINE-2,file_user);
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */

    if (line[0]=='\0') continue; /* empty line */

    err = regexec(&reg_line,line,3,regmatch,0);
    if (err) {
fprintf(stderr,"Line '%s' does not respect config line format - ignoring\n",line);
      continue;
    }
    memcpy(varname,line+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
    varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
    memcpy(value,line+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
    value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

    if (strcmp("name",varname)==0) {
      /* begin a new user */
        if ( (++user_count % 256)==0 ) {
          /* realloc of size user_count + 256 */
          user_pool = realloc(user_pool,(user_count+256)*sizeof(wzd_user_t));
        }
      strncpy(user_pool[user_count-1].username,value,255);
      user_pool[user_count-1].userperms = 0;
      user_pool[user_count-1].uid = -1;
      memset(user_pool[user_count-1].groups,0,256*sizeof(unsigned int));
      user_pool[user_count-1].group_num = 0;
      memset(user_pool[user_count-1].tagline,0,256);
      user_pool[user_count-1].max_ul_speed = 0;
      user_pool[user_count-1].max_dl_speed = 0;
      user_pool[user_count-1].max_idle_time = 0;
      user_pool[user_count-1].ip_allowed = NULL;
      user_pool[user_count-1].flags = NULL;
    }
    else if (strcmp("home",varname)==0) {
      if (!user_count) break;
      /* remove trailing / */
      if (value[strlen(value)-1] == '/')
	value[strlen(value)-1] = '\0';
      strncpy(user_pool[user_count-1].rootpath,value,1024);
    }
    else if (strcmp("pass",varname)==0) {
      if (!user_count) break;
      strncpy(user_pool[user_count-1].userpass,value,255);
    }
    else if (strcmp("flags",varname)==0) {
      if (!user_count) break;
      num = strlen(value);
      if (num < 0 || num > 256) { /* suspicious length ! */
        continue;
      }
      user_pool[user_count-1].flags = malloc(num);
      strcpy(user_pool[user_count-1].flags,value);
    } /* flags */
    else if (strcmp("uid",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid uid %s\n",value);
	continue;
      }
      user_pool[user_count-1].uid = num;
    }
    else if (strcmp("rights",varname)==0) {
      if (!user_count) break;
      num = strtoul(value, &ptr, 0);
      /* FIXME by default all users have CWD right FIXME */
      user_pool[user_count-1].userperms = num | RIGHT_CWD;
    }
    else if (strcmp("groups",varname)==0) {
      /* first group */
      ptr = strtok(value,",");
      if (!ptr) continue;
      i = 0;
      while (i < group_count) {
	if (strcmp(value,group_pool[i].groupname)==0) {
	  user_pool[user_count-1].groups[user_pool[user_count-1].group_num++] = i; /* ouch */
	  break;
	}
	i++;
      }
    } /* "groups" */
    else if (strcmp("tagline",varname)==0) {
      strncpy(user_pool[user_count-1].tagline,value,256);
    } /* tagline */
    else if (strcmp("max_ul_speed",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_ul_speed %s\n",value);
        continue;
      }
      user_pool[user_count-1].max_ul_speed = num;
    } /* max_ul_speed */
    else if (strcmp("max_dl_speed",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_dl_speed %s\n",value);
        continue;
      }
      user_pool[user_count-1].max_dl_speed = num;
    } /* max_ul_speed */
    else if (strcmp("max_idle_time",varname)==0) {
      if (!user_count) break;
      num = strtol(value, &ptr, 0);
      if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_idle_time %s\n",value);
        continue;
      }
      user_pool[user_count-1].max_idle_time = num;
    } /* max_idle_time */
    else if (strcmp("ip_allowed",varname)==0) {
      ip_add(&user_pool[user_count-1].ip_allowed,value);
    } /* ip_allowed */
  }
  return 0;
}


int read_section_groups(FILE * file_user, char * line)
{
  char c;
  char *token, *ptr;
  unsigned int directive;
  int err;
  long num;

fprintf(stderr,"Entering section GROUPS\n");
  while ( (c = getc(file_user)) != EOF ) {
    if (c=='\n') continue;
    if (c=='#') { fgets(line+1,MAX_LINE-2,file_user); continue; } /* comment */
    if (c == '[') { /* another section */
      ungetc(c,file_user);
      return 0;
    }
    line[0] = c; /* we avoid a stupid ungetc */
    fgets(line+1,MAX_LINE-2,file_user);
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */
    /* read config directive name */
    token = strtok(line," \t");
    if (!token) continue;
    directive = find_directive(token);
    switch (directive) {
    case D_PRIVGROUP:
      token = strtok(NULL,"\n");
fprintf(stderr,"Defining new private group %s\n",token);
      if ((++group_count % 256)==0) {
	group_pool = realloc(group_pool,group_count+256);
      }
      strncpy(group_pool[group_count-1].groupname,token,128);
      group_pool[group_count-1].groupperms = 0;
      group_pool[group_count-1].max_ul_speed = 0;
      group_pool[group_count-1].max_dl_speed = 0;
      group_pool[group_count-1].max_idle_time = 0;
      group_pool[group_count-1].ip_allowed = NULL;
      break;
    case D_NONE:
      err = regexec(&reg_line,line,3,regmatch,0);
      if (err) {
fprintf(stderr,"Line '%s' does not respect config line format - ignoring\n",line);
        continue;
      }
      memcpy(varname,line+regmatch[1].rm_so,regmatch[1].rm_eo-regmatch[1].rm_so);
      varname[regmatch[1].rm_eo-regmatch[1].rm_so]='\0';
      memcpy(value,line+regmatch[2].rm_so,regmatch[2].rm_eo-regmatch[2].rm_so);
      value[regmatch[2].rm_eo-regmatch[2].rm_so]='\0';

      if (strcasecmp(varname,"max_idle_time")==0) {
        if (!group_count) break;
        num = strtol(value, &ptr, 0);
        if (ptr == value || *ptr != '\0' || num < 0) { /* invalid number */
fprintf(stderr,"Invalid max_idle_time %s\n",value);
          continue;
        }
        group_pool[group_count-1].max_idle_time = num;
      } /* max_idle_time */
      break;
    default:
fprintf(stderr,"Houston, we have a problem\n");
      break;
    }
  }
  return 0;
}


int read_section_hosts(FILE * file_user, char * line)
{
  char c;

fprintf(stderr,"Entering section HOSTS\n");
  while ( (c = getc(file_user)) != EOF ) {
    if (c=='\n') continue;
    if (c=='#') { fgets(line+1,MAX_LINE-2,file_user); continue; } /* comment */
    if (c == '[') { /* another section */
      ungetc(c,file_user);
      return 0;
    }
    line[0] = c; /* we avoid a stupid ungetc */
    fgets(line+1,MAX_LINE-2,file_user);
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */
/*fprintf(stderr,"i read '%s'\n",line);*/
  }
  return 0;
}


int read_files(void)
{
  FILE *file_user;
  char * line, * token, *ptr;
  int ret;

  file_user = fopen(USERS_FILE,"r");

  line = malloc(MAX_LINE);

  /* prepare regexp */
  reg_line.re_nsub = 2;
  ret = regcomp (&reg_line, "^([a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)", REG_EXTENDED);
  if (ret) return 1; /* regexp could not be compiled */

  /* initial size of user_pool */
  user_count=0;
  user_pool = malloc(256*sizeof(wzd_user_t));
  group_count=0;
  group_pool = malloc(256*sizeof(wzd_group_t));

  /* XXX We always add a user nobody and a group nogroup */
  strcpy(user_pool[0].username,"nobody");
  strcpy(user_pool[0].userpass,"------");
  strcpy(user_pool[0].rootpath,"/no/home");
  strcpy(user_pool[0].tagline,"nobody");
  user_pool[0].uid = 65535;
  user_pool[0].userperms = RIGHT_CWD; /* should be enough ! */
  user_pool[0].group_num = 1;
  user_pool[0].groups[0] = 0; /* 0 == nogroup ! */
  user_pool[0].max_ul_speed = 1; /* at this rate, even if you can download it will be ... slow ! */
  user_pool[0].max_dl_speed = 1;
  user_pool[0].max_idle_time = 0;
  user_pool[0].flags = NULL;
  user_count++;

  strcpy(group_pool[0].groupname,"nogroup");
  group_pool[0].groupperms = 0; /* should be enough ! */
  group_pool[0].max_ul_speed = 0;
  group_pool[0].max_dl_speed = 0;
  group_pool[0].max_idle_time = 0;
  group_pool[0].ip_allowed = NULL;
  group_count++;

  while (1) {
    ptr = fgets(line,MAX_LINE-1,file_user);
    if (!ptr) { fclose(file_user); free(line); return 0; }
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n')
      line[strlen(line)-1] = '\0'; /* clear trailing \n */

    if (line[0] == '\0' || line[0] == '#') { /* ignore empty lines & comments */
      continue;
    }

    if (line[0] == '[') { /* we are beginning a section */
      token = strtok_r(line+1,"]",&ptr);
      if (strcasecmp("USERS",token)==0) ret = read_section_users(file_user,line);
      else if (strcasecmp("GROUPS",token)==0) ret = read_section_groups(file_user,line);
      else if (strcasecmp("HOSTS",token)==0) ret = read_section_hosts(file_user,line);
      else {
fprintf(stderr,"Unkown section %s\n",token);
        return 1;
      }
      continue;
    } /* line begins by [ */
    else { /* directive without section */
fprintf(stderr,"directive without section in line '%s'\n",line);
      return 1;
    }
  }
  while (ptr);

  /* end */
  fclose(file_user);
  free(line);
  return 0;
}


int FCN_INIT(void)
{
  int ret;

  ret = read_files();

  /* TODO check user definitions (no missing fields, etc) */

  return ret;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
/*  fprintf(stderr,"Plaintext validate login: %s\n",login);*/
  int count;
  int found;
/*  int i;*/

  count=0;
  found = 0;
  while (count<user_count) {
    if (strcmp(login,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }

  if (!found) {
fprintf(stderr,"User %s not found\n",login);
    return 1;
  }

  memcpy(user,&user_pool[count],sizeof(wzd_user_t));
  /* XXX we erase password (more security ?!) */
  memset(user->userpass,0,256);
  /* FIXME duplicate ip_allow list ? */
  
  return 0;
}

int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  int count;
  int found;
  char * cipher;

  count=0;
  found = 0;
  while (count<user_count) {
    if (strncmp(login,user_pool[count].username,strlen(user_pool[count].username))==0)
      { found = 1; break; }
    count++;
  }

  if (!found) {
fprintf(stderr,"User %s not found\n",login);
    return 1;
  }
/*fprintf(stderr,"found user at index: %d\n",count);*/

  /* special case: if user_pool[count].userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(user_pool[count].userpass,"%")==0) {
  }
  /* TODO choose encryption func ? */
  else {
    /* FIXME - crypt is NOT reentrant */
    /* XXX - md5 hash in crypt function does NOT work with cygwin */
    cipher = crypt(pass,user_pool[count].userpass);
    found = strcasecmp(cipher,user_pool[count].userpass);
/*fprintf(stderr,"%s %s == %s : %d\n",login,cipher,user_pool[count].userpass,found);*/
    if (found) {
fprintf(stderr,"Passwords do no match for user %s (received: %s)\n",user_pool[count].username,pass);
      return 1; /* passwords do not match */
    }
  }

/*
  strncpy(user->username,user_pool[count].username,255);
  strncpy(user->rootpath,user_pool[count].rootpath,1023);
  user->uid = user_pool[count].uid;
  user->group_num = user_pool[count].group_num;
  for (i=0; i<user->group_num; i++)
  {
    user->groups[i]=user_pool[count].groups[i];
  }
  memcpy(&user->userperms,&user_pool[count].userperms,sizeof(wzd_perm_t));
  user->max_ul_speed = user_pool[count].max_ul_speed;
  user->max_dl_speed = user_pool[count].max_dl_speed;
  user->max_idle_time = user_pool[count].max_idle_time;
  strncpy(user->tagline,user_pool[count].tagline,255);
*/

  memcpy(user,&user_pool[count],sizeof(wzd_user_t));
  /* XXX we erase password (more security ?!) */
  memset(user->userpass,0,256);
  /* FIXME duplicate ip_allow list ? */

  return 0;
}

int FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  int count;
  int found;
/*  int i;*/

  count=0;
  found = 0;
  while (count<user_count) {
    if (strcmp(name,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }

  if (!found) {
fprintf(stderr,"User %s not found\n",name);
    return 1;
  }
/*fprintf(stderr,"found user at index: %d\n",count);*/
/*
  strncpy(user->username,user_pool[count].username,255);
  strncpy(user->rootpath,user_pool[count].rootpath,1023);
  user->uid = user_pool[count].uid;
  user->group_num = user_pool[count].group_num;
  for (i=0; i<user->group_num; i++)
  {
    user->groups[i]=user_pool[count].groups[i];
  }
  memcpy(&user->userperms,&user_pool[count].userperms,sizeof(wzd_perm_t));
  user->max_ul_speed = user_pool[count].max_ul_speed;
  user->max_dl_speed = user_pool[count].max_dl_speed;
  user->max_idle_time = user_pool[count].max_idle_time;
  strncpy(user->tagline,user_pool[count].tagline,255);
*/

  memcpy(user,&user_pool[count],sizeof(wzd_user_t));
  /* XXX we erase password (more security ?!) */
  memset(user->userpass,0,256);

  return 0;
}

int FCN_FIND_GROUP(int num, wzd_group_t * group)
{
  if (num < 0 || num >= group_count) return 1;
/*
  strncpy(group->groupname,group_pool[num].groupname,256);
  group->groupperms = group_pool[num].groupperms;
  group->max_ul_speed = group_pool[num].max_ul_speed;
  group->max_dl_speed = group_pool[num].max_dl_speed;
  group->max_idle_time = group_pool[num].max_idle_time;
*/
  memcpy(group,&group_pool[num],sizeof(wzd_group_t));

  return 0;
} 

int FCN_CHPASS(const char *username, const char *new_pass)
{
  int count;
  int found;
  char * cipher;

  count=0;
  found = 0;
  while (count<user_count) {
    if (strcmp(username,user_pool[count].username)==0)
      { found = 1; break; }
    count++;
  }
  
  if (!found) {
fprintf(stderr,"User %s not found\n",username);
    return 1;
  }

  /* special case: if user_pool[count].userpass == "%" then any pass
   *  is accepted */
  if (strcasecmp(new_pass,"%")==0) {
    strcpy(user_pool[count].userpass,new_pass);
  }
  /* TODO choose encryption func ? */
  else {
    /* FIXME - crypt is NOT reentrant */
    /* XXX - md5 hash in crypt function does NOT work with cygwin */
    cipher = crypt(new_pass,username);
    strcpy(user_pool[count].userpass,cipher);
  }
  return 0;
}

int FCN_MOD_USER(const char *name, wzd_user_t * user)
{
  return 0;
}

int FCN_MOD_GROUP(int num, wzd_group_t * group)
{
  return 0;
}

int  FCN_COMMIT_CHANGES(void)
{
  return write_user_file();
}
