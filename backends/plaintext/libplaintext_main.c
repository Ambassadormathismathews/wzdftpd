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

typedef struct {
  char			username[256];
  char			userpass[256];
  char			homedir[1024];
  char			tagline[256];
  unsigned int		uid;
  wzd_perm_t		userperms;
  unsigned int		group_num;
  unsigned int		groups[256];
  unsigned long		max_ul_speed;
  unsigned long		max_dl_speed;
} user_t;

user_t * user_pool;
int user_count;

typedef struct {
  char			groupname[256];
  wzd_perm_t		groupperms;
  unsigned long		max_ul_speed;
  unsigned long		max_dl_speed;
} group_t;

group_t * group_pool;
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
    line[strlen(line)-1] = '\0'; /* clear trailing \n */

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
          user_pool = realloc(user_pool,(user_count+256)*sizeof(user_t));
        }
      strncpy(user_pool[user_count-1].username,value,255);
      user_pool[user_count-1].userperms = 0;
      user_pool[user_count-1].uid = -1;
      memset(user_pool[user_count-1].groups,0,256*sizeof(unsigned int));
      user_pool[user_count-1].group_num = 0;
      memset(user_pool[user_count-1].tagline,0,256);
      user_pool[user_count-1].max_ul_speed = 0;
      user_pool[user_count-1].max_dl_speed = 0;
    }
    else if (strcmp("home",varname)==0) {
      if (!user_count) break;
      /* remove trailing / */
      if (value[strlen(value)-1] == '/')
	value[strlen(value)-1] = '\0';
      strncpy(user_pool[user_count-1].homedir,value,1024);
    }
    else if (strcmp("pass",varname)==0) {
      if (!user_count) break;
      strncpy(user_pool[user_count-1].userpass,value,255);
    }
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
      num = strtol(value, &ptr, 0);
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
  }
  return 0;
}


int read_section_groups(FILE * file_user, char * line)
{
  char c;
  char *token;
  unsigned int directive;

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
    line[strlen(line)-1] = '\0'; /* clear trailing \n */
fprintf(stderr,"i read '%s'\n",line);
    /* read config directive name */
    token = strtok(line," \t");
    if (!token) continue;
    directive = find_directive(token);
fprintf(stderr,"directive: %d\n",directive);
    switch (directive) {
    case D_PRIVGROUP:
      token = strtok(NULL,"\n");
fprintf(stderr,"Defining new private group %s\n",token);
      if ((++group_count % 256)==0) {
	group_pool = realloc(group_pool,group_count+256);
      }
      strncpy(group_pool[group_count-1].groupname,token,256);
      group_pool[group_count-1].groupperms = 0;
      group_pool[group_count-1].max_ul_speed = 0;
      group_pool[group_count-1].max_dl_speed = 0;
      break;
    case D_NONE:
fprintf(stderr,"Unkown directive %s\n",token);
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
    line[strlen(line)-1] = '\0'; /* clear trailing \n */
fprintf(stderr,"i read '%s'\n",line);
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
  user_pool = malloc(256*sizeof(user_t));
  group_count=0;
  group_pool = malloc(256*sizeof(group_t));

  /* XXX We always add a user nobody and a group nogroup */
  strcpy(user_pool[0].username,"nobody");
  strcpy(user_pool[0].userpass,"------");
  strcpy(user_pool[0].homedir,"/no/home");
  strcpy(user_pool[0].tagline,"nobody");
  user_pool[0].uid = 65535;
  user_pool[0].userperms = RIGHT_CWD; /* should be enough ! */
  user_pool[0].group_num = 1;
  user_pool[0].groups[0] = 0; /* 0 == nogroup ! */
  user_pool[0].max_ul_speed = 1; /* at this rate, even if you can download it will be ... slow ! */
  user_pool[0].max_dl_speed = 1;
  user_count++;

  strcpy(group_pool[0].groupname,"nogroup");
  group_pool[0].groupperms = 0; /* should be enough ! */
  group_pool[0].max_ul_speed = 0;
  group_pool[0].max_dl_speed = 0;
  group_count++;

  while (1) {
    ptr = fgets(line,MAX_LINE-1,file_user);
    if (!ptr) { fclose(file_user); free(line); return 0; }
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
  fprintf(stderr,"Plaintext validate login: %s\n",login);
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
fprintf(stderr,"found user at index: %d\n",count);

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
fprintf(stderr,"%s %s == %s : %d\n",login,cipher,user_pool[count].userpass,found);
    if (found) {
fprintf(stderr,"Passwords do no match for user %s (received: %s)\n",user_pool[count].username,pass);
      return 1; /* passwords do not match */
    }
  }

  strncpy(user->username,user_pool[count].username,255);
  strncpy(user->rootpath,user_pool[count].homedir,1023);
  user->uid = user_pool[count].uid;
  memcpy(&user->perms,&user_pool[count].userperms,sizeof(wzd_perm_t));
  user->max_ul_speed = user_pool[count].max_ul_speed;
  user->max_dl_speed = user_pool[count].max_dl_speed;

  return 0;
}

int FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  int count;
  int found;

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
fprintf(stderr,"found user at index: %d\n",count);

  strncpy(user->username,user_pool[count].username,255);
  strncpy(user->rootpath,user_pool[count].homedir,1023);
  user->uid = user_pool[count].uid;
  memcpy(&user->perms,&user_pool[count].userperms,sizeof(wzd_perm_t));
  user->max_ul_speed = user_pool[count].max_ul_speed;
  user->max_dl_speed = user_pool[count].max_dl_speed;

  return 0;
}
