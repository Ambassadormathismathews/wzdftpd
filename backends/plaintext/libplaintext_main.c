#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include <wzd_backend.h>

#define PASSWD_FILE_NAME	"passwd"
#define	GROUP_FILE_NAME		"group"

#define	MAX_LINE		1024

typedef struct {
  char			username[256];
  char			homedir[2048];
  wzd_userlevel_t	level;
} user_t;

user_t * user_pool;

int FCN_INIT(void)
{
  FILE * passwdfile, * groupfile;
  char * line;
  char * field_user, * field_home, * field_level, *field;
  char * ptr;
  int c;
  int user_count=0;

  passwdfile = fopen(PASSWD_FILE_NAME,"r");
  groupfile = fopen(GROUP_FILE_NAME,"r");

  if (! (passwdfile && groupfile) ) {
    fprintf(stderr,"Could not open files %s and %s\n",PASSWD_FILE_NAME,GROUP_FILE_NAME);
    return 1;
  }

  line = malloc(MAX_LINE);

  /* initial size of user_pool */
  user_pool = malloc(256*sizeof(user_t));

  while (fgets(line,MAX_LINE-1,passwdfile))
  {
    c = 1;
    ptr = line;
    field_user = strtok_r(line,":",&ptr);
    if (!field_user) break;
    fprintf(stdout," field_user %d: %s\n",c,field_user);
    field_home = strtok_r(NULL,":",&ptr);
    if (!field_home) break;
    fprintf(stdout," field_home %d: %s\n",c,field_home);
    field_level = strtok_r(NULL,":",&ptr);
    if (!field_level) break;
    fprintf(stdout," field_level %d: %s\n",c,field_level);
    c++;
    strncpy(user_pool[user_count].username,field_user,255);
    strncpy(user_pool[user_count].homedir,field_home,2047);
    /* FIXME - write other tests .... */
    if (strcmp(field_level,"NORMAL")==0) user_pool[user_count].level = USR_NORMAL;
    if ( (++user_count % 256)==0 ) {
      /* TODO realloc of size user_count + 256 */
    }
  }

  fclose(passwdfile);
  fclose(groupfile);
  free(line);

  return 0;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  fprintf(stderr,"Plaintext validate login: %s\n",login);
  return 0;
}

int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  strncpy(user->username,login,256);
#ifndef __CYGWIN__
  strncpy(user->rootpath,"/home/pollux",1024);
#else
  strncpy(user->rootpath,"e:/pollux",1024);
#endif
  user->userlevel = USR_NORMAL;
  return 0;
}

