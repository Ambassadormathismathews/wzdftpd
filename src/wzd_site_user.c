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
  for (i=0; i<HARD_IP_PER_USER; i++)
    user.ip_allowed[i][0]='\0';
  user.bytes_ul_total=0;
  user.bytes_dl_total=0;

  /* add it to backend */
  /* FIXME backend name hardcoded */
  backend_mod_user("plaintext",username,&user);

  ret = send_message_with_args(200,context,"User added");
  return 0;
}
