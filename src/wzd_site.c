#include "wzd.h"

extern int serverstop;
extern time_t server_start;

#define	BUFFER_LEN	4096

/********************* do_site_help ************************/

void do_site_help(const char *site_command, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];

  snprintf(buffer,BUFFER_LEN,"Syntax error in command %s",site_command);
  send_message_with_args(501,context,buffer);
}


/********************* do_site_chown ***********************/
/* chown: user file1 [file2 ...]
 */

void do_site_chown(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * username, *filename;
  int ret;
  wzd_user_t user;

  ptr = command_line;
  username = strtok_r(command_line," \t\r\n",&ptr);
  if (!username) {
    do_site_help("chown",context);
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
    buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
    _setPerm(buffer,0,username,0,0,context);
  }

  snprintf(buffer,BUFFER_LEN,"CHOWN: '%s'",command_line);
  ret = send_message_with_args(200,context,buffer);
}

/********************* do_site_chmod ***********************/
/* chmod: user mode file1 [file2 ...]
 */

void do_site_chmod(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * mode, *username, *filename;
  int ret;
  wzd_user_t user;

  ptr = command_line;
  username = strtok_r(NULL," \t\r\n",&ptr);
  if (!username) {
    do_site_help("chmod",context);
    return;
  }
  /* check that username exists */
  if ( backend_find_user(username,&user) ) {
    ret = send_message_with_args(501,context,"User does not exists");
    return;
  }
  mode = strtok_r(command_line," \t\r\n",&ptr);
  if (!mode) {
    do_site_help("chmod",context);
    return;
  }
  /* TODO check that mode is ok */

  while ( (filename = strtok_r(NULL," \t\r\n",&ptr)) )
  {
    /* convert file to absolute path, remember _setPerm wants ABSOLUTE paths ! */
    if (checkpath(filename,buffer,context)) continue; /* path is NOT ok ! */
    buffer[strlen(buffer)-1] = '\0'; /* remove '/', appended by checkpath */
    _setPerm(buffer,username,0,0,mode,context);
  }

  snprintf(buffer,BUFFER_LEN,"CHMOD: '%s'",command_line);
  ret = send_message_with_args(200,context,buffer);
}

/********************* do_site_who *************************/
void do_site_who(wzd_context_t * context)
{
  int ret;
  char buffer[BUFFER_LEN];

/*  ret = send_message_with_args(200,context,"[ WHO ]\r\n   prout\r\n[ WHO ]");*/
/*  send_message_raw("200 [ WHO ]\r\n",context);*/
  send_message_raw("200- [ WHO ]\r\n",context);
  send_message_raw("                        ________ ____________________\r\n",context);
  send_message_raw("                       /___    //    /  |  \\_____    \\\r\n",context);
  send_message_raw("                       \\ /    //    /   _   \\    \\   \\\\\r\n",context);
  send_message_raw("                        /    //    /    |    \\    \\   .\\\r\n",context);
  send_message_raw("                       /____/\\___ //    |     \\ ________\\\r\n",context);
  send_message_raw("                       \\    \\ \\ \\/______|______\\/       /\r\n",context);
  send_message_raw("                        \\____\\/\\_\\      |      /_______/\r\n",context);
  send_message_raw("                                  \\_____|_____/\r\n",context);
  snprintf(buffer,4096," you are: %s\n",context->userinfo.username);
  send_message_raw(buffer,context);
  send_message_raw("200 [ WHO ]\r\n",context);
}

/********************* do_site_print_file ******************/
void do_site_print_file(const char * filename, wzd_context_t * context)
{
  struct stat s;
  char buffer[1024];
  int ret;
  FILE * fp;

  if (strlen(filename)==0) {
    ret = send_message_with_args(501,context,"Tell the admin to configure his site correctly");
    return;
  }

  if (stat(filename,&s)==-1) {
    ret = send_message_with_args(501,context,"Problem reading the rules file - inexistant ? - check your config");
    return;
  }

  fp = fopen(filename,"r");
  if (!fp) {
    ret = send_message_with_args(501,context,"Problem reading the file - check your config");
    return;
  }

  if ( (fgets(buffer,1022,fp)) == NULL) {
    ret = send_message_with_args(501,context,"File is empty");
    return;
  }

  /* send header */
  send_message_raw("200-\r\n",context);

  do {
    ret = cookies_replace(buffer,1024,context); /* TODO test ret */
    send_message_raw(buffer,context);
  } while ( (fgets(buffer,1022,fp)) != NULL);

  fclose(fp);
  send_message_raw("200 \r\n",context);
}

/********************* do_site *****************************/

int do_site(char *command_line, wzd_context_t * context)
{
  char buffer[4096];
  char *token, *ptr;
  int ret;
  
  token = ptr = command_line;
  token = strtok_r(command_line," \t\r\n",&ptr);

  if (!token || strlen(token)==0) {
    ret = send_message_with_args(501,context,"SITE command failed");
    return 1;
  }

  /* check general site permission */
  {
    char permname_buf[256];

#ifdef DEBUG
    if (strlen(token)>255) {
      fprintf(stderr,"*** WARNING *** permissions name too long > 255 - truncated : '%s'\n",token);
    }
#endif
    strcpy(permname_buf,"site_");
    strncpy(permname_buf+5,token,250); /* 250 = 256 - strlen("site_") - 1 */

    if (perm_check(permname_buf,context,&mainConfig)) {
      ret = send_message_with_args(501,context,"Permission Denied");
      return 1;
    }
  }

/******************* WHO ************************/
  if (strcasecmp(token,"WHO")==0) {
    do_site_who(context);
    return 0;
  } else
/******************* CHMOD **********************/
  if (strcasecmp(token,"CHMOD")==0) {
    do_site_chmod(command_line+6,context); /* 6 = strlen("chmod")+1 */
    return 0;
  } else
/******************* CHOWN **********************/
  if (strcasecmp(token,"CHOWN")==0) {
    do_site_chown(command_line+6,context); /* 6 = strlen("chown")+1 */
    return 0;
  } else
/******************* RULES **********************/
  if (strcasecmp(token,"RULES")==0) {
    do_site_print_file(mainConfig.site_config.file_rules,context);
    return 0;
  } else
/******************* HELP ***********************/
  if (strcasecmp(token,"HELP")==0) {
    do_site_print_file(mainConfig.site_config.file_help,context);
    return 0;
  } else
/******************* UPTIME *********************/
  if (strcasecmp(token,"UPTIME")==0) {
    time_t t;
    time(&t);
    t = t - server_start;
    snprintf(buffer,4096,"Uptime: %s",time_to_str(t));
    ret = send_message_with_args(200,context,buffer);
    return 0;
/******************* SHUTDOWN *******************/
  } else
  if (strcasecmp(token,"SHUTDOWN")==0) {
    serverstop = 1;
    ret = send_message_with_args(250,context,"SITE:","server will shutdown NOW");
    return 0;
  }

  ret = send_message_with_args(250,context,"SITE","command unknown, ok");

  return 0;
}
