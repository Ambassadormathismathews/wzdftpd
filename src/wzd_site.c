#include "wzd.h"

extern int serverstop;
extern time_t server_start;

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

  if (strcasecmp(token,"HELP")==0) {
    ret = send_message_with_args(250,context,"SITE","command ok");
    return 0;
  } else
  if (strcasecmp(token,"UPTIME")==0) {
    time_t t;
    time(&t);
    t = t - server_start;
    snprintf(buffer,4096,"Uptime: %s",time_to_str(t));
    ret = send_message_with_args(200,context,buffer);
    return 0;
  } else
  if (strcasecmp(token,"SHUTDOWN")==0) {
    serverstop = 1;
    ret = send_message_with_args(250,context,"SITE:","server will shutdown NOW");
    return 0;
  }

  ret = send_message_with_args(250,context,"SITE","command ok");

  return 0;
}
