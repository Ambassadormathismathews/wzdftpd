#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libwzd.h>

int main(int argc, const char **argv)
{
  int ret;
  const char *msg = "site uptime";
  wzd_reply_t * reply;
  char * buffer;

  wzd_parse_args(argc,argv);
  ret = wzd_init();

  ret = wzd_connect();
  if (ret < 0) {
    fprintf(stderr,"Could not connect to server\n");
    wzd_fini();
    exit(-1);
  }

  reply = wzd_send_message(msg,strlen(msg));
  if (reply) {
    if (reply->code != 200 || reply->data==NULL) {
      wzd_free_reply(reply);
      wzd_fini();
      return 1;
    }
    buffer = reply->data[0];
    ret = strlen(buffer);

    if (ret <= 6 || strncmp(buffer,"200 ",4)) {
      wzd_free_reply(reply);
      wzd_fini();
      return 1;
    }

    while (ret > 0 && (buffer[ret-1]=='\r' || buffer[ret-1]=='\n'))
      buffer[ret-- -1] = '\0';
    printf("%s\n",buffer+4);

    wzd_free_reply(reply);
  }

  wzd_fini();

  return 0;
}
