#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libwzd.h>

int main(int argc, const char **argv)
{
  const char *msg = "SITE WHO\r\n";
  int ret;
  wzd_reply_t * reply;
  int i;

  wzd_parse_args(argc,argv);
  ret = wzd_init();

  ret = wzd_connect();
  if (ret < 0) {
    fprintf(stderr,"Could not connect to server\n");
    wzd_fini();
    exit(-1);
  }

  if (ret >= 0) {

    reply = wzd_send_message(msg,strlen(msg));

    if (reply) {

      if (reply->data) {
        for (i=0; reply->data[i]!=NULL; i++) {
          printf("%s\n",reply->data[i]);
        }
      }
      wzd_free_reply(reply);
    }

  }

  wzd_fini();

  return 0;
}
