#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <libwzd.h>

char *msg = NULL;

void siteconfig_parse_args(int argc, char **argv)
{
  int optindex;

  /* We have to be carefull here not to use the same values
   * as libwzd (see libwzd/libwzd.c /wzd_parse_args
   */
  for (optindex=1; optindex<argc; optindex++)
  {
    if (strcmp(argv[optindex],"-m")==0)
    {
      optindex++;
      if (optindex < argc)
      {
        if (strlen(argv[optindex])>0)
          msg = strdup(argv[optindex]);
      }
    }
  }
}


int main(int argc, char **argv)
{
  int ret;
  wzd_reply_t * reply;
  int i;

  siteconfig_parse_args(argc,argv);

  /* if no message was given with -m, then read it from stdin */
  if (!msg) {
    msg = malloc(1025);
    if(!fgets(msg,1024,stdin) || strlen(msg)<=1) {
      exit(1);
    }
    msg[strlen(msg)-1] = '\0';
  }

  if (!msg || strncasecmp(msg,"site vars",strlen("site vars"))) {
    fprintf(stderr,"Incorrect command.\n");
    fprintf(stderr,"supported commands are:\n");
    fprintf(stderr," site vars\n");
    fprintf(stderr," site vars_user\n");
    fprintf(stderr," site vars_group\n");
    exit (1);
  }

  wzd_parse_args(argc,argv);
  ret = wzd_init();

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
