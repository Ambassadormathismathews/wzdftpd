#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libwzd.h>

int main(int argc, char **argv)
{
  int ret;
  const char *msg = "site uptime";
  char buffer[1024];

  wzd_parse_args(argc,argv);
  ret = wzd_init();
  if (ret < 0) {
    printf("Could not connect to server !\n");
    exit (1);
  }

  ret = wzd_send_message(msg,strlen(msg),buffer,1024);
  if (ret == 0) {
    ret = strlen(buffer);
    if (ret <= 6 || strncmp(buffer,"200 ",4)) {
      wzd_fini();
      return 1;
    }

    while (ret > 0 && (buffer[ret-1]=='\r' || buffer[ret-1]=='\n'))
      buffer[ret-- -1] = '\0';
    printf("%s\n",buffer+4);
  }

  wzd_fini();

  return 0;
}
