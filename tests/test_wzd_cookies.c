#include <stdlib.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_misc.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

#define BUFLEN 1024

struct comp_t {
  char * in;
  char * ref;
};


int test_cookies(const char * input, const char * reference, char * buffer, char * outbuf)
{
  strncpy(buffer,input,BUFLEN);
  cookie_parse_buffer(buffer,f_user,NULL,NULL,outbuf,BUFLEN);
  if (strcmp(outbuf,reference)) {
    fprintf(stderr,"test_cookies: got unexpected output [%s]\n",buffer);
    return 1;
  }

  return 0;
}

/* run this program inside a memory checker (like valgrind) */

int main()
{
  unsigned long c1 = C1;
  char outbuf[BUFLEN];
  char buffer[BUFLEN];
  unsigned long c2 = C2;
  struct comp_t comparisons[] = {
    { "HELO %username\n", "HELO test_user\r\n" },
/*    { "HELO %!black%username%!0\n", "HELO [30mtest_user[0m\r\n" },*/
    { NULL, NULL }
  };
  unsigned int i;

  fake_mainConfig();

  /* all NULL test */
  cookie_parse_buffer(NULL,NULL,NULL,NULL,NULL,0);

  /* do nothing test */
  memset(buffer,'x',BUFLEN);
  buffer[BUFLEN-1] = '\0';
  cookie_parse_buffer(buffer,NULL,NULL,NULL,outbuf,BUFLEN);

  /* no user */
  strncpy(buffer,"HELO %username\n",BUFLEN);
  cookie_parse_buffer(buffer,NULL,NULL,NULL,outbuf,BUFLEN);

  fake_user();
  fake_context();

  /* general tests */
  i = 0;
  while (comparisons[i].in) {
    if (test_cookies(comparisons[i].in,comparisons[i].ref,buffer,outbuf)) {
      fprintf(stderr, "cookies: %s failed !\n",comparisons[i].in);
      return -2;
    }
    i++;
  }

  /* spacefree with no user */
  strncpy(buffer,"Space: %spacefree\n",BUFLEN);
  cookie_parse_buffer(buffer,NULL,NULL,NULL,outbuf,BUFLEN);

  /* spacefree with user */
  strncpy(buffer,"Space: %spacefree\n",BUFLEN);
  cookie_parse_buffer(buffer,f_user,NULL,f_context,outbuf,BUFLEN);
printf("spacefree with user: [%s]\n",outbuf);

  /* msg with no user */
  strncpy(buffer,"msg: %msg\n",BUFLEN);
  cookie_parse_buffer(buffer,NULL,NULL,NULL,outbuf,BUFLEN);

  /* msg with user */
  strncpy(buffer,"msg: %msg\n",BUFLEN);
  cookie_parse_buffer(buffer,f_user,NULL,f_context,outbuf,BUFLEN);
printf("msg with user: [%s]\n",outbuf);

  /* usertotaldl2 with no user */
  strncpy(buffer,"usertotal_dl2: %usertotal_dl2\n",BUFLEN);
  cookie_parse_buffer(buffer,NULL,NULL,NULL,outbuf,BUFLEN);

  /* usertotaldl2 with user */
  strncpy(buffer,"%usertotal_dl2",BUFLEN);
  cookie_parse_buffer(buffer,f_user,NULL,f_context,outbuf,BUFLEN);
printf("usertotal_dl2 with user: [%s]\n",outbuf);



  fake_exit();

  if (c1 != C1) {
    fprintf(stderr, "c1 nuked !\n");
    return -1;
  }
  if (c2 != C2) {
    fprintf(stderr, "c2 nuked !\n");
    return -1;
  }

  return 0;
}
