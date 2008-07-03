#include <stdlib.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>

#include <libwzd-core/wzd_events.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

#define EVENT_ID_TEST1  (1<<1)
#define EVENT_ID_TEST2  (1<<2)
#define EVENT_ID_TEST12 ((1<<1) | (1<<2))
#define EVENT_ID_TEST3  (1<<3)
#define EVENT_ID_TEST4  (1<<4)

event_reply_t callback1(const char * args)
{
  printf("callback1 [args: %s]\n",args);
  return EVENT_OK;
}

int main()
{
  unsigned long c1 = C1;
  wzd_event_manager_t * mgr;
  wzd_string_t * command_name;
  wzd_string_t * fixed_args, * event_args;
  event_reply_t event_reply;
  unsigned long c2 = C2;

  fake_context();
  fake_proto();

  /******* event_exec **********/
  /* test 1: printing a file */
  event_reply = event_exec("!/etc/hosts", f_context);

  /* test 2: running a simple command */
  event_reply = event_exec("/bin/ls", f_context);

  /* test 3: running a simple command with arguments */
  event_reply = event_exec("/bin/ls -a /tmp", f_context);

  /* test 4: testing a protocol */
  event_reply = event_exec("perl:/tmp/test.pl", f_context);

  /* test 5: testing a protocol with arguments*/
  event_reply = event_exec("perl:/tmp/test.pl user group", f_context);

  /* test 6: testing a protocol, special name */
  event_reply = event_exec("perl:'/tmp 2/test.pl'", f_context);

  /* test 7: testing a protocol, special name with args */
  event_reply = event_exec("perl:'/tmp 2/test.pl' user group", f_context);

  mgr = malloc(sizeof(wzd_event_manager_t));
  event_mgr_init(mgr);

  fixed_args = STR("fixed args");
  event_connect_function(mgr, EVENT_ID_TEST1, callback1, fixed_args);
  str_deallocate(fixed_args);

  command_name = STR("/bin/ls");
  event_connect_external(mgr, EVENT_ID_TEST2, command_name, NULL);
  str_deallocate(command_name);

  command_name = STR("!/etc/hosts");
  event_connect_external(mgr, EVENT_ID_TEST3, command_name, NULL);
  str_deallocate(command_name);

  event_args = STR("toto");
  event_send(mgr, EVENT_ID_TEST1,  200, event_args, f_context);
  event_send(mgr, EVENT_ID_TEST2,  200, event_args, f_context);
  str_store(event_args,"; touch /tmp/toto");
  event_send(mgr, EVENT_ID_TEST2,  200, event_args, f_context);
  event_send(mgr, EVENT_ID_TEST12, 200, NULL, f_context);
  event_send(mgr, EVENT_ID_TEST3,  200, NULL, f_context);
  event_send(mgr, EVENT_ID_TEST4,  200, NULL, f_context);
  str_deallocate(event_args);

  event_mgr_free(mgr);
  free(mgr);

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
