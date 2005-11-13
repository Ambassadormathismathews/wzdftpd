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

int callback1(const char * args)
{
  printf("callback1 [args: %s]\n",args);
  return 0;
}

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_event_manager_t * mgr;
  wzd_string_t * command_name;
  wzd_string_t * fixed_args, * event_args;
  unsigned long c2 = C2;

  fake_context();

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
  event_send(mgr, EVENT_ID_TEST1,  event_args, f_context);
  event_send(mgr, EVENT_ID_TEST2,  event_args, f_context);
  str_store(event_args,"; touch /tmp/toto");
  event_send(mgr, EVENT_ID_TEST2,  event_args, f_context);
  event_send(mgr, EVENT_ID_TEST12, NULL, f_context);
  event_send(mgr, EVENT_ID_TEST3,  NULL, f_context);
  event_send(mgr, EVENT_ID_TEST4,  NULL, f_context);
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
