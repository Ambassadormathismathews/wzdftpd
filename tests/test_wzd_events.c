#include <stdlib.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>

#include <libwzd-core/wzd_events.h>

#define C1 0x12345678
#define C2 0x9abcdef0

#define EVENT_ID_TEST1  (1<<1)
#define EVENT_ID_TEST2  (1<<2)
#define EVENT_ID_TEST12 ((1<<1) | (1<<2))
#define EVENT_ID_TEST3  (1<<3)

int callback1(void)
{
  printf("callback1\n");
  return 0;
}

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_event_manager_t * mgr;
  wzd_string_t * command_name;
  unsigned long c2 = C2;

  mgr = malloc(sizeof(wzd_event_manager_t));
  event_mgr_init(mgr);

  command_name = STR("/bin/ls");

  event_connect_function(mgr, EVENT_ID_TEST1, callback1, NULL);
  event_connect_external(mgr, EVENT_ID_TEST2, command_name, NULL);

  str_deallocate(command_name);

  event_send(mgr, EVENT_ID_TEST1,  NULL, NULL);
  event_send(mgr, EVENT_ID_TEST2,  NULL, NULL);
  event_send(mgr, EVENT_ID_TEST12, NULL, NULL);
  event_send(mgr, EVENT_ID_TEST3,  NULL, NULL);

  event_mgr_free(mgr);
  free(mgr);

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
