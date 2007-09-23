#include <stdlib.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>

#include <libwzd-core/wzd_data.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

#define EVENT_ID_TEST1  (1<<1)
#define EVENT_ID_TEST2  (1<<2)
#define EVENT_ID_TEST12 ((1<<1) | (1<<2))
#define EVENT_ID_TEST3  (1<<3)
#define EVENT_ID_TEST4  (1<<4)

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  int ret;
  unsigned long c2 = C2;
  unsigned char localhost[4] = { 127, 0, 0, 1 };

  fake_context();
  fake_proto();

  /* if running as a non-privileged user, this should fail */
  mainConfig->pasv_low_range = 1022;
  mainConfig->pasv_high_range = 1023;
  ret = get_pasv_port(WZD_INET4, f_context);
  fprintf(stderr, "bound port: %d (awaited: %s)\n", ret, "-1 if user is non-privileged");
  pasv_close(f_context);

  /* this one should be ok after a few tries */
  mainConfig->pasv_low_range = 1015;
  mainConfig->pasv_high_range = 1025;
  ret = get_pasv_port(WZD_INET4, f_context);
  fprintf(stderr, "bound port: %d (awaited: %s)\n", ret, "any port with range");
  pasv_close(f_context);

  /* same with IPv6 */
  mainConfig->pasv_low_range = 1015;
  mainConfig->pasv_high_range = 1025;
  ret = get_pasv_port(WZD_INET6, f_context);
  fprintf(stderr, "bound port: %d (awaited: %s)\n", ret, "any port with range");
  pasv_close(f_context);

  /* bind to a specific address */
  mainConfig->pasv_low_range = 1033;
  mainConfig->pasv_high_range = 4096;
  memcpy(mainConfig->pasv_ip,localhost,4);
  ret = get_pasv_port(WZD_INET4, f_context);
  fprintf(stderr, "bound port: %d (awaited: %s)\n", ret, "any port with range");
  pasv_close(f_context);

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
