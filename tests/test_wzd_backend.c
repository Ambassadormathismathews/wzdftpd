#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>
#include <libwzd-core/wzd_backend.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_backend_def_t * def;
  unsigned long c2 = C2;
  int ret;

  fake_mainConfig();


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
