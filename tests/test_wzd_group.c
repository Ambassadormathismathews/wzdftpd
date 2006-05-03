#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_group.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_group_t * group;
  wzd_group_t * group1;
  wzd_group_t * group2;
  int ret;
  unsigned long c2 = C2;

  fake_mainConfig();


  group1 = group_allocate();
  group1->gid = 3;

  ret = group_register(group1,1 /* backend id */);

  group2 = group_allocate();
  group2->gid = -1;

  ret = group_register(group2,1);

  group2->gid = 1255;
  /* try to unregister and free a group not registered */
  group = group_unregister(group2->gid);
  group_free(group);

  ret = group_register(group2,1 /* backend id */);

  group = group_unregister(group1->gid);
  group_free(group);

  group = group_unregister(group2->gid);
  group_free(group);

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
