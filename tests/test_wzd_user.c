#include <string.h> /* memset */
#include <stdlib.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_user.h>

#include "test_common.h"

#include <libwzd-core/wzd_debug.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main()
{
  unsigned long c1 = C1;
  wzd_user_t * user;
  wzd_user_t * user1;
  wzd_user_t * user2;
  uid_t * uid_list;
  int ret;
  unsigned long c2 = C2;

  fake_mainConfig();


  user1 = user_allocate();
  user1->uid = 3;

  ret = user_register(user1,1 /* backend id */);

  user2 = user_allocate();
  user2->uid = -1;

  ret = user_register(user2,1);

  user2->uid = 1255;
  /* try to unregister and free a user not registered */
  user = user_unregister(user2->uid);
  user_free(user);

  ret = user_register(user2,1 /* backend id */);
  user_ip_add(user2, "127.0.0.1", 1);

  uid_list = user_get_list(1 /* backend id */);

  wzd_free(uid_list);

  /* test on flags */
  user_flags_clear(user1);
  user_flags_add(user1, "abc");
  if (strcmp(user1->flags,"abc")!=0) exit(1);
  user_flags_add(user1, "aef");
  if (strcmp(user1->flags,"abcef")!=0) exit(1);
  user_flags_delete(user1, "ade");
  if (strcmp(user1->flags,"bcf")!=0) exit(1);

  /* end of tests */
  user = user_unregister(user1->uid);
  user_free(user);

  user = user_unregister(user2->uid);
  user_free(user);

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
