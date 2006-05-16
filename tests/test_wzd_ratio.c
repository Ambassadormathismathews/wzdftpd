#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_ratio.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_context_t context;
  wzd_user_t user;
  wzd_user_t * puser;
  int ret;
  unsigned long c2 = C2;
  char path[16384];

  fake_mainConfig();

  memset(&context, 0, sizeof(wzd_context_t));

  strncpy(path, "Makefile", sizeof(path));

  /* prepare structures for tests */
  user.uid = 11;
  user.ratio = 0;
  strncpy(user.username, "test_user", sizeof(user.username));

  context.userid = user.uid;

  /* ratio_check_download */
  ret = ratio_check_download( path, &context );
  if (ret != 0) {
    fprintf(stderr, "infinite credits not working\n");
    return 1;
  }

  puser = GetUserByID(context.userid);
  if (!puser) {
    fprintf(stderr, "could not get user by id\n");
    return 2;
  }
  puser->ratio = 3;
  puser->credits = 0;

  /* ratio_check_download */
  ret = ratio_check_download( path, &context );
  if (ret != 1) {
    fprintf(stderr, "credits with ratio not working\n");
    return 3;
  }

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
