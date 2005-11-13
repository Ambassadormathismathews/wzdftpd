#include <stdlib.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  unsigned long c2 = C2;

  printf("Size of structs:\n");
  printf("  wzd_config_t:       %d\n", sizeof(wzd_config_t));
  printf("  wzd_context_t:      %d\n", sizeof(wzd_context_t));
  printf("  wzd_backend_t:      %d\n", sizeof(wzd_backend_t));
  printf("  wzd_user_t:         %d\n", sizeof(wzd_user_t));
  printf("  wzd_group_t:        %d\n", sizeof(wzd_group_t));


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
