#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>
#include <libwzd-core/wzd_action.h>

#include <libwzd-core/wzd_debug.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_context_t context;
  unsigned long c2 = C2;
  char buffer[16384];

  memset(&buffer, '&', sizeof(buffer));

  memset(&context, 0, sizeof(wzd_context_t));

  set_action(&context, buffer);

  if ( str_length(context.current_action.command) != strlen(buffer) ) {
    fprintf(stderr, "Incorrect length\n");
    return 2;
  }

  str_deallocate(context.current_action.command);

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
