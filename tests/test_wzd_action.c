#include <string.h> /* memset */

#include <wzd_structs.h>
#include <wzd_action.h>

extern void set_action(wzd_context_t * context, unsigned int token, const char *arg);

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

  set_action(&context, TOK_RETR, buffer);

  if ( context.current_action.token != TOK_RETR ) {
    fprintf(stderr, "Incorrect token\n");
    return 2;
  }
  if ( strlen(context.current_action.arg) != sizeof(context.current_action.arg) ) {
    fprintf(stderr, "Incorrect length\n");
    return 2;
  }

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
