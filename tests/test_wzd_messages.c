#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>

#include <libwzd-core/wzd_cache.h>
#include <libwzd-core/wzd_messages.h>

#include <stdlib.h>
#include <string.h>


#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  int i;
  const char * msg;
  int must_free;
  char * n;
  char * srcdir = NULL;
  const char * file1 = "file_crc.txt";
  char input1[1024];
  unsigned long c2 = C2;


  init_default_messages();

  for (i=0; i<1024; i++) {
    msg = getMessage(i, &must_free);

    if (must_free) wzd_free(msg);
  }

  if (argc > 1) {
    srcdir = argv[1];
  } else {
    srcdir = getenv("srcdir");
    if (srcdir == NULL) {
      fprintf(stderr, "Environment variable $srcdir not found, aborting\n");
      return 1;
    }
  }

  snprintf(input1,sizeof(input1)-1,"+%s/%s",srcdir,file1);

  n = strdup(input1);
  setMessage(n, 1);

  msg = getMessage(1, &must_free);
  wzd_free(msg);




  free_messages();
  wzd_cache_purge();

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
