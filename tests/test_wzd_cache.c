#include <stdio.h>
#include <string.h> /* memset */

#include <fcntl.h> /* O_RDONLY */

#include <wzd_structs.h>
#include <wzd_cache.h>

#include <wzd_debug.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  char buffer1[1024];
  const char * input1 = "file_crc.txt";
  wzd_cache_t * cache;
  FILE * file;
  char buffer2[1024];
  unsigned long c2 = C2;

  wzd_debug_init();

  /* Compare output from wzd_cache and standard FILE functions */

  file = fopen(input1,"r");
  if (!file) {
    fprintf(stderr, "Input file not found\n");
    return 1;
  }

  cache = wzd_cache_open(input1,O_RDONLY,0600);
  if (!cache) {
    fprintf(stderr, "wzd_cache_open broken\n");
    return 2;
  }

  while(fgets(buffer1,sizeof(buffer1)-1,file)) {
    if (!wzd_cache_gets(cache,buffer2,sizeof(buffer2)-1)) {
      fprintf(stderr, "wzd_cache_gets broken\n");
      return 4;
    }

    if (!memcmp(buffer1,buffer2,sizeof(buffer1))) {
      fprintf(stderr, "fgets and wzd_cache_gets returned different output\n");
      return 5;
    }
  }

  wzd_cache_close(cache);
  fclose(file);

  wzd_debug_fini();

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
