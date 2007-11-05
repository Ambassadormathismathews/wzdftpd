#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */

#include <fcntl.h> /* O_RDONLY */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_cache.h>

#include <libwzd-core/wzd_debug.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  char buffer1[1024];
  char input1[1024];
  const char * file1 = "file_crc.txt";
  wzd_cache_t * cache;
  FILE * file;
  char buffer2[1024];
  char * srcdir = NULL;
  unsigned long c2 = C2;

  wzd_debug_init();

  if (argc > 1) {
    srcdir = argv[1];
  } else {
    srcdir = getenv("srcdir");
    if (srcdir == NULL) {
      fprintf(stderr, "Environment variable $srcdir not found, aborting\n");
      return 1;
    }
  }

  /* TEST 1 : cache MISS */
  /* Compare output from wzd_cache and standard FILE functions */

  snprintf(input1,sizeof(input1)-1,"%s/%s",srcdir,file1);
  file = fopen(input1,"r+");
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


  /* TEST 2 : cache HIT */
  /* redo it (though, this time it is in cache) */
  fseek(file, 0, SEEK_SET);
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


  /* TEST 3 : cache REFRESH */
  /* modify file, then redo it */
  fseek(file, 0, SEEK_SET);
  if (fgets(buffer1,sizeof(buffer1)-1,file)) {
    fseek(file, 0, SEEK_SET);
    fwrite(buffer1, strlen(buffer1), 1, file);
  }
  fseek(file, 0, SEEK_SET);
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

  wzd_cache_purge();

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
