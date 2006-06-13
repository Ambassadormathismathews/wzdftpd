#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_crc32.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  unsigned long crc = 0x0;
  char input1[1024];
  const char * file1 = "file_crc.txt";
  const unsigned long crc_ref = 0xEB2FAFAF; /* cksfv file_crc.txt */
  char * srcdir = NULL;
  unsigned long c2 = C2;

  srcdir = getenv("srcdir");
  if (srcdir == NULL) {
    fprintf(stderr, "Environment variable $srcdir not found, aborting\n");
    return 1;
  }

  snprintf(input1,sizeof(input1)-1,"%s/%s",srcdir,file1);

  if ( calc_crc32(input1,&crc,0,(unsigned long)-1) ) {
    fprintf(stderr, "calc_crc32 failed\n");
    return 1;
  }

  if ( crc != crc_ref ) {
    fprintf(stderr, "calc_crc32 returned crap\n");
    return 1;
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
