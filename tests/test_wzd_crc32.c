#include <stdio.h>
#include <string.h> /* memset */

#include <wzd_structs.h>
#include <wzd_crc32.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  unsigned long crc = 0x0;
  const char * input1 = "file_crc.txt";
  const unsigned long crc_ref = 0xEB2FAFAF; /* cksfv file_crc.txt */
  unsigned long c2 = C2;

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
