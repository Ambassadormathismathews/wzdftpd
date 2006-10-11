#include <stdio.h>
#include <stdlib.h>

#include <libwzd/libwzd_codes.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  int code;
  int ret;
  int d1, d2, d3;
  unsigned long c2 = C2;

  code = 421;
  if ( ! REPLY_IS_VALID(code) ) {
    fprintf(stderr,"REPLY_IS_VALID not working\n");
    return 1;
  }

  if ( REPLY_GET_DIGIT1(code) != 4 ) {
    fprintf(stderr,"REPLY_GET_DIGIT1 not working\n");
    return 2;
  }

  if ( REPLY_GET_DIGIT2(code) != 2 ) {
    fprintf(stderr,"REPLY_GET_DIGIT2 not working\n");
    return 3;
  }

  if ( REPLY_GET_DIGIT3(code) != 1 ) {
    fprintf(stderr,"REPLY_GET_DIGIT3 not working\n");
    return 4;
  }

  code = 1400;
  if ( REPLY_IS_VALID(code) ) {
    fprintf(stderr,"REPLY_IS_VALID not working\n");
    return 5;
  }

  code = -10;
  if ( REPLY_IS_VALID(code) ) {
    fprintf(stderr,"REPLY_IS_VALID not working\n");
    return 6;
  }

  code = 226;
  if ( ! REPLY_IS_OK(code) ) {
    fprintf(stderr,"REPLY_IS_OK not working\n");
    return 7;
  }
  if ( REPLY_IS_ERROR(code) ) {
    fprintf(stderr,"REPLY_IS_ERROR not working\n");
    return 8;
  }

  code = 421;
  if ( REPLY_IS_OK(code) ) {
    fprintf(stderr,"REPLY_IS_OK not working\n");
    return 9;
  }
  if ( ! REPLY_IS_ERROR(code) ) {
    fprintf(stderr,"REPLY_IS_ERROR not working\n");
    return 10;
  }



  code = 421;
  ret = wzd_split_reply_code(code,NULL,NULL,NULL);
  if ( ret != 0 ) {
    fprintf(stderr,"wzd_split_reply_code not working (NULL parameters)\n");
    return 11;
  }

  ret = wzd_split_reply_code(code,&d1,&d2,&d3);
  if ( ret != 0 || d1 != 4 || d2 != 2 || d3 != 1) {
    fprintf(stderr,"wzd_split_reply_code not working\n");
    return 12;
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
