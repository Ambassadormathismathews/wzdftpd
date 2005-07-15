#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

#if 0
struct wzd_string_t {
  char * buffer;
  size_t length;
  size_t allocated;
};
#endif


int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_string_t * str, * str2;
  wzd_string_t * token;
  unsigned long c2 = C2;
  const char in1[] = "  variable =\tvalue:val2  \r\n";
  const char in2[] = "télàçö";
  const char ref1[] = "text 234\0";
  const char ref2[] = "text 234 blah\0";
  const char ref3[] = "foo text 234 blah\0";
  const char ref4[] = "wzdftpd\0";
  const char ref5[] = "variable\0";
  const char ref6[] = "=\0";
  const char ref7[] = "value\0";
  const char ref8[] = "val2\0";
  const char ref9[] = {0x74, 0xc3, 0xa9, 0x6c, 0xc3, 0xa0, 0xc3, 0xa7, 0xc3, 0xb6, 0x0};
  const char ref10[] = "télàçö";

  str = str_allocate();

  str_sprintf(str,"%s %d","text",234);
  if ( strcmp(ref1,str_tochar(str)) ) {
    fprintf(stderr, "sprintf not working\n");
    return 1;
  }
  if ( !str_checklength(str,7,8) ) {
    fprintf(stderr, "str_checklength not working\n");
    return 2;
  }

  str2 = str_dup(str);
  if ( strcmp(str_tochar(str),str_tochar(str2)) ) {
    fprintf(stderr, "str_tochar not working\n");
    return 3;
  }
  str_deallocate(str2);

  str2 = str_allocate();
  str_copy(str2,str);
  if ( strcmp(ref1,str_tochar(str2)) ) {
    fprintf(stderr, "str_copy not working\n");
    return 4;
  }

  str_append(str2," blah");
  if ( strcmp(ref2,str_tochar(str2)) ) {
    fprintf(stderr, "str_append not working\n");
    return 5;
  }

  str_prepend(str2,"foo ");
  if ( strcmp(ref3,str_tochar(str2)) ) {
    fprintf(stderr, "str_prepend not working\n");
    return 6;
  }

  str_append(str2," \r\n");
  str_prepend(str2,"\t ");
  str_trim(str2);
  if ( strcmp(ref3,str_tochar(str2)) ) {
    fprintf(stderr, "str_trim not working\n");
    return 7;
  }

  str_sprintf(str2,"wZdFtPd");
  str_tolower(str2);
  if ( strcmp(ref4,str_tochar(str2)) ) {
    fprintf(stderr, "str_tolower not working\n");
    return 8;
  }

  str_deallocate(str2);
  str2 = STR(in1);
  token = str_read_token(str2);
  if ( strcmp(ref5,str_tochar(token)) ) {
    fprintf(stderr, "str_read_token not working\n");
    return 9;
  }
  str_deallocate(token);
  token = str_read_token(str2);
  if ( strcmp(ref6,str_tochar(token)) ) {
    fprintf(stderr, "str_read_token not working\n");
    return 10;
  }
  str_deallocate(token);
  token = str_tok(str2,":");
  if ( strcmp(ref7,str_tochar(token)) ) {
    fprintf(stderr, "str_tok not working\n");
    return 11;
  }
  str_deallocate(token);
  token = str_read_token(str2);
  if ( strcmp(ref8,str_tochar(token)) ) {
    fprintf(stderr, "str_read_token not working\n");
    return 12;
  }
  str_deallocate(token);

  fake_utf8();

  str_deallocate(str2);
  str2 = STR(in2);
  if (str_local_to_utf8(str2,"latin1")) {
    fprintf(stderr, "str_local_to_utf8 not working\n");
    return 13;
  }
  if ( strcmp(ref9,str_tochar(str2)) ) {
    fprintf(stderr, "str_local_to_utf8 returned crap\n");
    return 14;
  }
  if (str_utf8_to_local(str2,"latin1")) {
    fprintf(stderr, "str_utf8_to_local not working\n");
    return 15;
  }
  if ( strcmp(ref10,str_tochar(str2)) ) {
    fprintf(stderr, "str_utf8_to_local returned crap\n");
    return 16;
  }


  str_deallocate(str);
  str_deallocate(str2);

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
