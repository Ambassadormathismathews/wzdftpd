#include <stdlib.h>
#include <string.h>

#include <wzd_structs.h>
#include <wzd_vfs.h>

#define C1 0x12345678
#define C2 0x9abcdef0

void test_stripdir(char * test_input, const char * correct_out)
{
  unsigned long c1 = C1;
  char buffer[WZD_MAX_PATH];
  char * ptr;
  unsigned long c2 = C2;

  ptr = stripdir(test_input, buffer, sizeof(buffer));
  if (strcmp(buffer, correct_out)) {
    fprintf(stderr, "stripdir failed: in %s should have been %s (is %s)\n", test_input, correct_out, buffer);
    exit(1);
  }

  if (c1 != C1) {
    fprintf(stderr, "c1 nuked !\n");
    exit(-1);
  }
  if (c2 != C2) {
    fprintf(stderr, "c2 nuked !\n");
    exit(-1);
  }
}

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  int i;
  unsigned long c2 = C2;
  char * tab_stripdir[] = {
    "/", "/",
    "/./", "/",
    "///", "/",
    "/d/toto/../dir", "/d/dir",
    "/d/toto/..", "/d",
    "/d/toto/../", "/d",
    "/d/toto/../../e", "/e",
    "/dir.", "/dir.",
    "/dir..", "/dir..",
    NULL, NULL
  };

  for (i=0; tab_stripdir[i]!=NULL; i+=2) {
    test_stripdir(tab_stripdir[i],tab_stripdir[i+1]);
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
