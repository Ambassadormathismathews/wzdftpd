#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_section.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main()
{
  unsigned long c1 = C1;
  wzd_section_t * section_list = NULL;
  wzd_section_t * section;
  char * name;
  unsigned long c2 = C2;
  const char * name1 = "section1";
  const char * mask1 = "/path1/*";
  const char * filter1 = "^([]\\[A-Za-z0-9_.'() \\t+-])*$";
  const char * name2 = "section2";
  const char * mask2 = "/path2/*";
  const char * filter2 = "^([]\\[A-Za-z0-9_.'() \\t+-])*$";
  const char * testpath1 = "/none";
  const char * testpath2 = "/path1/section1";
  const char * testpath3 = "/path2/section2";
  const char * testfilter1 = "path_ok_234.5(2)";
  const char * testfilter2 = "path_not_ok/_234.5(2)";

  /* add examples sections */
  if ( section_add(&section_list,name1,mask1,filter1) ) {
    fprintf(stderr, "add section failed\n");
    return 1;
  }
  if ( section_add(&section_list,name2,mask2,filter2) ) {
    fprintf(stderr, "add section failed\n");
    return 2;
  }

  /* section_find */
  if ( (section = section_find(section_list,testpath1)) ) {
    fprintf(stderr, "section_find (none) failed\n");
    return 3;
  }
  if ( !(section = section_find(section_list,testpath2)) ) {
    fprintf(stderr, "section_find (path1) failed\n");
    return 4;
  }

  /* section_check */
  if ( section_check(section,testpath3) ) {
    fprintf(stderr, "section_check (none) failed\n");
    return 5;
  }
  if ( !section_check(section,testpath2) ) {
    fprintf(stderr, "section_check (testpath2) failed\n");
    return 6;
  }

  /* section_check_filter */
  if ( !section_check_filter(section,testfilter1) ) {
    fprintf(stderr, "section_check_filter (testfilter1) failed\n");
    return 7;
  }
  if ( section_check_filter(section,testfilter2) ) {
    fprintf(stderr, "section_check_filter (testfilter2) failed\n");
    return 8;
  }

  /* section_getname */
  name = section_getname(section);
  if ( !name || strcmp(name1,name) ) {
    fprintf(stderr, "section_getname failed\n");
    return 9;
  }

  section_free(&section_list);

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
