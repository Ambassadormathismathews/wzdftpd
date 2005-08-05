#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_ip.h>

#define C1 0x12345678
#define C2 0x9abcdef0

struct test_ip_t {
  const char * pattern;
  signed int   result;
};

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  unsigned long c2 = C2;
  const char * ip1 = "192.168.0.10";
  struct test_ip_t test_ip1[] = {
    { "192.168.0.10",  1 },
    { "192.168.0.1",   0 },
    { "192.168.0.100", 0 },
    { "192.168.1.10",  0 },
    { "192.168.0.*",   1 },
    { "192.168.0.1?",  1 },
    { "192.168.0.?",   0 },
    { "192.168.*.10",  1 },
    { "192.168.?.10",  1 },
    { "192.*.?.10",    1 },
    { "192.1?.0.10",   0 },
    { "192.168.*",     1 },
    { "192.168.*10",   1 },
    { "192.168.*1",    0 },
    { "*",             1 },
    { NULL, 2 } };
#ifdef IPV6_SUPPORT
  const char * ip2 = "3dde:70ef:3223:0:0:0:0:ffff";
  struct test_ip_t test_ip2[] = {
    { "3dde:70ef:3223:0:0:0:0:ffff",  1 },
    { "3dde:70ef::0:0:0:0:ffff",      0 },
    { "3dde:70ef:*:0:0:0:0:ffff",     1 },
    { "3dde:70e?:3223:0:0:0:0:ffff",  1 },
    { "192.168.*",                    0 },
    { "*",                            1 },
    { NULL, 2 } };
#endif
  unsigned int i;



  /* ip_compare */
  i=0;
  while (test_ip1[i].pattern != NULL) {
    if (ip_compare(ip1,test_ip1[i].pattern) != test_ip1[i].result) {
      fprintf(stderr, "ip_compare(%s,%s) failed !\n",ip1,test_ip1[i].pattern);
      return -2;
    }
    i++;
  }
#ifdef IPV6_SUPPORT
  i=0;
  while (test_ip2[i].pattern != NULL) {
    if (ip_compare(ip2,test_ip2[i].pattern) != test_ip2[i].result) {
      fprintf(stderr, "ip_compare(%s,%s) failed !\n",ip2,test_ip2[i].pattern);
      return -2;
    }
    i++;
  }
#endif

  /* ip_add */
  /* ip_inlist */
  /* ip_free */

  /* user_ip_add */
  /* user_ip_inlist */

  /* group_ip_add */
  /* group_ip_inlist */





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
