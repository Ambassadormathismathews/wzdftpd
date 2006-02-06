#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */

#include <libwzd-base/list.h>

#define C1 0x12345678
#define C2 0x9abcdef0

typedef struct {
  int i;
  char * s;
} test_struct_t;

void my_free(void * data)
{
  test_struct_t * t;

  t = (test_struct_t *)data;

  free(t->s);
  free(t);
}

int my_test(const void *val1, const void *val2)
{
  const test_struct_t *t1, *t2;

  if (val1 == NULL || val2 == NULL)
    return (val1 == val2);

  t1 = val1;
  t2 = val2;

  return strcmp(t1->s,t2->s);
}

int populate_list(List * list)
{
  ListElmt * elmnt;
  test_struct_t * t;
  int ret;

  /* head insertion */
  t = malloc(sizeof(test_struct_t));
  t->i = 1;
  t->s = strdup("test1");
  ret = list_ins_next(list, NULL, t);

  t = malloc(sizeof(test_struct_t));
  t->i = 2;
  t->s = strdup("test2");
  ret = list_ins_next(list, NULL, t);

  /* tail insertion */
  elmnt = list_tail(list);
  t = malloc(sizeof(test_struct_t));
  t->i = 3;
  t->s = strdup("test3");
  ret = list_ins_next(list, elmnt, t);

  return 0;
}

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  List list;
  ListElmt * elmnt, * el;
  test_struct_t * t;
  int ret;
  int i;
  unsigned long c2 = C2;
  test_struct_t ref[] = {
    { 1, "test1" },
    { 2, "test2" },
    { 3, "test3" } };

  list_init(&list,my_free);

  populate_list(&list);

  /* iterating through list */
  for (elmnt = list_head(&list); elmnt != NULL; elmnt = list_next(elmnt))
  {
    t = list_data(elmnt);
    i = t->i;
    if (ref[i-1].i != t->i ||
        strcmp(ref[i-1].s,t->s) != 0)
    {
      fprintf(stderr, "error for test entry { %d, %s }\n",t->i,t->s);
      return 1;
    }
  }

  /** list_rem_next **/
  /* head suppression */
  ret = list_rem_next(&list, NULL, (void**)&t);
  my_free(t);
  /* should not work, there is nothing after tail */
  ret = list_rem_next(&list, list_tail(&list), (void**)&t);

  ret = list_rem_next(&list, list_head(&list), (void**)&t);
  my_free(t);

  ret = list_rem_next(&list, NULL, (void**)&t);
  my_free(t);

  /* should not work, list is empty */
  ret = list_rem_next(&list, NULL, (void**)&t);

  populate_list(&list);

  /** list_remove **/

  /* should not work, no element to remove */
  ret = list_remove(&list, NULL, (void**)&t);

  /* tail suppression */
  ret = list_remove(&list, list_tail(&list), (void**)&t);
  my_free(t);

  /* head suppression */
  ret = list_remove(&list, list_head(&list), (void**)&t);
  my_free(t);

  ret = list_remove(&list, list_head(&list), (void**)&t);
  my_free(t);

  /* should not work, list is empty */
  ret = list_remove(&list, list_head(&list), (void**)&t);

  populate_list(&list);

  /* list_lookup_node (without test function) */
  el = list_lookup_node(&list,NULL);
  for (elmnt = list_head(&list); elmnt != NULL; elmnt = list_next(elmnt))
  {
    t = list_data(elmnt);
    el = list_lookup_node(&list,t);
    if (el == NULL) {
      fprintf(stderr, "(list_lookup_node) error for test entry { %d, %s }\n",t->i,t->s);
      return 2;
    }
  }

  /* list_lookup_node (with a test function) */
  list.test = my_test;
  el = list_lookup_node(&list,NULL);
  for (i=0; i<(int)( (sizeof(ref)/sizeof(ref[0])) ); i++)
  {
    el = list_lookup_node(&list,&ref[i]);
    if (el == NULL) {
      fprintf(stderr, "(list_lookup_node) error for test entry { %d, %s }\n",t->i,t->s);
      return 3;
    }
  }

  /* list_ins_sorted */
  list_destroy(&list);

  list_init(&list,my_free);
  list.test = my_test;

  t = malloc(sizeof(test_struct_t));
  t->i = 2;
  t->s = strdup("test2");
  ret = list_ins_sorted(&list, t);

  t = malloc(sizeof(test_struct_t));
  t->i = 1;
  t->s = strdup("test1");
  ret = list_ins_sorted(&list, t);

  t = malloc(sizeof(test_struct_t));
  t->i = 3;
  t->s = strdup("test3");
  ret = list_ins_sorted(&list, t);

  /* check that the list is effectively sorted */
  i = 1;
  for (elmnt = list_head(&list); elmnt != NULL; elmnt = list_next(elmnt))
  {
    t = list_data(elmnt);
    if (t->i != i ||
        strcmp(ref[i-1].s,t->s) != 0)
    {
      fprintf(stderr, "error for test entry { %d, %s }\n",t->i,t->s);
      return 1;
    }
    i++;
  }



  list_destroy(&list);

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
