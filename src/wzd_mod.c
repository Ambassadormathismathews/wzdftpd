#include "wzd.h"

/* free hook list */
int hook_free(wzd_hook_t **hook_list)
{
  wzd_hook_t * current_hook, * next_hook;

  current_hook = *hook_list;

  while (current_hook) {
    next_hook = current_hook->next_hook;

#ifdef DEBUG
    current_hook->mask = 0;
    current_hook->hook = NULL;
    current_hook->next_hook = NULL;
#endif /* DEBUG */
    free(current_hook);

    current_hook = next_hook;
  }

  *hook_list = NULL;
  return 0;
}

/* register a new hook */
int hook_add(wzd_hook_t ** hook_list, unsigned long mask, void_fct hook)
{
  wzd_hook_t * current_hook, * new_hook;

  new_hook = malloc(sizeof(wzd_hook_t));
  if (!new_hook) return 1;

  new_hook->mask = mask;
  new_hook->hook = hook;
  new_hook->next_hook = NULL;

  current_hook = *hook_list;

  if (!current_hook) {
    *hook_list = new_hook;
    return 0;
  }

  while (current_hook->next_hook) {
    current_hook = current_hook->next_hook;
  }

  current_hook->next_hook = new_hook;

  return 0;
}

