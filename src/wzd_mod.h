#ifndef __WZD_MOD_H__
#define __WZD_MOD_H__

/* free hook list */
int hook_free(wzd_hook_t **hook_list);

/* register a new hook */
int hook_add(wzd_hook_t ** hook_list, unsigned long mask, void_fct hook);

#define FORALL_HOOKS(test_mask)	{ \
  wzd_hook_t * hook; \
  for (hook = mainConfig->hook; hook; hook = hook->next_hook) \
  { \
    if (hook->mask & (test_mask)) { \

#define	END_FORALL_HOOKS	}\
  }\
}

#endif /* __WZD_MOD_H__ */
