#ifndef __WZD_MOD_H__
#define __WZD_MOD_H__

/* free hook list */
int hook_free(wzd_hook_t **hook_list);

/* register a new hook */
int hook_add(wzd_hook_t ** hook_list, unsigned long mask, void_fct hook);
int hook_add_external(wzd_hook_t ** hook_list, unsigned long mask, const char *command);

#define FORALL_HOOKS(test_mask)	{ \
  wzd_hook_t * hook; \
  for (hook = mainConfig->hook; hook; hook = hook->next_hook) \
  { \
    if (hook->mask & (test_mask)) { \

#define	END_FORALL_HOOKS	}\
  }\
}

/* module hook struct, used in modules */
typedef struct { unsigned long	event_id; void_fct	fct; } module_hook_t;

/* check a module file */
int module_check(const char *filename);

/* add a module to the list */
int module_add(wzd_module_t ** module_list, const char * name);

/* load a module - module really should have been checked before ! */
int module_load(wzd_module_t *module);

/********************************/
/* modules functions prototypes */

#define	WZD_MODULE_INIT		wzd_module_init
#define	STR_MODULE_INIT		"wzd_module_init"
typedef int (*fcn_module_init)(void);

#define	WZD_MODULE_CLOSE	wzd_module_close

#endif /* __WZD_MOD_H__ */
