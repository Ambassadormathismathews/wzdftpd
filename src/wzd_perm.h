#ifndef __WZD_PERM__
#define __WZD_PERM__

int perm_is_valid_perm(const char *permname);

wzd_command_perm_t * perm_find(const char *commandname, wzd_config_t * config);
wzd_command_perm_t * perm_find_create(const char *permname, wzd_config_t * config);
wzd_command_perm_entry_t * perm_find_entry(const char * target, wzd_cp_t cp, wzd_command_perm_t * command_perm);
wzd_command_perm_entry_t * perm_find_create_entry(const char * target, wzd_command_perm_t * command_perm);

int perm_add_perm(const char *permname, const char *permline, wzd_config_t * config);

void perm_free_recursive(wzd_command_perm_t * perm);

/* returns 0 if ok, 1 otherwise */
int perm_check(const char *permname, const wzd_context_t * context, wzd_config_t * config);

#endif /* __WZD_PERM__ */
