#ifndef __WZD_STRUCTS__
#define __WZD_STRUCTS__

/**************** COMMANDS PERMISSIONS ********************/
typedef enum {
  CP_USER,
  CP_GROUP,
  CP_FLAG
} wzd_cp_t;

typedef struct _wzd_command_perm_entry_t {
  wzd_cp_t cp;
  char target[256];
  struct _wzd_command_perm_entry_t * next_entry;
} wzd_command_perm_entry_t;



typedef struct _wzd_command_perm_t {
  char  command_name[256];
  wzd_command_perm_entry_t * entry_list;
  struct _wzd_command_perm_t * next_perm;
} wzd_command_perm_t;


/*********************** SITE *****************************/
typedef struct {
  char	file_help[256];
  char	file_rules[256];
} wzd_site_config_t;

#endif /* __WZD_STRUCTS__ */
