#ifndef __WZD_STRUCTS__
#define __WZD_STRUCTS__

/*********************** RIGHTS ***************************/

#define RIGHT_NONE      0x00000000

#define RIGHT_LIST      0x00000001
#define RIGHT_RETR      0x00000002
#define RIGHT_STOR      0x00000004


/* other rights - should not be used directly ! */
#define RIGHT_CWD       0x00010000
#define RIGHT_RNFR      0x00020000

typedef unsigned long wzd_perm_t;

/******************** BANDWIDTH LIMIT *********************/

typedef struct limiter
{
  int maxspeed;
  struct timeval current_time;
  int bytes_transfered;
} wzd_bw_limiter;

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
  char	file_user[256];
  char	file_who[256];
} wzd_site_config_t;


/********************* IP CHECKING ************************/
typedef struct _wzd_ip_t {
  char  * regexp;
  struct _wzd_ip_t * next_ip;
} wzd_ip_t;

/************************ VFS *****************************/
typedef struct _wzd_vfs_t {
  char	* virtual_dir;
  char	* physical_dir;

  struct _wzd_vfs_t	* next_vfs;
} wzd_vfs_t;

/*********************** DATA *****************************/
typedef enum {
  DATA_PORT,
  DATA_PASV
} data_mode_t;

/********************** USER, GROUP ***********************/

typedef struct {
  char                  username[256];
  char			userpass[256];
  char                  rootpath[1024];
  char                  tagline[256];
  unsigned int          uid;
  unsigned int          group_num;
  unsigned int          groups[256];
  time_t	        max_idle_time;
  wzd_perm_t            userperms;
  char                  flags[MAX_FLAGS_NUM];
  unsigned long         max_ul_speed;
  unsigned long         max_dl_speed;   /* bytes / sec */
  char			ip_allowed[HARD_IP_PER_USER][MAX_IP_LENGTH];
  unsigned long		bytes_ul_total;
  unsigned long		bytes_dl_total;
} wzd_user_t;

typedef struct {
  char                  groupname[128];
  wzd_perm_t            groupperms;
  time_t		max_idle_time;
  unsigned long         max_ul_speed;
  unsigned long         max_dl_speed;
  char			ip_allowed[HARD_IP_PER_USER][MAX_IP_LENGTH];
} wzd_group_t;

/************************ FLAGS ***************************/

#define	FLAG_IDLE	'I'
#define	FLAG_SEE_IP	's'
#define	FLAG_SEE_HOME	't'
#define	FLAG_HIDDEN	'H'

/************************ MODULES *************************/

typedef int (*void_fct)(void);

typedef struct _wzd_hook_t {
  unsigned long mask;

  void_fct	hook;

  struct _wzd_hook_t	*next_hook;
} wzd_hook_t;

/* defined in binary, combine with OR (|) */

#define	EVENT_LOGIN		0x00000001
#define	EVENT_LOGOUT		0x00000002

#define	EVENT_PREUPLOAD		0x00000010
#define	EVENT_POSTUPLOAD	0x00000020
#define	EVENT_POSTDOWNLOAD	0x00000080

#define	EVENT_MKDIR		0x00000100

/************************** SFV ***************************/

/* values randomly chosen :) */ 
#define	SFV_UNKNOWN	0x0324
#define	SFV_OK		0x7040
#define	SFV_MISSING	0x0220
#define	SFV_BAD		0x1111

typedef struct {
  char *        filename;
  unsigned long crc;
  unsigned int	state;
} wzd_sfv_entry;

typedef struct {
  char **       comments;
  wzd_sfv_entry **sfv_list;
} wzd_sfv_file;

#endif /* __WZD_STRUCTS__ */
