#ifndef __WZD_MISC__
#define __WZD_MISC__

unsigned long compute_hashval (const void *key, size_t keylen);

char * time_to_str(time_t time);

void chop(char *s);

/* returns system ip on specifed interface (e.g eth0) */
int get_system_ip(const char * itface, struct in_addr * ina);

/* returns info on device containing dir/file */
int get_device_info(const char *file, long * f_type, long * f_bsize, long * f_blocks, long *f_free);

/* returns 1 if file is perm file */
int is_perm_file(const char *filename);

/* get file last change time */
time_t get_file_ctime(const char *file);
time_t lget_file_ctime(int fd);

/* renames file/dir, if on different fs then moves recursively */
int safe_rename(const char *src, const char *dst);

/* formats the message if multiline, e.g 220-hello\r\n220 End */
void v_format_message(int code, unsigned int length, char *buffer, va_list argptr);
void format_message(int code, unsigned int length, char *buffer, ...);

/* Bandwidth limitation */

wzd_bw_limiter * limiter_new(int maxspeed);
void limiter_add_bytes(wzd_bw_limiter *l, wzd_sem_t sem, int byte_count, int force_check);
void limiter_free(wzd_bw_limiter *l);

/* cookies */
int cookies_replace(char * buffer, unsigned int buffersize, void * void_param, void * void_context);

/* print_file : read file, replace cookies and prints it
 * header (200-) MUST have been sent, and end (200 ) is NOT sent)
 */
int print_file(const char *filename, int code, void * void_context);

/* used to translate text to binary word for rights */
unsigned long right_text2word(const char * text);

/* dst can be composed of wildcards */
int my_str_compare(const char * src, const char *dst);

/* IP allowing */
int ip_add(wzd_ip_t **list, const char *newip);
int ip_inlist(wzd_ip_t *list, const char *ip);
void ip_free(wzd_ip_t *list);

int user_ip_add(wzd_user_t * user, const char *newip);
int user_ip_inlist(wzd_user_t * user, const char *ip);

int group_ip_add(wzd_group_t * group, const char *newip);
int group_ip_inlist(wzd_group_t * group, const char *ip);

/* wrappers to user list */
wzd_user_t * GetUserByID(unsigned int id);
wzd_user_t * GetUserByName(const char *name);
wzd_group_t * GetGroupByID(unsigned int id);
wzd_group_t * GetGroupByName(const char *name);
unsigned int GetUserIDByName(const char *name);
unsigned int GetGroupIDByName(const char *name);

/* wrappers to context list */
void * GetMyContext(void);

#endif /* __WZD_MISC__ */

