/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#ifndef __WZD_MISC__
#define __WZD_MISC__

unsigned long compute_hashval (const void *key, size_t keylen);

char * time_to_str(time_t time);

int bytes_to_unit(float *value, char *unit);

void chop(char *s);

int split_filename(const char *filename, char *path, char *stripped_filename, int pathlen, int filelen);

/* returns system ip on specifed interface (e.g eth0) */
int get_system_ip(const char * itface, struct in_addr * ina);

/* returns info on device containing dir/file */
int get_device_info(const char *file, long * f_type, long * f_bsize, long * f_blocks, long *f_free);

/* returns 1 if file is perm file */
int is_perm_file(const char *filename);

/** returns 1 if file is hidden: perm,hidden,race_info file, etc */
int is_hidden_file(const char *filename);

/* get file last change time */
time_t get_file_ctime(const char *file);
time_t lget_file_ctime(int fd);

/* renames file/dir, if on different fs then moves recursively */
int safe_rename(const char *src, const char *dst);

#ifndef HAVE_INET_NTOP
const char * inet_ntop(int af, const void *src, char *dst, int size);
#endif
#ifndef HAVE_INET_PTON
int inet_pton(int af, const char *src, void *dst);
#endif

int server_get_param(const char *name, void *buffer, unsigned int maxlen, wzd_param_t *param_list);
int server_set_param(const char *name, void *data, unsigned int length, wzd_param_t **plist);
void server_clear_param(wzd_param_t **plist);

/** Checks server status */
int server_diagnose(void);

/* formats the message if multiline, e.g 220-hello\r\n220 End */
/* if code is negative, the last line will NOT be formatted as the end
 * of a normal ftp reply
 */
void v_format_message(int code, unsigned int *plength, char **pbuffer, va_list argptr);
void format_message(int code, unsigned int *plength, char **pbuffer, ...);
/*void v_format_message(int code, unsigned int length, char *buffer, va_list argptr);*/
/*void format_message(int code, unsigned int length, char *buffer, ...);*/

/* Bandwidth limitation */

wzd_bw_limiter * limiter_new(int maxspeed);
void limiter_add_bytes(wzd_bw_limiter *l, wzd_sem_t sem, int byte_count, int force_check);
void limiter_free(wzd_bw_limiter *l);

/* cookies */
/* defined in wzd_cookie_lex.l */
int cookie_parse_buffer(const char *buffer, wzd_user_t * user, wzd_group_t * group, wzd_context_t * context, char * out_buffer, unsigned int out_buffer_len);

/* print_file : read file, replace cookies and prints it
 * header (200-) MUST have been sent, and end (200 ) is NOT sent)
 */
int print_file(const char *filename, int code, void * void_context);

/* used to translate text to binary word for rights */
unsigned long right_text2word(const char * text);

/* dst can be composed of wildcards */
int my_str_compare(const char * src, const char *dst);

/* lower only characters in A-Z ! */
void ascii_lower(char * s, unsigned int length);

/* replace all \ with / and lower string */
void win_normalize(char * s, unsigned int length);

/* IP allowing */
int ip_add(wzd_ip_t **list, const char *newip);
int ip_inlist(wzd_ip_t *list, const char *ip);
void ip_free(wzd_ip_t *list);

int user_ip_add(wzd_user_t * user, const char *newip);
int user_ip_inlist(wzd_user_t * user, const char *ip, const char *ident);

int group_ip_add(wzd_group_t * group, const char *newip);
int group_ip_inlist(wzd_group_t * group, const char *ip, const char *ident);

/* wrappers to user list */
wzd_user_t * GetUserByID(unsigned int id);
wzd_user_t * GetUserByName(const char *name);
wzd_group_t * GetGroupByID(unsigned int id);
wzd_group_t * GetGroupByName(const char *name);
unsigned int GetUserIDByName(const char *name);
unsigned int GetGroupIDByName(const char *name);

short is_user_in_group(wzd_user_t * user, int gid);
int group_remove_user(wzd_user_t * user, int gid);

/* wrappers to context list */
void * GetMyContext(void);

#endif /* __WZD_MISC__ */

