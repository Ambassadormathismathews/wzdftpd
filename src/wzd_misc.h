/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
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

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  /* struct in_addr */
#endif

#include "wzd_mutex.h"

unsigned long compute_hashval (const void *key, size_t keylen);

char * time_to_str(time_t time);

int bytes_to_unit(float *value, char *unit);

void chop(char *s);

int split_filename(const char *filename, char *path, char *stripped_filename, int pathlen, unsigned int filelen);

/** send exit signal to a child */
int kill_child_new(unsigned long pid, wzd_context_t * context);

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

unsigned long get_bandwidth(void);
wzd_bw_limiter * limiter_new(int maxspeed);
void limiter_add_bytes(wzd_bw_limiter *l, wzd_mutex_t *mutex, int byte_count, int force_check);
void limiter_free(wzd_bw_limiter *l);

/** \brief allocate buffer big enough to format arguments with printf
 *
 * Returned string must be freed with \ref wzd_free
 */
char * safe_vsnprintf(const char *format, va_list ap);

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

/** \brief read next token
 * \return a pointer to the next token, or NULL if not found, or if there is
 * only whitespaces, or if quotes are unbalanced
 *
 * Read next token separated by a whitespace, except if string begins
 * with a ' or ", in this case it searches the matching character.
 * Note: input string is modified as a \\0 is written.
 */
char * read_token(char *s, char **endptr);

/* replace all \ with / and lower string */
void win_normalize(char * s, unsigned int length, unsigned int lower);

short is_user_in_group(wzd_user_t * user, unsigned int gid);
int group_remove_user(wzd_user_t * user, unsigned int gid);

/* wrappers to context list */
void * GetMyContext(void);

#endif /* __WZD_MISC__ */

