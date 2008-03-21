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

#ifdef WIN32
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

/** \brief Kill child using a signal
 *
 * Child is killed instantly (this function should not be used for self)
 * If the client is inside a function, it is stopped immediatly,
 * maybe creating some problems.
 */
int kill_child_signal(unsigned long pid, wzd_context_t * context);

/** \brief Kill child
 *
 * A message is sent to the client thread, telling it to exit nicely on
 * the next loop iteration.
 * If the client is inside a function, it will exit after the function
 * is finished.
 */
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

/** \brief Checks server status
 */
int server_diagnose(void);

/** \brief Formats the message if multiline, e.g 220-hello\\r\\n220 End
 *
 * if code is negative, the last line will NOT be formatted as the end
 * of a normal ftp reply
 */
wzd_string_t * v_format_message(wzd_context_t * context, int code, va_list argptr);
wzd_string_t * format_message(wzd_context_t * context, int code, ...);

/* Bandwidth limitation */

unsigned long get_bandwidth(unsigned long *dl, unsigned long *ul);
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

/* used to translate text to binary word for rights */
unsigned long right_text2word(const char * text);

/* dst can be composed of wildcards */
int my_str_compare(const char * src, const char *dst);

/* lower only characters in A-Z ! */
void ascii_lower(char * s, size_t length);

/** \brief Read next token from input string.
 * \return a pointer to the next token, or NULL if not found, or if there is
 * only whitespaces, or if quotes are unbalanced
 *
 * Read next token separated by a whitespace, except if string begins
 * with a ' or ", in this case it searches the matching character.
 *
 * \note input string is modified as a \\0 is written.
 */
char * read_token(char *s, char **endptr);

/* replace all \ with / and lower string */
void win_normalize(char * s, unsigned int length, unsigned int lower);

short is_user_in_group(wzd_user_t * user, unsigned int gid);
int group_remove_user(wzd_user_t * user, unsigned int gid);

/* wrappers to context list */
void * GetMyContext(void);

#endif /* __WZD_MISC__ */

