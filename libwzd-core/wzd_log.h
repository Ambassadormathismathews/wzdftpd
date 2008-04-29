/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

#ifndef __WZD_LOG__
#define __WZD_LOG__

/* colors */

#ifndef _MSC_VER
#define CLR_BOLD	"[1m"

#define	CLR_BLUE	"[34m"
#define	CLR_CYAN	"[36m"
#define	CLR_GREEN	"[32m"
#define	CLR_RED		"[31m"

#define	CLR_NOCOLOR	"[0m"
#else
#define CLR_BOLD	""

#define	CLR_BLUE	""
#define	CLR_CYAN	""
#define	CLR_GREEN	""
#define	CLR_RED		""

#define	CLR_NOCOLOR	""
#endif


/* DEBUG & LOG */
#define LEVEL_LOWEST	0
#define	LEVEL_FLOOD	1
#define	LEVEL_INFO	3
#define	LEVEL_NORMAL	5
#define	LEVEL_HIGH	7
#define	LEVEL_CRITICAL	9

/** \brief Initialize logging facilities
 *
 * Init structures used for logging
 */
int log_init(void);

/** \brief Open file for logging
 */
int log_open(const char * filename, int filemode);

/** \brief Close log file
 */
void log_close(int fd);

/** \brief Close all log descriptors
 */
void log_fini(void);

/** \brief Open log file descriptor, and set mainConfig->logfile
 * to the corresponding FILE *
 * \deprecated Use \ref log_open
 */
int log_open_old(const char *filename, int filemode);

/** \brief Close logfile opened using \ref log_open_old
 * \deprecated Use \ref log_close
 */
void log_close_old(void);

/** \brief Get file descriptor asociated to log level
 *
 * Get file decriptor corresponding to all messages sent to the
 * log level.
 */
int log_get(unsigned int level);

/** \brief Redirect log level to file descriptor
 *
 * Set file decriptor corresponding to all messages sent to the
 * log level.
 *
 * \note fd must have been returned from log_open()
 */
int log_set(unsigned int level, int fd);

/** \brief Use syslog for specified level
 *
 * Set value to 0 to disable syslogging level, otherwise us syslog
 */
int log_set_syslog(unsigned int level, int syslog_value);

/** \brief Open file of type xferlog and returns file descriptor if ok
 */
int xferlog_open(const char *filename, unsigned int filemode);

/** \brief Close xferlog file opened using \ref xferlog_open
 */
void xferlog_close(int fd);

/** \brief Send message to the server logger
 */
void out_log(int level,const char *fmt,...)
#ifdef __GNUC__
  __attribute__((__format__(printf,2,3)))
#endif
;

/** \brief Send message to the server error stream
 * \note This function does nothing in release mode
 */
void out_err(int level, const char *fmt,...)
#ifdef __GNUC__
  __attribute__((__format__(printf,2,3)))
#endif
;

/** \brief Automatically create and send the message in xferlog format
 * after a file transfer has been completed or interrupted.
 */
void out_xferlog(struct wzd_context_t * context, int is_complete);

/** \brief Format in a standard way and send message to the server logger
 * using LEVEL_NORMAL
 *
 * A newline is appended.
 */
void log_message(const char *event, const char *fmt, ...)
#ifdef __GNUC__
  __attribute__((__format__(printf,2,3)))
#endif
;

struct memory_log_t {
  int size; /**< number of messages kept */
  char ** data;
};

/** \brief Return a pointer to the log buffer (last log messages, stored in memory)
 *
 * The structure must not be changed or freed
 */
struct memory_log_t * get_log_buffer(void);

/** \brief Convert a string containing the log level name ("lowest", "flood", etc.)
 * into the corresponding constant (LEVEL_LOWEST)
 * \return The constant, or -1 on error
 */
int str2loglevel(const char *s);

/** \brief Convert a standard log level (LEVEL_LOWEST) into the
 * corresponding string ("lowest")
 * \return The constant string, or an empty string ("") on error
 */
const char * loglevel2str(int l);

#endif /* __WZD_LOG__ */
