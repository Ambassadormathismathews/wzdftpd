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

int log_open(const char *filename, int filemode);
void log_close(void);

/* Opens file of type xferlog and returns file descriptor if ok */
int xferlog_open(const char *filename, unsigned int filemode);
void xferlog_close(int fd);

void out_log(int level,const char *fmt,...);
void out_err(int level, const char *fmt,...);
void out_xferlog(wzd_context_t * context, int is_complete);

void log_message(const char *event, const char *fmt, ...);

int str2loglevel(const char *s);
const char * loglevel2str(int l);

#endif /* __WZD_LOG__ */
