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

#ifndef __WZD_MESSAGES__
#define __WZD_MESSAGES__

void init_default_messages(void);
void free_messages(void);

/* must_free == 1 if calling function MUST free return after use */
const char * getMessage(int code, int *must_free);

/* be carefull: the function does NOT copy string, it just stores its adress ! */
void setMessage(const char *newMessage, int code);

/* message sending functions */
int send_message(int code, wzd_context_t * context);
int send_message_with_args(int code, wzd_context_t * context, ...);
int send_message_raw(const char *msg, wzd_context_t * context);

#endif /* __WZD_MESSAGES__ */
