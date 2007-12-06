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

/* must_free == 1 if calling function MUST free return with wzd_free after use */
const char * getMessage(int code, int *must_free);

/* be carefull: the function does NOT copy string, it just stores its adress ! */
void setMessage(const char *newMessage, int code);

/* message sending functions */
int send_message(int code, wzd_context_t * context);
int send_message_with_args(int code, wzd_context_t * context, ...);
int send_message_raw(const char *msg, wzd_context_t * context);

/** \brief send formatted reply to client, you have to take care of reply code
 *
 */
int send_message_raw_formatted(wzd_context_t * context, const char * format, ...);

/** \brief send formatted reply to client
 *
 * This will replace all previous functions to send messages
 */
int send_message_formatted(int code, wzd_context_t * context, const char * format, ...)
#ifdef __GNUC__
  __attribute__((__format__(printf,3,4)))
#endif
;

struct wzd_reply_t {
  int code; /**< the current reply code, or 0 if no reply is set */
  wzd_string_t * _reply;
  int sent; /**< 1 if the reply has already been sent */
};

/** \brief Allocate memory for a struct wzd_reply_t */
struct wzd_reply_t * reply_alloc(void);

/** \brief Free memory used by struct wzd_reply_t */
void reply_free(struct wzd_reply_t * reply);

/** \brief Clear the stored reply */
void reply_clear(wzd_context_t * context);

/** \brief Set the current reply code */
void reply_set_code(wzd_context_t * context, int code);

/** \brief Get the current reply code */
int reply_get_code(wzd_context_t * context);

/** \brief Add a message to the stored reply */
int reply_push(wzd_context_t * context, const char * s);

/** \brief Send formatted reply to client.
 *
 * \a code must be set
 */
int reply_send(wzd_context_t * context);

#endif /* __WZD_MESSAGES__ */
