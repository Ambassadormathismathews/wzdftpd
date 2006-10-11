/* vi:ai:et:ts=8 sw=2
 */
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

/** \file libwzd_codes.h
 *  \brief Definitions for FTP reply codes
 */

#ifndef __LIBWZD_CODES__
#define __LIBWZD_CODES__

/*! \addtogroup libwzd
 *  @{
 */

#ifdef	__cplusplus
extern "C" {
#endif

/** The requested action is being initiated; expect another
 * reply before proceeding with a new command. This
 * type of reply can be used to indicate that the command
 * was accepted and the user-process may now pay attention
 * to the data connections, for implementations where
 * simultaneous monitoring is difficult.  The server-FTP
 * process may send at most, one 1yz reply per command.
 */
#define REPLY_POSITIVE_PRELIMINARY 1

/** The requested action has been successfully completed.  A
 * new request may be initiated.
 */
#define REPLY_POSITIVE_COMPLETION 2

/** The command has been accepted, but the requested action
 * is being held in abeyance, pending receipt of further
 * information.  The user should send another command
 * specifying this information.  This reply is used in
 * command sequence groups.
 */
#define REPLY_POSITIVE_INTERMEDIATE 3

/** The command was not accepted and the requested action did
 * not take place, but the error condition is temporary and
 * the action may be requested again.  The user should
 * return to the beginning of the command sequence, if any.
 */
#define REPLY_TRANSCIENT_NEGATIVE_COMPLETION 4

/** The command was not accepted and the requested action did
 * not take place.  The User-process is discouraged from
 * repeating the exact request (in the same sequence).
 */
#define REPLY_PERMANENT_NEGATIVE_COMPLETION 5




/** These replies refer to syntax errors,
 * syntactically correct commands that don't fit any
 * functional category, unimplemented or superfluous
 * commands.
 */
#define REPLY2_SYNTAX 0

/** These are replies to requests for
 * information, such as status or help.
 */
#define REPLY2_INFORMATION 1

/** Replies referring to the control and data connections.
 */
#define REPLY2_CONNECTIONS 2

/** Replies for the login process and accounting procedures.
 */
#define REPLY2_AUTH 3

/** Unspecified as yet. */
#define REPLY2_UNSPECIFIED 4

/** These replies indicate the status of the
 * Server file system vis-a-vis the requested transfer or
 * other file system action.
 */
#define REPLY2_FILESYSTEM 5






/** \brief return true if the code is a valid FTP reply
 *
 * This is a very simple macro, since checking if the FTP reply
 * conforms to the FTP protocol is a far more complicated task.
 */
#define REPLY_IS_VALID(code) ( (int)(code) >= 100 && (int)(code) <= 599 )

/** \brief get the first digit of reply code */
#define REPLY_GET_DIGIT1(code) ( (int)(code) / 100 )

/** \brief get the second digit of reply code */
#define REPLY_GET_DIGIT2(code) ( ((int)(code) / 10) % 10 )

/** \brief get the third digit of reply code */
#define REPLY_GET_DIGIT3(code) ( (int)(code) % 10 )



/** \brief true if the reply indicates that the command was correctly executed */
#define REPLY_IS_OK(code) ( REPLY_GET_DIGIT1(code) == 2)

/** \brief true if the reply code is an error (temporary or permanent) */
#define REPLY_IS_ERROR(code) ( REPLY_GET_DIGIT1(code) == 4 || REPLY_GET_DIGIT1(code) == 5)


/** Splits the FTP reply code in three parts, which can be interpreted using
 * the previous macros REPLY_DIGIT_... and REPLY_DIGIT2_...
 * \note The meaning of the last digit is very unclear in RFC959
 * \return 0 if ok, 1 if the code is not a valid FTP reply code
 */
int wzd_split_reply_code(int code, int * digit1, int * digit2, int * digit3);



#ifdef	__cplusplus
} /* extern "C" */
#endif

/*! @} */

#endif /* __LIBWZD_CODES__ */

