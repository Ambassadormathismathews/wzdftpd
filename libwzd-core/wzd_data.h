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

#ifndef __WZD_DATA__
#define __WZD_DATA__

/** \brief Close data connection (if opened) */
void data_close(wzd_context_t * context);

/** \brief End current transfer if any, close data connection and send event
 */
void data_end_transfer(int is_upload, int end_ok, wzd_context_t * context);

/* sets the correct fds and return the highest fd that was set or -1 */
int data_set_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde);

/* returns 1 if a set is ok, 0 if not fd set, -1 if error */
int data_check_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde);

/* send or retr data */
int data_execute(wzd_context_t * context, wzd_user_t * user, fd_set *fdr, fd_set *fdw);

/** \brief run local transfer loop for RETR
 */
int do_local_retr(wzd_context_t * context);

/** \brief run local transfer loop for STOR
 */
int do_local_stor(wzd_context_t * context);

/** \brief Create thread for data transfer (RETR)
 */
int data_start_thread_retr(wzd_context_t * context);

/** \brief Create thread for data transfer (STOR)
 */
int data_start_thread_stor(wzd_context_t * context);

#endif /* __WZD_DATA__ */
