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

#ifndef __WZD_CLIENT_THREAD__
#define __WZD_CLIENT_THREAD__

#include "wzd_string.h"

int clear_read(fd_t sock, char *msg, size_t length, int flags, unsigned int timeout, void * vcontext);
int clear_write(fd_t sock, const char *msg, size_t length, int flags, unsigned int timeout, void * vcontext);

void * clientThreadProc(void *arg);

void client_die(wzd_context_t * context);

#ifdef TEST_MLSD
#define GLOBAL_FEATURES  " NON-FREE FTPD SUCKS\n MDTM\n SIZE\n SITE\n REST\n PRET\n XCRC\n XMD5\n MLST Type*;Size*;Modify*;Perm*;Unique*;UNIX.mode;\n"
#else
#define GLOBAL_FEATURES  " NON-FREE FTPD SUCKS\n MDTM\n SIZE\n SITE\n REST\n PRET\n XCRC\n XMD5\n"
#endif

#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
#define TEMP_FEAT  GLOBAL_FEATURES " AUTH TLS\n PBSZ\n PROT\n SSCN\n CPSV\n"
#else
#define TEMP_FEAT GLOBAL_FEATURES
#endif

#ifdef HAVE_UTF8
#define TEMP_FEAT2  TEMP_FEAT" UTF8\n"
#else
#define TEMP_FEAT2 TEMP_FEAT
#endif

#define SUPPORTED_FEATURES (TEMP_FEAT2 "End")



int do_type(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_port(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_pasv(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_eprt(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_epsv(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_abor(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_print_message(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_rnfr(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_rnto(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_cwd(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_list(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_mlst(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_mlsd(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_stat(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_mkdir(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_rmdir(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_retr(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_stor(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_rest(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_mdtm(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_size(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_dele(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_pret(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_xcrc(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_xmd5(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_opts(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_quit(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_prot(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_sscn(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int do_help(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);

#endif /* __WZD_CLIENT_THREAD__ */
