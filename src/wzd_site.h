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

#ifndef __WZD_SITE__
#define __WZD_SITE__

int do_site(wzd_string_t *command, wzd_string_t *command_line, wzd_context_t * context);
void do_site_help(const char *site_command, wzd_context_t * context);

void do_site_print_file(const char *filename, wzd_user_t *user, wzd_group_t *group, wzd_context_t *context);


int do_site_backend(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_chacl(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_checkperm(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_chgrp(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_chmod(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_chown(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_chpass(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_free(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context);
int do_site_invite(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_link(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_msg(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_perm(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_reload(wzd_string_t * ignored, wzd_string_t *param, wzd_context_t * context);
int do_site_rusage(wzd_string_t * ignored, wzd_string_t *param, wzd_context_t * context);
int do_site_savecfg(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_test(wzd_string_t *command, wzd_string_t *param, wzd_context_t * context);
int do_site_unlock(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_utime(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_vars(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_vars_group(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_vars_user(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_version(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_vfsls(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_vfsadd(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_vfsdel(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_wipe(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
#endif /* __WZD_SITE__ */
