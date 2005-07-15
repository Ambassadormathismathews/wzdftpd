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

#ifndef __WZD_SITE_USER__
#define __WZD_SITE_USER__

int do_site_adduser(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_deluser(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_readduser(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_purgeuser(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context);
int do_site_kick(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context);
int do_site_kill(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context);
int do_site_killpath(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_su(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);

int do_site_addip(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_delip(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);

int do_site_color(wzd_string_t *command_line, wzd_string_t *param, wzd_context_t * context);

int do_site_changegrp(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_chratio(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_give(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_take(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);

int do_site_change(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);

int do_site_flags(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_idle(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);
int do_site_tagline(wzd_string_t *ignored, wzd_string_t *command_line, wzd_context_t * context);

#endif /* __WZD_SITE_USER__ */
