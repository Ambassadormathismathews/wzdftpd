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

#ifndef __WZD_MOD_H__
#define __WZD_MOD_H__

/* free hook list */
void hook_free(wzd_hook_t **hook_list);

/* register a new hook */
int hook_add(wzd_hook_t ** hook_list, unsigned long mask, void_fct hook);
int hook_add_external(wzd_hook_t ** hook_list, unsigned long mask, const char *command);
int hook_add_custom_command(wzd_hook_t ** hook_list, const char *name, const char *command);

int hook_call_custom(wzd_context_t * context, wzd_hook_t *hook, const char *args);
int hook_call_external(wzd_hook_t *hook, const char *args);

unsigned long str2event(const char *s);

#define FORALL_HOOKS(test_mask)	{ \
  wzd_hook_t * hook; \
  for (hook = mainConfig->hook; hook; hook = hook->next_hook) \
  { \
    if (hook->mask & (test_mask)) { \

#define	END_FORALL_HOOKS	}\
  }\
}

/* module hook struct, used in modules */
typedef struct {
  unsigned long event_id;
  void_fct fct;
} module_hook_t;

/* check a module file */
int module_check(const char *filename);

/* add a module to the list */
int module_add(wzd_module_t ** module_list, const char * name);

/* load a module - module really should have been checked before ! */
int module_load(wzd_module_t *module);

/* free module list */
void module_free(wzd_module_t ** module_list);

/********************************/
/* modules functions prototypes */

#define	WZD_MODULE_INIT		wzd_module_init
#define	STR_MODULE_INIT		"wzd_module_init"
typedef int (*fcn_module_init)(void);

#define	WZD_MODULE_CLOSE	wzd_module_close

#endif /* __WZD_MOD_H__ */
