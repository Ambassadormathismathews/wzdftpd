#ifndef __WZD_SITE_USER__
#define __WZD_SITE_USER__

int do_site_adduser(char *command_line, wzd_context_t * context);
int do_site_deluser(char *command_line, wzd_context_t * context);
int do_site_readduser(char *command_line, wzd_context_t * context);
int do_site_purgeuser(char *command_line, wzd_context_t * context);
int do_site_kick(char *command_line, wzd_context_t * context);
int do_site_kill(char *command_line, wzd_context_t * context);

int do_site_addip(char *command_line, wzd_context_t * context);
int do_site_delip(char *command_line, wzd_context_t * context);

int do_site_chgrp(char *command_line, wzd_context_t * context);

int do_site_change(char *command_line, wzd_context_t * context);

int do_site_flags(char *command_line, wzd_context_t * context);
int do_site_idle(char *command_line, wzd_context_t * context);
int do_site_tagline(char *command_line, wzd_context_t * context);

#endif /* __WZD_SITE_USER__ */
