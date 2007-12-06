#ifndef LIBWZD_DUPECHECK_COMMANDS_H
#define LIBWZD_DUPECHECK_COMMANDS_H

int dupecheck_command_undupe(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);
int dupecheck_command_dupe(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context);

void dupecheck_command_help_undupe(wzd_context_t * context);
void dupecheck_command_help_dupe(wzd_context_t * context);

#endif
