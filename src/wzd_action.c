#include "wzd.h"

void set_action(wzd_context_t * context, unsigned int token, const char *arg)
{
  if (!context) return;

  context->current_action.token = token;
  strncpy(context->current_action.arg,arg,4096);
  context->current_action.tm_start = time(NULL);
}
