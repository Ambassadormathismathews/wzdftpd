#ifndef __WZD_MESSAGES__
#define __WZD_MESSAGES__

void init_default_messages(void);

const char * getMessage(int code);
void setMessage(const char *newMessage, int code);

/* message sending functions */
int send_message(int code, wzd_context_t * context);
int send_message_with_args(int code, wzd_context_t * context, ...);
int send_message_raw(const char *msg, wzd_context_t * context);

#endif /* __WZD_MESSAGES__ */
