#ifndef __WZD_MESSAGES__
#define __WZD_MESSAGES__

void init_default_messages(void);

const char * getMessage(int code);
void setMessage(const char *newMessage, int code);

#endif /* __WZD_MESSAGES__ */
