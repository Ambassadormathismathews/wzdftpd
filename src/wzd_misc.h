#ifndef __WZD_MISC__
#define __WZD_MISC__

char * time_to_str(time_t time);

void chop(char *s);

/* formats the message if multiline, e.g 220-hello\r\n220 End */
void v_format_message(int code, unsigned int length, char *buffer, va_list argptr);
void format_message(int code, unsigned int length, char *buffer, ...);

#endif /* __WZD_MISC__ */

