#ifndef __WZD_MISC__
#define __WZD_MISC__

char * time_to_str(time_t time);

void chop(char *s);

/* formats the message if multiline, e.g 220-hello\r\n220 End */
void v_format_message(int code, unsigned int length, char *buffer, va_list argptr);
void format_message(int code, unsigned int length, char *buffer, ...);

/* Bandwidth limitation */

wzd_bw_limiter * limiter_new(int maxspeed);
void limiter_add_bytes(wzd_bw_limiter *l, int byte_count, int force_check);
void limiter_free(wzd_bw_limiter *l);

/* cookies */
int cookies_replace(char * buffer, unsigned int buffersize, void * void_context);

/* used to translate text to binary word for rights */
unsigned long right_text2word(const char * text);


#endif /* __WZD_MISC__ */

