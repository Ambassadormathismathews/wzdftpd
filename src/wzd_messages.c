#include "wzd.h"

#define HARD_MSG_LIMIT	1024
#define DEFAULT_MSG	"No message for this code"

const char *msg_tab[HARD_MSG_LIMIT];

void init_default_messages(void)
{
	memset(msg_tab,0,HARD_MSG_LIMIT*sizeof(char *));

	msg_tab[220] = "wzd server ready.";
	msg_tab[331] = "need password.";
}

const char * getMessage(int code)
{
	const char * ptr;
	if (code < 0 || code > HARD_MSG_LIMIT)
		return DEFAULT_MSG;
	ptr = msg_tab[code];
	if (ptr)
		return ptr;
	return DEFAULT_MSG;
}

void setMessage(const char *newMessage, int code)
{
}
