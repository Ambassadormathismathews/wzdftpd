#include "wzd.h"

#define DEFAULT_MSG	"No message for this code"

const char *msg_tab[HARD_MSG_LIMIT];

void init_default_messages(void)
{
  memset(msg_tab,0,HARD_MSG_LIMIT*sizeof(char *));

  msg_tab[150] = "Status OK, about to open data connection.";

  msg_tab[200] = "%s"; /* Command okay */
  msg_tab[202] = "Command not implemented.";
  msg_tab[211] = "Extension supported\n%s";
  msg_tab[213] = "%s"; /* mdtm */
  msg_tab[215] = "UNIX Type: L8";
  msg_tab[220] = "wzd server ready.";
  msg_tab[221] = "Cya !";
  msg_tab[226] = "Closing data connection.";
  msg_tab[227] = "Entering Passive Mode (%d,%d,%d,%d,%d,%d)"; /* DON'T TOUCH ! */
  msg_tab[230] = "User logged in, proceed.";
  msg_tab[234] = "AUTH command OK. Initializing %s mode"; /* SSL init */
  msg_tab[250] = "%s %s";
  msg_tab[257] = "\"%s\" %s";
  msg_tab[258] = "%s %s";

  msg_tab[331] = "User %s okay, need password.";
  msg_tab[350] = "Restarting at %ld. Send STORE or RETRIEVE.";

  msg_tab[421] = "%s"; /* Service not available, closing control connection. */
  msg_tab[425] = "Can't open data connection.";
  msg_tab[451] = "Transmission error occured.";
  msg_tab[491] = "Data connection already active.";

  msg_tab[501] = "%s";
  msg_tab[502] = "Command not implemented.";
  msg_tab[530] = "Not logged in.";
  msg_tab[550] = "%s: %s";
  msg_tab[553] = "Requested action not taken: %s";
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
