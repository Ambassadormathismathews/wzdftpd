#if defined __CYGWIN__ && defined WINSOCK_SUPPORT
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"
#include "wzd_misc.h"
#include "wzd_log.h"


#define DEFAULT_MSG	"No message for this code"

#define BUFFER_LEN	4096

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
  msg_tab[350] = "%s"; /* "Restarting at %ld. Send STORE or RETRIEVE.", or "OK, send RNTO" */

  msg_tab[421] = "%s"; /* Service not available, closing control connection. */
  msg_tab[425] = "Can't open data connection.";
  msg_tab[426] = "Error occured, data connection closed.";
  msg_tab[431] = "%s"; /* Unable to accept security mechanism. */
  msg_tab[451] = "Transmission error occured.";
  msg_tab[491] = "Data connection already active.";

  msg_tab[501] = "%s";
  msg_tab[502] = "Command not implemented.";
  msg_tab[503] = "%s";
  msg_tab[530] = "%s"; /* Not logged in." */
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

/*************** send_message ************************/

int send_message(int code, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  int ret;

  format_message(code,BUFFER_LEN,buffer);
#ifdef DEBUG
if (buffer[strlen(buffer)-1]!='\n')
  out_err(LEVEL_FLOOD,"I answer: %s\n",buffer);
else
  out_err(LEVEL_FLOOD,"I answer: %s",buffer);
#endif
  ret = (context->write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);
/*  sprintf(buffer,"%3d \r\n",code);
  ret = (context->write_fct)(context->controlfd,buffer,6,0,HARD_XFER_TIMEOUT,context);*/

  return ret;
}

/*************** send_message_with_args **************/

int send_message_with_args(int code, wzd_context_t * context, ...)
{
  va_list argptr;
  char buffer[BUFFER_LEN];
  int ret;

  va_start(argptr,context); /* note: ansi compatible version of va_start */
  v_format_message(code,BUFFER_LEN,buffer,argptr);
#ifdef DEBUG
if (buffer[strlen(buffer)-1]!='\n')
  out_err(LEVEL_FLOOD,"I answer: %s\n",buffer);
else
  out_err(LEVEL_FLOOD,"I answer: %s",buffer);
#endif
  ret = (context->write_fct)(context->controlfd,buffer,strlen(buffer),0,HARD_XFER_TIMEOUT,context);

  return 0;
}

/*************** send_message_raw ********************/

int send_message_raw(const char *msg, wzd_context_t * context)
{
  int ret;

/*#ifdef DEBUG
if (buffer[strlen(buffer)-1]!='\n')
  out_err(LEVEL_FLOOD,"I answer: %s\n",buffer);
else
  out_err(LEVEL_FLOOD,"I answer: %s",buffer);
#endif*/
  ret = (context->write_fct)(context->controlfd,msg,strlen(msg),0,HARD_XFER_TIMEOUT,context);

  return ret;
}

