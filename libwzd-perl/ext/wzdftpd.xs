#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "libwzd.h"


MODULE = wzdftpd		PACKAGE = wzdftpd		

PROTOTYPES: ENABLE

#/* we can use PREINIT to give default values
# * see perlxs(1)  The PROTOTYPE: Keyword
# */
int
wzd_init(host="localhost",port=21,user="wzdftpd",pass="wzdftpd")
    const char *	host
    int			port
    const char *	user
    const char *	pass
  CODE:
  {
    int ok=1;

    ok = wzd_init();

    if (ok && host) {
      if (wzd_set_hostname(host)<0) ok = 0;
    }
    if (ok && port) {
      if (wzd_set_port(port)<0) ok = 0;
    }
    if (ok && user) {
      if (wzd_set_username(user)<0) ok = 0;
    }
    if (ok && pass) {
      if (wzd_set_password(pass)<0) ok = 0;
    }

    if (ok) {
      RETVAL = (!wzd_connect());
    } else {
      RETVAL = 0;
    }
  }
  OUTPUT:
    RETVAL

int
wzd_fini()
  CODE:
    RETVAL = wzd_fini();
  OUTPUT:
    RETVAL

char *
wzd_send_message(message)
    const char *	message
  INIT:
    wzd_reply_t * reply;
    unsigned int i;

  PPCODE:
    reply = wzd_send_message(message,strlen(message));
    if (!reply)
      XSRETURN_UNDEF;


    for (i=0; reply->data[i]!=NULL; i++) {
      XPUSHs(sv_2mortal(newSVpv(reply->data[i],strlen(reply->data[i]))));
    }

    wzd_free_reply(reply);

