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
wzd_init(host,port,user,pass)
    const char *	host
    int			port
    const char *	user
    const char *	pass
  CODE:
    /** XXX FIXME need to call wzd_parse_ags... */
    RETVAL = wzd_init();
  OUTPUT:
    RETVAL

int
wzd_fini()
  CODE:
    RETVAL = wzd_fini();
  OUTPUT:
    RETVAL
