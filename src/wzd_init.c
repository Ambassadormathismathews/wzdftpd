#include "wzd.h"

#include <string.h>
#include <malloc.h>

int readConfigFile(const char *fileName)
{
#ifdef __CYGWIN__
	WORD wVersionRequested;
	WSADATA wsaData;
#endif
	int err;


	init_default_messages();

	mainConfig.max_threads=32;
	mainConfig.logfilename = malloc(256);
	strcpy(mainConfig.logfilename,"wzd.log");
	mainConfig.logfilemode = malloc(3);
	strcpy(mainConfig.logfilemode,"a");
	mainConfig.loglevel=LEVEL_LOWEST;

#ifdef __CYGWIN__
	/* init sockets */
	wVersionRequested = MAKEWORD( 2, 2 );
	err = WSAStartup( wVersionRequested, &wsaData );
#endif

	mainConfig.port = 6969;
	
	return 0;
}
