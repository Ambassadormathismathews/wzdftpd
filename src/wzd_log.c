#include "wzd.h"

void out_log(int level,const char *fmt,...)
{
	va_list argptr;

	if (level >= mainConfig.loglevel) {
		va_start(argptr,fmt); /* note: ansi compatible version of va_start */
		if (mainConfig.logfile) {
			vfprintf(stdout,fmt,argptr);
/*			vfprintf(mainConfig.logfile,fmt,argptr);
			fflush(mainConfig.logfile);*/
		} else { /* security - will be used iff log is not opened at this time */
			vfprintf(stderr,fmt,argptr);
		}
	}
}

void out_err(int level, const char *fmt,...)
{
  va_list argptr;

  if (level >= mainConfig.loglevel) {
    va_start(argptr,fmt); /* note: ansi compatible version of va_start */
    vfprintf(stderr,fmt,argptr);
  }
}

void interpret_wsa_error()
{
#if 0
/*#ifdef __CYGWIN__*/
	int errcode;

	errcode = WSAGetLastError();

	switch(errcode) {
	case WSANOTINITIALISED:
		out_log(LEVEL_HIGH,"A successful WSAStartup call must occur before using this function\n");
		break;
	case WSAENETDOWN:
		out_log(LEVEL_HIGH,"The network subsystem has failed\n");
		break;
	case WSAEFAULT:
		out_log(LEVEL_HIGH,"The addrlen parameter is too small or addr is not a valid part of the user address space.\n");
		break;
	case WSAEINTR:
		out_log(LEVEL_HIGH,"A blocking Windows Sockets 1.1 call was canceled through WSACancelBlockingCall\n");
		break;
	case WSAEINPROGRESS:
		out_log(LEVEL_HIGH,"A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function\n");
		break;
	case WSAEINVAL:
		out_log(LEVEL_HIGH,"The listen function was not invoked prior to accept\n");
		break;
	case WSAEMFILE:
		out_log(LEVEL_HIGH,"The queue is nonempty upon entry to accept and there are no descriptors available\n");
		break;
	case WSAENOBUFS:
		out_log(LEVEL_HIGH,"No buffer space is available\n");
		break;
	case WSAENOTSOCK:
		out_log(LEVEL_HIGH,"The descriptor is not a socket\n");
		break;
	case WSAEOPNOTSUPP:
		out_log(LEVEL_HIGH,"The referenced socket is not a type that supports connection-oriented service\n");
		break;
	case WSAEWOULDBLOCK:
		out_log(LEVEL_HIGH,"The socket is marked as nonblocking and no connections are present to be accepted\n");
		break;
	default:
		break;
	}
#endif
}
