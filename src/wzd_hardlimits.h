#ifndef __WZD_HARD_LIMITS__
#define __WZD_HARD_LIMITS__


#define	HARD_REACTION_TIME	1L

/* FIXME should be a variable */
#define	HARD_XFER_TIMEOUT	60L

#define	TRFMSG_INTERVAL		1000000


#define	HARD_THREADLIMIT	2000
#define	HARD_USERLIMIT		128
#define	HARD_DEF_USER_MAX	64
#define	HARD_DEF_GROUP_MAX	64
#define	HARD_MSG_LIMIT		1024

#define	MAX_IP_LENGTH		128
#define	HARD_IP_PER_USER	8
#define	HARD_IP_PER_GROUP	8

#define	MAX_FLAGS_NUM		32


#define	HARD_PERMFILE		".dirinfo"

/* interval of time to check dynamic ip (default: 10 mns) */
#define	HARD_DYNAMIC_IP_INTVL	60


#define	HARD_LS_BUFFERSIZE	4096

#endif /* __WZD_HARD_LIMITS__ */
