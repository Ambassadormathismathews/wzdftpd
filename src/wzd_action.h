#ifndef __WZD_ACTION__
#define __WZD_ACTION__

#define TOK_UNKNOWN     0
#define TOK_USER        1
#define TOK_PASS        2
#define TOK_AUTH        3
#define TOK_QUIT        4
#define TOK_TYPE        5
#define TOK_MODE        6
#define TOK_PORT        7
#define TOK_PASV        8
#define TOK_PWD         9
#define TOK_NOOP        10
#define TOK_SYST        11
#define TOK_CWD         12
#define TOK_CDUP        13
#define TOK_LIST        14
#define TOK_NLST        15
#define TOK_MKD         16
#define TOK_RMD         17
#define TOK_RETR        18
#define TOK_STOR        19
#define TOK_REST        20
#define TOK_MDTM        21
#define TOK_SIZE        22
#define TOK_DELE        23
#define TOK_ABOR        24

#if SSL_SUPPORT
#define TOK_PBSZ        25
#define TOK_PROT        26
#endif

#define TOK_SITE        27
#define TOK_FEAT        28
#define	TOK_ALLO	29
#define	TOK_RNFR	30
#define	TOK_RNTO	31

typedef struct {
  unsigned int	token;
  char		arg[4096];

  FILE *	current_file;
  unsigned int	bytesnow;

  time_t	tm_start;
} wzd_action_t;

#endif /* __WZD_ACTION__ */

