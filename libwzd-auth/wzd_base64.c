/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *radixN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int radix_encode(unsigned char inbuf[], unsigned char outbuf[], int *len, int decode)
{
    int           i,j,D=0;
    char          *p;
    unsigned char c=0;

    if (decode) {
	for (i=0,j=0; inbuf[i] && inbuf[i] != '='; i++) {
	    if ((p = strchr(radixN, inbuf[i])) == NULL) return(1);
	    D = p - radixN;
	    switch (i&3) {
		case 0:
		    outbuf[j] = D<<2;
		    break;
		case 1:
		    outbuf[j++] |= D>>4;
		    outbuf[j] = (D&15)<<4;
		    break;
		case 2:
		    outbuf[j++] |= D>>2;
		    outbuf[j] = (D&3)<<6;
		    break;
		case 3:
		    outbuf[j++] |= D;
	    }
	}
#if 0
	switch (i&3) {
	    case 1: return(3);
	    case 2: if (D&15) return(3);
		if (strcmp((char *)&inbuf[i], "==")) return(2);
		break;
	    case 3: if (D&3) return(3);
		if (strcmp((char *)&inbuf[i], "="))  return(2);
	}
#endif
	*len = j;
    } else {
	for (i=0,j=0; i < *len; i++)
	    switch (i%3) {
		case 0:
		    outbuf[j++] = radixN[inbuf[i]>>2];
		    c = (inbuf[i]&3)<<4;
		    break;
		case 1:
		    outbuf[j++] = radixN[c|inbuf[i]>>4];
		    c = (inbuf[i]&15)<<2;
		    break;
		case 2:
		    outbuf[j++] = radixN[c|inbuf[i]>>6];
		    outbuf[j++] = radixN[inbuf[i]&63];
		    c = 0;
	    }
	if (i%3) outbuf[j++] = radixN[c];
	switch (i%3) {
	    case 1: outbuf[j++] = '=';
	    case 2: outbuf[j++] = '=';
	}
	outbuf[*len = j] = '\0';
    }
    return(0);
}

#if 0
/* base64 error messages
 */
static char *radix_error(e)
{
    switch (e) {
	case 0:  return("Success");
	case 1:  return("Bad character in encoding");
	case 2:  return("Encoding not properly padded");
	case 3:  return("Decoded # of bits not a multiple of 8");
	default: return("Unknown error");
    }
}
#endif


