#ifndef __WZD_MD5_H__
#define __WZD_MD5_H__

typedef unsigned int uint32;

struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    unsigned char in[64];
};

void GoodMD5Init(struct MD5Context *);
void GoodMD5Update(struct MD5Context *, unsigned const char *, unsigned);
void GoodMD5Final(unsigned char digest[16], struct MD5Context *);
void GoodMD5Transform(uint32 buf[4], uint32 const in[16]);
void BrokenMD5Init(struct MD5Context *);
void BrokenMD5Update(struct MD5Context *, unsigned const char *, unsigned);
void BrokenMD5Final(unsigned char digest[16], struct MD5Context *);
void BrokenMD5Transform(uint32 buf[4], uint32 const in[16]);

char *Goodcrypt_md5(const char *pw, const char *salt);
char *Brokencrypt_md5(const char *pw, const char *salt);


/* FIXME VISUAL */
#define MD5Name(x) (Good ## x)

/* Read string and fills tab crc[16] */
void strtomd5(char *ptr,char **ptest, unsigned char *crc);

/* Calculates the md5 checksum of fname, and stores the result
 * in crc. Returns 0 on success, nonzero on error.
 */
int calc_md5( const char *fname, unsigned char md5_crc[16], unsigned long startpos, unsigned long length );

#endif /* __WZD_MD5_H__ */

