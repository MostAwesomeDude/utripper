/*
 *  crypt_util.h
 */

#ifndef _CRYPT_UTIL_H
#define _CRYPT_UTIL_H

typedef unsigned char u8;
typedef unsigned int u32;
#ifdef __LP64__
typedef unsigned long u64;
#endif

#ifdef HAVE_MMX
#define rcrypt rcrypt_mmx
#define output_conversion output_conversion_mmx
#define crypt_core crypt_core_mmx
#define SIMUL_KEYS 2
#else
#define rcrypt rcrypt_default
#define output_conversion output_conversion_default
#define crypt_core crypt_core_default
#define SIMUL_KEYS 1
#endif

/* external data types */

struct crypt_state {
	u32 efp[16][64][2];
	u32 e_inverse[64];
	u32 disturbed_e[48];
	u32 *sb[4];
	u32 oldsaltbits;
	u8 salt[4];
	int sequential;
};

/* external APIs */

void crypt_init(struct crypt_state *crs);
void crypt_exit(struct crypt_state *crs);
void rcrypt(struct crypt_state *crs, char *salt, unsigned char *key, unsigned char outbuf[][16]);
void output_conversion(struct crypt_state *crs, u32 *res, char *outbuf);
void crypt_core(u32 result[], u32 **sb, u32 *ktab);

#endif /* _CRYPT_UTIL_H */
