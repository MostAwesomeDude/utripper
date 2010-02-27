/*
 *  crypt_util.h
 */

#ifndef _CRYPT_UTIL_H
#define _CRYPT_UTIL_H

#include <stdint.h>

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
	uint32_t efp[16][64][2];
	uint32_t e_inverse[64];
	uint32_t disturbed_e[48];
	uint32_t *sb[4];
	uint32_t oldsaltbits;
	uint8_t salt[4];
	int sequential;
};

/* external APIs */

void crypt_init(struct crypt_state *crs);
void crypt_exit(struct crypt_state *crs);
void rcrypt(struct crypt_state *crs, char *salt, unsigned char *key, unsigned char outbuf[][16]);
void output_conversion(struct crypt_state *crs, uint32_t *res, char *outbuf);
void crypt_core(uint32_t result[], uint32_t **sb, uint32_t *ktab);

#endif /* _CRYPT_UTIL_H */
