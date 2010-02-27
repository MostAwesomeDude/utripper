/* crypt_core */

#define SBA(sb, v) (*(uint64_t*)((char*)(sb)+(v)))

#define F(I, O, SBX, SBY) \
    do { uint32_t s = *k++ ^ I; \
    O ^= SBA(SBX, (s & 0xffff)); \
    O ^= SBA(SBY, (s >>= 16)); } while(0);

#define G(I, O)                                             \
        F((I & 0xffffffffUL), O, sb1, sb0) F((I >> 32), O, sb3, sb2)

#define H G(r, l) G(l, r)

void
crypt_core_default(uint32_t result[], uint32_t **sb, uint32_t *ktab)
{
	int i, j;
	uint64_t l, r, s;
	uint32_t *k;
	uint64_t *sb0, *sb1, *sb2, *sb3;

	sb0 = (uint64_t *)sb[0];
	sb1 = (uint64_t *)sb[1];
	sb2 = (uint64_t *)sb[2];
	sb3 = (uint64_t *)sb[3];

	l = r = 0;
	for(j=0; j<25; j++) {
		k = ktab;
		for(i=8; i--; ) {
			H;
		}
		s = l; l = r; r = s;
	}

	result[0] = l & 0xffffffffUL;
	result[1] = l >> 32;
	result[2] = r & 0xffffffffUL;
	result[3] = r >> 32;
}
