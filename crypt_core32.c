/* crypt_core */

#define SBA(sb, v) (*(uint32_t*)((char*)(sb)+(v)))

#define F(I, O1, O2, SBX, SBY)                                        \
    s = *k++ ^ I;                                                     \
    O1 ^= SBA(SBX, (s & 0xffff)); O2 ^= SBA(SBX, ((s & 0xffff) + 4)); \
    O1 ^= SBA(SBY, (s >>= 16));   O2 ^= SBA(SBY, ((s)          + 4));

#define G(I1, I2, O1, O2)                                             \
        F(I1, O1, O2, sb1, sb0) F(I2, O1, O2, sb3, sb2)

#define H G(r1, r2, l1, l2); G(l1, l2, r1, r2)

void
crypt_core_default(uint32_t result[], uint32_t **sb, uint32_t *ktab)
{
	int i, j;
	uint32_t l1, l2, r1, r2, s;
	uint32_t *k;
	uint32_t *sb0, *sb1, *sb2, *sb3;

	sb0 = sb[0];
	sb1 = sb[1];
	sb2 = sb[2];
	sb3 = sb[3];

	l1=l2=r1=r2=0;
	for(j=0; j<25; j++) {
		k = ktab;
		for(i=8; i--; ) {
			H;
		}
		s=l1; l1=r1; r1=s; s=l2; l2=r2; r2=s;
	}

	result[0] = l1;
	result[1] = l2;
	result[2] = r1;
	result[3] = r2;
}
