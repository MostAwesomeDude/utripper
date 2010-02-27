/*
  utripper.c
  www.2ch.net `trip' calculator
  $Date: 2002/11/03 20:02:41 $
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include "ut.h"
#include "crypt_util.h"

/* all character set (the first 64 characters are also valid for salt) */
unsigned char cs[N_CS] = {
	/* numeric 0-9 (10) */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	/* ALPHABET A-Z (26) */
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
	0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
	0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
	/* alphabet a-z (26) */
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
	0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
	0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
	/* other printables (32) */
	0x2e, 0x2f,		/* "./" */
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
	0x2b, 0x2c, 0x2d, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x7b, 0x7c, 0x7d, 0x7e
};

/* XXX These numbers are index of cs[] array */
#define INDEX_DQUOTE	(65)
#define INDEX_LOWER	(79)
#define INDEX_GREATER	(81)

#if 0
/* might be used... */
static unsigned char hkana[] = {
	/* hankaku kana 63 */
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
	0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
	0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
	0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
	0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2,
	0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
	0xdd, 0xde, 0xdf
};
#endif

/*
 * characters translation table for salt (2ch-specific)
 *
 * 0x3a - 0x40 -> 'A' - 'G'
 * 0x5b - 0x60 -> 'a' - 'f'
 */
static char saltchar[] = {
/*	+0  +1	 +2   +3   +4	+5   +6	  +7
	+8  +9	 +A   +B   +C	+D   +E	  +F */
	/* 0x00 */
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	/* 0x10 */
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	/* 0x20 */
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '/', 
	/* 0x30 */
	'0', '1', '2', '3', '4', '5', '6', '7', 
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 
	/* 0x40 */
	'G', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 
	/* 0x50 */
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 
	'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 
	/* 0x60 */
	'f', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 
	'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 
	/* 0x70 */
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 
	'x', 'y', 'z', '.', '.', '.', '.', '.', 
	/* 0x80 - 0xff */
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.', 
	'.', '.', '.', '.', '.', '.', '.', '.'
};


/* used for string match */
static char bm_skip[256];
static int bm_len;

/* used by timer */
static double start_time;

/* flag bitmap for already searched salts */
static unsigned char salt_used[N_CS * N_CS / 8];

/* current search key */
static int currentkey[6];

unsigned long tripflags;

/* prototypes */
static void start_timer(void);


static void
start_timer()
{
	start_time = current_time();
}


static double
get_timer()
{
	return current_time() - start_time;
}


/* exit interrupt handler */
void
exit_interrupt()
{
	char buf[256];

	snprintf(buf, 256, "##### End (%.1fsec) #####\n", get_timer());
	log_out(buf);
	log_close();
	exit_utripper("");
}


/* make salt randomly */
static void
make_salt(char *key, char *salt)
{
	static int cnt;
	static int last;
	int i, found;
	int rawsalt;
	unsigned int mask;
	unsigned char *flagp;

	/* shut up compiler warning */
	rawsalt = -1;

	if (cnt < (N_CS * N_CS * 3 / 4)) {
		for (;;) {
			rawsalt = rand() % (N_CS * N_CS); 
			flagp = &salt_used[rawsalt / 8];
			mask = 1 << (rawsalt % 8);
			if ((*flagp & mask) == 0) {
				*flagp |= mask;
				break;
			}
		}
	} else {
		found = 0;
		for (i = last; i < (N_CS * N_CS); i++) {
			flagp = &salt_used[i / 8];
			mask = 1 << (i % 8);
			if ((*flagp & mask) == 0) {
				found = 1;
				last = rawsalt = i;
				*flagp |= mask;
				break;
			}
		}
		if (!found) {
			exit_utripper("Salt exhausted");
			/* NO RETURN */
		}
	}

	cnt++;

	key[1] = cs[rawsalt / N_CS];
	key[2] = cs[rawsalt % N_CS];

	/* get salt from key : 2ch specific */
	salt[0] = saltchar[(int)key[1]];
	salt[1] = saltchar[(int)key[2]];
	salt[2] = 0;

	log_out("##### New SALT= %s #####\n", salt);
}


/* setup BM string search table */
static void
setup_str_match(unsigned char *srch)
{
	int i;

	bm_len = strlen(srch);

	if (bm_len > PRECISION)
		exit_utripper("search string is too long!");

	if (tripflags & FLAG_IGNORE_CASE)
		for (i = 0; i < bm_len; i++)
			srch[i] = toupper(srch[i]);

	for (i = 0; i < 256; i++)
		bm_skip[i] = bm_len;

	for (i = 0; i < bm_len - 1; i++)
		bm_skip[(int)srch[i]] = bm_len - 1 - i;
}


/*
  string match
  based on Boyer-Moore Algorithm
*/
static int
str_match(const unsigned char *trip, const unsigned char *srch)
{
	int i, j, k, c, tail;

	if (bm_len == 1) {
		for (i = 0; i < PRECISION; i++)
			if (trip[i] == srch[0])
				return 1;
	} else {
		i = bm_len - 1;
		tail = srch[i];
		for (; i < PRECISION;) {
			c = trip[i];
			if (c == tail) {
				j = bm_len - 1;
				k = i;
				while (srch[--j] == trip[--k])
					if (j == 0)
						return 1;
			}
			i += bm_skip[c];
		}
	}

	return 0;
}


static int
str_match_icase(const unsigned char *trip, const unsigned char *srch)
{
	int i, j, k, c, tail;

	if (bm_len == 1) {
		for (i = 0; i < PRECISION; i++)
			if (toupper(trip[i]) == srch[0])
				return 1;
	} else {
		i = bm_len - 1;
		tail = srch[i];
		for (; i < PRECISION; ) {
			c = toupper(trip[i]);
			if (c == tail) {
				j = bm_len - 1;
				k = i;
				while (srch[--j] == toupper(trip[--k]))
					if (j == 0)
						return 1;
			}
			i += bm_skip[c];
		}
	}

	return 0;
}


static regex_t re;

/* setup regular expression match */
static void
setup_reg_match(unsigned char *srch)
{
	int ret, cflags;
	char buf[BUFSIZ];

	cflags = REG_NOSUB;

	if (tripflags & FLAG_USE_EXTENDED)
		cflags |= REG_EXTENDED;

	if (tripflags & FLAG_IGNORE_CASE)
		cflags |= REG_ICASE;

	ret = regcomp(&re, srch, cflags);

	if (ret) {
		regerror(ret, &re, buf, BUFSIZ);
		regfree(&re);
		exit_utripper("Regular Expression error:\n%s", buf);
	}
}


/* regular expression match */
static int
reg_match(const unsigned char *trip, const unsigned char *srch)
{
	int ret;

	ret = regexec(&re, trip, 0, 0, 0);
	return ret == 0 ? 1 : 0;
}


int
sequential_next_key(int *current)
{
	int d;

	for (d = 2; ; d++) {
		current[d]++;
		if (current[d] < N_CS)
			break;
		current[d] = 0;
		if (d == 5) {
			/* We're done, try new salt! */
			return 1;
		}
	}
	return 0;
}


int
random_next_key(int *current)
{
	static int count;
	int d;

	for (d = 2; d < 6; d++)
		current[d] = rand() % N_CS;

	/* renew salt for 100000 trips */
	if (++count >= 1000000) {
		count = 0;
		return 1;
	}
	return 0;
}


static unsigned char s_trip[N_CS * N_CS][16];

/* search keys for trip */
void
utrip(int ntrips, unsigned char **srch)
{
	unsigned char key[9];
	unsigned char salt[3];
	int *current = currentkey;
	unsigned long found, mloop, loop;
	struct crypt_state crs;
	int i;
	double last_time, curr_time;

	void (*setup_match)(unsigned char *srch);
	int (*match)(const unsigned char *trip, const unsigned char *srch);
	int (*next_key)(int *current);

	crypt_init(&crs);

	if (tripflags & FLAG_USE_REGEX) {
		setup_match = setup_reg_match;
		match = reg_match;
	} else if (tripflags & FLAG_IGNORE_CASE) {
		setup_match = setup_str_match;
		match = str_match_icase;
	} else {
		setup_match = setup_str_match;
		match = str_match;
	}

	if (tripflags & FLAG_RANDOM) {
		next_key = random_next_key;
		crs.sequential = 0;
	} else {
		next_key = sequential_next_key;
		crs.sequential = 1;
	}

	if (log_open())
		exit_utripper("Log open error!");

	log_out("##### Start : target=%s #####\n", srch[0]);

	setup_match(srch[0]);


	/* guard against using '"' '<' '>' for salt */
	for (i = 0; i < N_CS; i++) {
		salt_used[(INDEX_DQUOTE * N_CS + i) / 8] |=
			(1 << ((INDEX_DQUOTE * N_CS + i) % 8));
		salt_used[(INDEX_LOWER * N_CS + i) / 8] |= 
			(1 << ((INDEX_LOWER * N_CS + i) % 8));
		salt_used[(INDEX_GREATER * N_CS + i) / 8] |=
			(1 << ((INDEX_GREATER * N_CS + i) % 8));

		salt_used[(INDEX_DQUOTE + N_CS * i) / 8] |=
			(1 << ((INDEX_DQUOTE + N_CS * i) % 8));
		salt_used[(INDEX_LOWER + N_CS * i) / 8] |=
			(1 << ((INDEX_LOWER + N_CS * i) % 8));
		salt_used[(INDEX_GREATER + N_CS * i) / 8] |=
			(1 << ((INDEX_GREATER + N_CS * i) % 8));
	}

	current[0] = current[1] = current[2] =
	current[3] = current[4] = current[5] = 0;
#if 0
	current[0] = current[1] = current[2] = 0;
	current[3] = rand() % N_CS;
	current[4] = rand() % N_CS;
	current[5] = rand() % N_CS;
#endif

	mloop = loop = found = 0;
	memset(key, 0, sizeof(key));
	memset(s_trip, 0, sizeof(s_trip));
	make_salt(key, salt);

	start_timer();
	last_time = get_timer();
	setup_event();

	/* main loop */
	for (;;) {
		key[0] = cs[current[5]];
		/* 1,2 are fixed (salt) */
		key[3] = cs[current[4]];
		key[4] = cs[current[3]];
		key[5] = cs[current[2]];
		key[6] = cs[0];
		key[7] = cs[0];

		rcrypt(&crs, salt, key, s_trip);

		for (i = 0; i < N_CS * N_CS; i++) {
			if (match(&s_trip[i][13 - PRECISION], srch[0])) {
				found++;
#ifdef DEBUG
				printf("Trip: %s Salt: %\n", trip, salt);
#endif
				key[6] = cs[i / N_CS];
				key[7] = cs[i % N_CS];
				display_match(key, &s_trip[i][13 - PRECISION], found);
				log_out("%s : #%s (%ld)\n",
					&s_trip[i][13 - PRECISION],
					key, found);
			}
		}

		loop += N_CS * N_CS;

		if (loop >= 100000) {
			mloop += (loop / 100000);
			loop %= 100000;
			curr_time = get_timer();
			if (curr_time > last_time + 3.0) {
				display_status(found, mloop, loop, get_timer());
				last_time = curr_time;
			}
		}

		if (next_key(current))
			make_salt(key, salt);
	}
}
