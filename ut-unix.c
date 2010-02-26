/*
 * ut-unix.c
 * $Date: 2002/11/03 20:01:52 $
 */

#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "ut.h"
#include "crypt_util.h"


/* log filename & fp */
static char *logfile;
static FILE *logfp;

static unsigned int rseed;


static void
sigint_handler(int sig)
{
	exit_interrupt();
}


void
setup_event()
{
	signal(SIGINT, sigint_handler);
}


double
current_time()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (tv.tv_usec / 1.0e6);
}


/*
 * @found: trips found
 * @mloop: the number of loop / 100000
 * @loop: the number of loop % 100000
 * @t: time
 */
void
display_status(unsigned long found, unsigned long mloop, unsigned long loop, double t)
{
	double loops = mloop * 1.0e5 + loop;

	if (t < 0.1)
		return;

	fprintf(stderr,
		"Found %lu (in %.0f %.2fs %dtrips/s)    \r",
		found, loops, t,
		(int)(loops / t));
}


void
display_match(char *key, char *trip, unsigned long found)
{
	/* XXX */
	printf("                                                                              \r");
	printf("%s : #%s (%lu)\n", trip, key, found);
}


static void
usage()
{
	fprintf(stderr, "Usage:\n"
		"utripper [options] searchstring\n"
		"-i\t: ignore case\n"
		"-s num\t: random number seed\n"
#ifdef __CYGWIN__
		"-p num\t: priority (-20 to 20, larger number is lower priority)\n"
#endif
		"-l filename : log filename\n"
		"-r\t: turn on basic regular expression search\n"
		"-e\t: turn on extended regular expression search\n"
		"-n\t: random search (default: sequential search)\n"
		);
	exit(1);
}


void
parse_option(int *argc, char ***argv)
{
	extern char *optarg;
	extern int optind;
	int c;

	while ((c = getopt(*argc, *argv, "is:l:renp:")) != -1) {
		switch (c) {
		case 'i':
			tripflags |= FLAG_IGNORE_CASE;
			break;
		case 's':
			rseed = strtol(optarg, NULL, 10);
			break;
#ifndef __CYGWIN__
		case 'p':
			if (setpriority(PRIO_PROCESS, 0, strtol(optarg, NULL, 10)) < 0)
				exit_utripper("setpriority failed");
			break;
#endif
		case 'l':
			logfile = optarg;
			break;
		case 'r':
			tripflags |= FLAG_USE_REGEX;
			break;

		case 'e':
			tripflags |= (FLAG_USE_REGEX | FLAG_USE_EXTENDED);
			break;
		case 'n':
			tripflags |= FLAG_RANDOM;
			break;
		default:
			usage();
		}
	}

	*argc -= optind;
	*argv += optind;
}


int
main(int argc, char **argv)
{
	time_t t;

	logfile = DEFAULT_LOGFILE_NAME;
	time(&t);
	rseed = (unsigned int)t;

	parse_option(&argc, &argv);

	if (argc < 1)
		usage();

	srand(rseed);
	utrip(argc, (unsigned char **)argv);

	return 0;
}


int
log_open()
{
	
	if ((logfp = fopen(logfile, "a")) == NULL)
		exit_utripper("log file open error!");

	return 0;
}


void
log_close()
{
	if (logfp)
		fclose(logfp);
}


void
log_out(const char *format, ...)
{
	va_list ap;

	if (logfp) {
		va_start(ap, format);
		vfprintf(logfp, format, ap);
		va_end(ap);
		fflush(logfp);
	}
}


void exit_utripper(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	exit(0);
}
