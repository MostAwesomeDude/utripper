/*
 * ut-win32.c
 * $Date: 2002/11/03 20:01:52 $
 */

#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

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
	time_t t;
	time(&t);
	return (double)t;
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
		"-sNUM\t: random number seed\n"
		"-pNUM\t: priority (0 to 2, larger number is lower priority)\n"
		"-lFILENAME : log filename\n"
		"-r\t: turn on basic regular expression search\n"
		"-e\t: turn on extended regular expression search\n"
		"-n\t: random search (default: sequential search)\n"
		);
	exit(1);
}


void
parse_option(int *argc, char **argv[])
{
	char *optarg;
	int c, use_next, opt_used;

	*argc -= 1;
	*argv += 1;

	if (*argc < 1)
		return;

	while (*argc > 0 && (**argv)[0] == '-') {
		c = (**argv)[1];
		use_next = 0;
		opt_used = 0;

		if ((**argv)[2]) {
			optarg = **argv + 2;
		} else if (*argc > 1) {
			optarg = (*argv)[1];
			use_next = 1;
		} else {
			optarg = NULL;
		}

		switch (c) {
		case 'i':
			tripflags |= FLAG_IGNORE_CASE;
			break;
		case 's':
			if (!optarg)
				usage();
			rseed = strtol(optarg, NULL, 10);
			opt_used = 1;
			break;
		case 'p':
			if (!optarg)
				usage();
			opt_used = 1;
			{
				HANDLE hProcess;
				DWORD dwPriority;

				hProcess = GetCurrentProcess();
				switch (strtol(optarg, NULL, 10)) {
				case 0:
					dwPriority = HIGH_PRIORITY_CLASS;
					break;
				case 1:
					dwPriority = NORMAL_PRIORITY_CLASS;
					break;
				case 2:
					dwPriority = IDLE_PRIORITY_CLASS;
					break;
				default:
					dwPriority = NORMAL_PRIORITY_CLASS;
				}
				SetPriorityClass(hProcess, dwPriority);
			}
			break;
		case 'l':
			if (!optarg)
				usage();
			logfile = optarg;
			opt_used = 1;
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

		*argc -= (1 + use_next * opt_used);
		*argv += (1 + use_next * opt_used);
	}
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
