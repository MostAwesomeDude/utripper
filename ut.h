/*
 * ut.h
 * $Date: 2002/11/03 03:21:41 $
 */

#ifndef _UT_H
#define _UT_H

#define DEFAULT_LOGFILE_NAME "utripper.log"

/* tripper global flags and bit definition */
extern unsigned long tripflags;

/* tripflags: search option */
#define FLAG_IGNORE_CASE	(0x00000001)

/* tripflags: regular expression */
#define FLAG_USE_REGEX		(0x00000100)
#define FLAG_USE_EXTENDED	(0x00000200)

/* tripflags: searching method */
#define FLAG_RANDOM		(0x00010000)

/* trip precision (10 or 8) */
#ifndef PRECISION
#define PRECISION		10
#endif

#define N_CS 94
extern unsigned char cs[N_CS];

extern double current_time(void);

extern void display_status(unsigned long found, unsigned long mloop, unsigned long loop, double t);
void display_match(char *key, char *trip, unsigned long found);

extern int log_open(void);
extern void log_close(void);
extern void log_out(const char *format, ...);

extern void setup_event(void);
extern void exit_interrupt(void);
extern void exit_utripper(const char *format, ...);

extern void utrip(int ntrips, unsigned char **srch);

#endif
