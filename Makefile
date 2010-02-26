# Makefile for utripper
# $Date: 2002/11/03 22:44:42 $

DEFINES = -DINLINE=inline

# If you use system-supplied regex library, uncomment this
#DEFINES += -DUSE_SYSTEM_REGEX

# If you want to compile glibc regex functions, uncomment this line
EXTRAOBJS += regex.o

# if you don't have an MMX cpu, comment this line out
DEFINES += -DHAVE_MMX

# if you don't have an SSE cpu, comment this line out
DEFINES += -DHAVE_SSE

# if you use smaller cache machine (e.g. Coppermine Celeron)
# uncomment this line
#DEFINES += -DSMALL_CACHE

ASMDEFS = $(DEFINES)

CFLAGS = -O3 -finline-functions -fomit-frame-pointer -Wall -msse3
#CFLAGS = -O2 -pg -finline-functions -Wall

ASMSRC = crypt_core_mmx.S
ASMOBJ = $(ASMSRC:.S=.o)
EXTRAOBJS += $(ASMOBJ)

MAINOBJ = ut-unix.o

CC = gcc
CPP = cpp

.PHONY:	all dist clean

all: utripper

.c.o	:
	$(CC) $(CFLAGS) $(DEFINES) -c $<

.S.o	:
	$(CC) -E $(ASMDEFS) $< > tmp.s
	$(CC) $(CFLAGS) -c tmp.s -o $@
	rm tmp.s

utripper : $(MAINOBJ) utripper.o crypt_util.o $(EXTRAOBJS)
	$(CC) $(CFLAGS) -o $@ utripper.o $(MAINOBJ) crypt_util.o $(EXTRAOBJS) $(LIBS)

ut-unix.o : ut-unix.c ut.h crypt_util.h
utripper.o : utripper.c ut.h crypt_util.h
crypt_util.o : crypt_util.c crypt_util.h crypt_core32.c crypt_core64.c

crypttest: crypttest.c crypt_util.o $(EXTRAOBJS)
	$(CC) -DHAVE_MMX -O -o $@ crypttest.c crypt_util.o $(EXTRAOBJS) -lcrypt

regex.o : regex.c regex.h
	$(CC) $(CFLAGS) -DSTDC_HEADERS -I. -c regex.c

crypt_core_mmx.o : crypt_core_mmx.S

dist :
	nkf -sc README.txt > README_sjis.txt
	cd .. ; zip -9 utripper_`date +%Y%m%d`.zip utripper/Makefile utripper/Makefile.mingw utripper/README.txt utripper/README_sjis.txt utripper/crypt_util.c utripper/crypt_util.h utripper/crypt_core32.c utripper/crypt_core64.c utripper/trip.pl utripper/8to10.pl utripper/utripper.c utripper/ut-unix.c utripper/ut.h utripper/crypt_core_mmx.S utripper/regex.c utripper/regex.h utripper/ut-win32.c

clean:
	rm -f *.o utripper crypttest *~
