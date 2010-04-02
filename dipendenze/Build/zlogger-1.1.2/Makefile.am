#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Werror -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

lib_LTLIBRARIES = libzlogger.la
libzlogger_la_SOURCES = log.c logger.c geterror.c format.c appender.c plugin.c \
                          app_file.c app_syslog.c app_ring.c \
                          ringdump.c util.c dump_structures.c
libzlogger_la_LDFLAGS = -version-info 1:0:0
libzlogger_la_LIBADD = -ldl 

pkginclude_HEADERS = zlogger.h
noinst_HEADERS = zlogger.private.h

man_MANS = 

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS) INSTALL README ToDo

if HAVE_PLUGINS
subdirs_1 = plugins
endif
if HAVE_UTILITIES
subdirs_2 = utilities
endif
SUBDIRS = doc pkgconfig $(subdirs_1) $(subdirs_2)

dist-hook:
	(cd samples;make dist)
	mkdir $(distdir)/samples
	mv samples/zlogger-`grep AC_INIT configure.in | sed -e 's/.*[^,]*,\([^)]*\).*/\1/'`.tar.gz $(distdir)/samples/zloggersamples-`grep AC_INIT samples/configure.in | sed -e 's/.*[^,]*,\([^)]*\).*/\1/'`.tar.gz
