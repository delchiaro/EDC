#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Werror -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

bin_PROGRAMS = zlogger_udp_receiver
zlogger_udp_receiver_SOURCES = zlogger_udp_receiver.c

pkginclude_HEADERS = 
noinst_HEADERS = 

man_MANS = 

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS)
