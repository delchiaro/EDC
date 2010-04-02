#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Werror -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

plugindir = @PLUGINDIR@

plugin_LTLIBRARIES = fmt_zlog.la
fmt_zlog_la_SOURCES = fmt_zlog.c
fmt_zlog_la_LDFLAGS = -module -avoid-version
fmt_zlog_la_LIBADD = 

pkginclude_HEADERS = 
noinst_HEADERS = 

man_MANS = 

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS)
