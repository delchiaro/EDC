#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Werror -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

plugindir = @PLUGINDIR@

plugin_LTLIBRARIES = app_udp.la
app_udp_la_SOURCES = app_udp.c
app_udp_la_LDFLAGS = -module -avoid-version
app_udp_la_LIBADD = 

pkginclude_HEADERS = 
noinst_HEADERS = 

man_MANS = 

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS)
