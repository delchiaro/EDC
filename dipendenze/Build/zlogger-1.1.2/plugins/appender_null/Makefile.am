#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Werror -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

plugindir = @PLUGINDIR@

plugin_LTLIBRARIES = app_null.la
app_null_la_SOURCES = app_null.c
app_null_la_LDFLAGS = -module -avoid-version
app_null_la_LIBADD = 

pkginclude_HEADERS = 
noinst_HEADERS = 

man_MANS = 

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS)
