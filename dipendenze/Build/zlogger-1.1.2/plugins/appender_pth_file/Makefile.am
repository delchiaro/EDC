#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Werror -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

plugindir = @PLUGINDIR@

plugin_LTLIBRARIES = app_pth_file.la
app_pth_file_la_SOURCES = app_pth_file.c
app_pth_file_la_LDFLAGS = -module -avoid-version
app_pth_file_la_LIBADD = 

pkginclude_HEADERS = 
noinst_HEADERS = 

man_MANS = 

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS)
