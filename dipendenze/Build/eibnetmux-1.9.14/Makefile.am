#
# eibnetmux - eibnet/ip multiplexer
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure config.h.in eibnetmux-*.*.tar.gz

if MINIMAL_BUILD
BUILDDIRS = 
else
BUILDDIRS = eibnetmux webmon
endif

SUBDIRS = client_lib $(BUILDDIRS) doc

EXTRA_DIST = Changelog INSTALL README ToDo
