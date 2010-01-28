#
# eibnetmux - eibnet/ip multiplexer
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES    = Makefile.in

if PHP_CLIENT
ADDITIONALDIRS = php
else
ADDITIONALDIRS = 
endif

SUBDIRS = c c/pkgconfig $(ADDITIONALDIRS)

EXTRA_DIST = Changelog
