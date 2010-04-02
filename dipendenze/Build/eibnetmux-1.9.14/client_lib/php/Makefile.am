#
# eibnetmux - eibnet/ip multiplexer
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST = eibnetmux.php

# settings
SRCDIR = .
PHP_INSTALLDIR ?= /usr/share/php5
INSTALL= install

clean:

install:
	$(INSTALL) -d -v $(prefix)/$(PHP_INSTALLDIR)
	$(INSTALL) -c -m 644 -v $(SRCDIR)/eibnetmux.php $(prefix)/$(PHP_INSTALLDIR)/eibnetmux.php
