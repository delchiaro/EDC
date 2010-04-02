#
# eibnetmux - eibnet/ip multiplexer
#

AUTOMAKE_OPTIONS = foreign
LDADD =    @LIBPTH@ @LIBZLOGGER_LIBS@ @LIBPOLARSSL@
AM_CFLAGS = -Wall -Wstrict-prototypes -O0 -g
if WITH_AUTHENTICATION
ADDONS = eibnetmux_hash eibnetmux_dhm
eibnetmux_hash_SOURCES = hasher.c
eibnetmux_dhm_SOURCES = dhm_genprime.c
EXTRA_PROGRAMS = eibnetmux_hash eibnetmux_dhm
else
ADDONS = 
endif
bin_PROGRAMS = eibnetmux $(ADDONS)
eibnetmux_SOURCES = main.c config.c log.c network.c util.c \
					client.c common.c eibnetip.c server.c \
					socketserver.c eibdserver.c

pkginclude_HEADERS = include/eibnetip.h include/socketserver.h

noinst_HEADERS = include/declarations.h include/eibnetip_private.h eibnetmux.h \
		 include/log.h include/socketserver_private.h include/eibdserver_private.h \
		 include/types.h include/util.h include/eibtypes.h

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure config.h.in

# man page
if WITH_AUTHENTICATION
AUTH_MANUAL = man/eibnetmux_dhm.1 man/eibnetmux_hash.1
else
AUTH_MANUAL = 
endif
man_MANS = man/eibnetmux.1 man/eibnetmux_security.5 $(AUTH_MANUAL)

# we want these in the dist tarball
EXTRA_DIST = BUGS TODO $(man_MANS)
