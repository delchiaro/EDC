#
# eibnetmux - eibnet/ip multiplexer
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall -Wstrict-prototypes

MAINTAINERCLEANFILES    = Makefile.in

lib_LTLIBRARIES = libeibnetmux.la
libeibnetmux_la_SOURCES = auth.c connection.c geterror.c init.c \
                          internal.c pth_internal.c search.c \
                          mgmt.c monitor.c read.c write.c vars.private.c \
                          conversions.c helper.c \
                          L7_connect.c L7_memory.c L7_reset.c L7_internal.c
libeibnetmux_la_LDFLAGS = -version-info 2:0:0 @LIBPTH@ @LIBPOLARSSL@

pkginclude_HEADERS = enmx_lib.h
noinst_HEADERS = enmx_lib.private.h

if WITH_AUTHENTICATION
AUTH_MANUAL = 
else
AUTH_MANUAL = 
endif
man_MANS = man/enmx_auth.3 man/enmx_close.3 man/enmx_errormessage.3 man/enmx_geterror.3 \
           man/enmx_init.3 man/enmx_monitor.3 man/enmx_open.3 man/enmx_pth_open.3 man/enmx_read.3 \
           man/enmx_write.3 \
           man/enmx_mgmt_connect.3 man/enmx_mgmt_disconnect.3 \
           man/enmx_mgmt_getloglevel.3 man/enmx_mgmt_setloglevel.3 \
           man/enmx_mgmt_getaccessblock.3 man/enmx_mgmt_setaccessblock.3 \
           man/enmx_mgmt_getstatus.3 man/enmx_mgmt_releasestatus.3 \
           man/enmx_eis2value.3 man/enmx_frame2value.3 man/enmx_value2eis.3 \
           man/enmx_getaddress.3 man/enmx_getgroup.3 man/enmx_gethost.3 \
           man/enmx_getservers.3 man/enmx_pth_getservers.3 man/enmx_releaseservers.3 \
           man/enmx_L7_connect.3 man/enmx_L7_disconnect.3 man/enmx_L7_reset.3 man/enmx_L7_readmemory.3

# we want these in the dist tarball
EXTRA_DIST = $(man_MANS)
