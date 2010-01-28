#
# zLogger - logging library for C
# plugins
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4

if WITH_PTH_PLUGINS
subdirs = appender_pth_file appender_pth_udp
endif
SUBDIRS = appender_null appender_udp format_zlog $(subdirs)
