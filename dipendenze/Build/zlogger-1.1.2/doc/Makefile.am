#
# zLogger - logging library for C
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES    = Makefile.in clib.doxyfile dev.doxyfile devdoc userdoc doxy.log

EXTRA_DIST = clib.doxyfile.in dev.doxyfile.in \
			 footer.html header.html maindoc_en.txt style_en.css \
			 images/zlogger_logo.png

if DOXYGEN_AVAILABLE
C_DOC = c_doc
else
C_DOC = 
endif

all: $(C_DOC)

TOP_DOCDIR = `cd @top_srcdir@/doc && pwd`

c_doc:
	doxygen clib.doxyfile
	tar cjf userdoc.tar.bz2 userdoc/html/*
	@rm -rf userdoc
	@echo "=============================================================================="
	@echo "=====                                                                        ="
	@echo "===== zLogger library documentation put in                                   ="
	@echo "===== $(TOP_DOCDIR)/userdoc.tar.bz2"
	@echo "=====                                                                        ="
	@echo "=============================================================================="

.PHONY: c_doc
