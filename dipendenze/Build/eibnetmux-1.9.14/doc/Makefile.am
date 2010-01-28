#
# eibnetmux - eibnet/ip multiplexer
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES    = Makefile.in clib.doxyfile dev.doxyfile devdoc userdoc doxy.log

EXTRA_DIST = clib.doxyfile.in dev.doxyfile.in \
			 footer.html header.html maindoc_en.txt style_en.css \
			 images/eibnetmux_logo.png

if DOXYGEN_AVAILABLE
C_DOC = c_doc
else
C_DOC = 
endif

if PHPDOC_AVAILABLE
PHP_DOC = php_doc
else
PHP_DOC = 
endif

all: $(C_DOC) $(PHP_DOC)

TOP_DOCDIR = `cd @top_srcdir@/doc && pwd`

c_doc:
	doxygen clib.doxyfile
	tar cjf userdoc.tar.bz2 userdoc/html/*
	@rm -rf userdoc
	@echo "=============================================================================="
	@echo "=====                                                                        ="
	@echo "===== C client library documentation put in                                  ="
	@echo "===== $(TOP_DOCDIR)/userdoc.tar.bz2"
	@echo "=====                                                                        ="
	@echo "=============================================================================="

php_doc:
	phpdoc -q -ti "eibnetmux PHP client library" -f ../client_lib/php/eibnetmux.php -t php_doc -s -o "HTML:Smarty:HandS"
	cp images/eibnetmux_logo.png php_doc/media/logo.png
	tar cjf php_doc.tar.bz2 php_doc/*
	@rm -rf php_doc
	@echo "=============================================================================="
	@echo "=====                                                                        ="
	@echo "===== PHP client library documentation put in                                ="
	@echo "===== $(TOP_DOCDIR)/php_doc.tar.bz2"
	@echo "=====                                                                        ="
	@echo "=============================================================================="

.PHONY: c_doc php_doc
