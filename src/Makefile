# C and C++ compilers
CC = gcc
CXX = g++

# Use these settings if you have mysql_config.  Note that if you have
# multiple installations of MySQL, you can compile with the client
# library from any of them by changing the value of MYSQL_CONFIG to
# the full pathname of the version of mysql_config that you want to
# use.
MYSQL_CONFIG = mysql_config
INCLUDES = ${shell $(MYSQL_CONFIG) --include} -I/usr/local/include
LIBS = ${shell $(MYSQL_CONFIG) --libs} -L/usr/local/lib -lpth -leibnetmux -lm -lzlogger
EMBLIBS = ${shell $(MYSQL_CONFIG) --libmysqld-libs}

# Use these settings if you don't have mysql_config; modify as necessary
#INCLUDES = -I/usr/include/mysql #
#LIBS = -L/usr/lib/mysql -lmysqlclient #-lm -lsocket -lnsl
#EMBLIBS = -L/usr/lib/mysql -lmysqld #-lm -lsocket -lnsl

ALL_PROGRAMS = edc

default:: $(ALL_PROGRAMS)


all:: $(ALL_PROGRAMS)

.c.o:
	$(CC) -c $(INCLUDES) $<


# Prepared-statement demonstration


edc.o: edc.c \
	prepared.c \
	eibtrace.c \
	process_prepared_statement.c \
	process_result_set.c
edc:: edc.o 
	$(CXX) -o $@ edc.o libmy.a $(LIBS)


clean::
	rm -f $(ALL_PROGRAMS) *.o
