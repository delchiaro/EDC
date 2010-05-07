#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=
CXX=
FC=
AS=as

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_CONF=Debug
CND_DISTDIR=dist

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=build/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/dbconnection.o \
	${OBJECTDIR}/eibtrace.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/statement.o

# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-L/usr/local/lib -L/usr/lib -L/usr/lib/mysql -leibnetmux -lpth -lzlogger -lm -lmysqld

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	${MAKE}  -f nbproject/Makefile-Debug.mk dist/Debug/GNU-Linux-x86/edc

dist/Debug/GNU-Linux-x86/edc: ${OBJECTFILES}
	${MKDIR} -p dist/Debug/GNU-Linux-x86
	${LINK.c} -L/usr/lib/mysql -lmysqlclient -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/edc ${OBJECTFILES} ${LDLIBSOPTIONS} 

${OBJECTDIR}/dbconnection.o: nbproject/Makefile-${CND_CONF}.mk dbconnection.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -g -I/usr/local/include/eibnetmux -I/usr/include/mysql -I/usr/include -Imylib -MMD -MP -MF $@.d -o ${OBJECTDIR}/dbconnection.o dbconnection.c

${OBJECTDIR}/eibtrace.o: nbproject/Makefile-${CND_CONF}.mk eibtrace.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -g -I/usr/local/include/eibnetmux -I/usr/include/mysql -I/usr/include -Imylib -MMD -MP -MF $@.d -o ${OBJECTDIR}/eibtrace.o eibtrace.c

${OBJECTDIR}/main.o: nbproject/Makefile-${CND_CONF}.mk main.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -g -I/usr/local/include/eibnetmux -I/usr/include/mysql -I/usr/include -Imylib -MMD -MP -MF $@.d -o ${OBJECTDIR}/main.o main.c

${OBJECTDIR}/statement.o: nbproject/Makefile-${CND_CONF}.mk statement.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -g -I/usr/local/include/eibnetmux -I/usr/include/mysql -I/usr/include -Imylib -MMD -MP -MF $@.d -o ${OBJECTDIR}/statement.o statement.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r build/Debug
	${RM} dist/Debug/GNU-Linux-x86/edc

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
