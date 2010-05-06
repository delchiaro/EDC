/* 
 * File:   eibtrace.h
 * Author: nagash
 *
 * Created on 6 maggio 2010, 19.03
 */

#ifndef _EIBTRACE_H
#define	_EIBTRACE_H

#ifdef	__cplusplus
extern "C" {
#endif

    #ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <eibnetmux/enmx_lib.h>

#define EIB_DAF_GROUP                   0x80
#define A_RESPONSE_VALUE_REQ            0x0040
#define A_WRITE_VALUE_REQ               0x0080


// Global variables

void     Usage( char *progname );
char     *knx_physical( uint16_t phy_addr );
char     *knx_group( uint16_t grp_addr );

/*
 * EIB request frame
 */
typedef struct __attribute__((packed)) {
        uint8_t  code;
        uint8_t  zero;
        uint8_t  ctrl;
        uint8_t  ntwrk;
        uint16_t saddr;
        uint16_t daddr;
        uint8_t  length;
        uint8_t  tpci;
        uint8_t  apci;
        uint8_t  data[16];
} CEMIFRAME;


#ifdef	__cplusplus
}
#endif

#endif	/* _EIBTRACE_H */

