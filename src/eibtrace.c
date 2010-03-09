
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
//#include "../mylib/mylib.h"
#include "mylib.h"



#define EIB_DAF_GROUP                   0x80
#define A_RESPONSE_VALUE_REQ            0x0040
#define A_WRITE_VALUE_REQ               0x0080


// Global variables
ENMX_HANDLE     sock_con = 0;
unsigned char   conn_state = 0;


#include "eibtrace.h"


static void Usage( char *progname )
{
    fprintf( stderr, "Usage: %s [options] [hostname[:port]]\n"
                     "where:\n"
                     "  hostname[:port]                      defines eibnetmux server with default port of 4390\n"
                     "\n"
                     "options:\n"
                     "  -u user                              name of user                           default: -\n"
                     "  -c count                             stop after count number of requests    default: endless\n"
                     "  -q                                   no verbose output (default: no)\n"
                     "\n", basename( progname ));
}




/*
 * Return representation of physical device KNX address as string
 */
static char *knx_physical( uint16_t phy_addr )
{
        static char     textual[64];
        int             area;
        int             line;
        int             device;

        phy_addr = ntohs( phy_addr );

        area = (phy_addr & 0xf000) >> 12;
        line = (phy_addr & 0x0f00) >> 8;
        device = phy_addr & 0x00ff;

        sprintf( textual, "%d.%d.%d", area, line, device );
        return( textual );
}


/*
 * Return representation of logical KNX group address as string
 */
static char *knx_group( uint16_t grp_addr )
{
        static char     textual[64];
        int             top;
        int             sub;
        int             group;

        grp_addr = ntohs( grp_addr );

        top = (grp_addr & 0x7800) >> 11;
        sub = (grp_addr & 0x0700) >> 8;
        group = grp_addr & 0x00ff;
        sprintf( textual, "%d/%d/%d", top, sub, group );
        return( textual );
}


