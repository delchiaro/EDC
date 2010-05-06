#include "eibtrace.h"




void Usage( char *progname )
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
char *knx_physical( uint16_t phy_addr )
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
char *knx_group( uint16_t grp_addr )
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


//END OF EIBTRACE.C

