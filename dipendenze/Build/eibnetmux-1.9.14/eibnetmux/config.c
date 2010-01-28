/*
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2009 Urs Zurbuchen <going_nuts@users.sourceforge.net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * configuration is read from the command line
 * usage is:
 *      eibnetmux [options] [hostname[:port]]
 * 
 * where:
 * hostname[:port]                      defines remote eibnet/ip tunneling server with default port of 3671
 * 
 * options:
 * <client services>
 * -s --eib_server[=ip:port]            activate eibnet/ip server       default: no
 * -t --tcp_server[=ip:port]            activate tcp server             default: no
 * -u --unix_server                     activate unix socket server     default: no
 * -e --eibd_server[=ip:port]           activate eibd server            default: no
 * 
 *    --maxsocketclients=maximum        set maximum number of socket clients
 *                                                                      default: 5
 * 
 * <logging>
 * -l --log_level=level                 set log level                   default: none
 *                                      (info, verbose, warning, error, critical, fatal, user, debug,
 *                                       trace client, trace server, trace socketserver, trace eibd, admin)
 * -L --log_dest=(udp: | syslog: | file:)parameter                      default: -
 *                                      set log destination (protocol, host:port, filename)
 * -r --ring_level=level                set levels logged to ring buffer default: 128
 * -R --ring_size=kilobytes             set size of debug ring buffer   default: 32
 * 
 * <behaviour>
 * -d --daemon                          run as daemon                   default: no
 * -i --user=username                   run process as user             default: -
 * -g --group=groupname                            and group            default: -
 * -p --pidfile=file                    file to write pid to            default: -
 * -S --security=file                   file with security restrictions default: -
 * -A --address=ip-address              fixed IP address to use         default: -
 * -T --testmode                        run in testmode without connection to bus, looping back to myself
 *                                                                      default: no
 */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#ifdef WITH_AUTHENTICATION
#include <polarssl/bignum.h>
#include <polarssl/dhm.h>
#endif

#include "eibnetmux.h"
#include "include/log.h"
#include "include/socketserver_private.h"
#include "include/eibnetip_private.h"
#include "include/eibdserver_private.h"


#define  THIS_MODULE    logModuleConfig


/*
 * sections of config file
 */
#define SECTION_NONE            0
#define SECTION_EIBNETIP        1
#define SECTION_CLIENTS         2
#define SECTION_USERS           3
#define SECTION_DHM             4
#define SECTION_AUTHORISATION   5
#define SECTION_EIBD            6
#define SECTION_UNKNOWN        99

typedef struct _sSection {
    char    *name;
    int     id;
} sSection;

sSection    sectionDefinitions[] = {
    { "eibnetip", SECTION_EIBNETIP },
    { "clients", SECTION_CLIENTS },
    { "eibd", SECTION_EIBD },
    { "users", SECTION_USERS },
    { "dhm", SECTION_DHM },
    { "authorisations", SECTION_AUTHORISATION },
    { NULL, SECTION_UNKNOWN },                 // must be last entry
};

/*
 * function declarations
 */
static sSecurityAddr    *configParseAddress( int section, char *txt_type, char *txt_address, char *txt_mask, unsigned int line_nr );
static int              configParseIPPort( char *arg, uint32_t *p_ip, uint16_t *p_port, uint16_t default_port );
static int              parsePrepareLine( char *src, char *buf, unsigned int maxlen, unsigned int line_nr, unsigned int skip );
#ifdef WITH_AUTHENTICATION
static sSecurityUser    *configParseUser( char *txt_name, char *txt_hash, char *txt_level, unsigned int line_nr );
static void             configParseAuthorisation( sSecurityConfig *secConf, char *txt_level, char *txt_name, unsigned int line_nr );
#endif


static struct option option_list[] = {
    { "version",    0, NULL, 'V' },
    { "eib_server", 2, NULL, 's' },
    { "tcp_server", 2, NULL, 't' },
    { "unix_server",2, NULL, 'u' },
    { "eibd_server",2, NULL, 'e' },
    { "daemon",     0, NULL, 'd' },
    { "user",       1, NULL, 'i' },
    { "group",      1, NULL, 'g' },
    { "log_level",  1, NULL, 'l' },
    { "log_dest",   1, NULL, 'L' },
    { "ring_level", 1, NULL, 'r' },
    { "ring_size",  1, NULL, 'R' },
    { "pidfile",    1, NULL, 'p' },
    { "security",   1, NULL, 'S' },
    { "address",    1, NULL, 'A' },
    { "maxsocketclients", 1, NULL, 'c' },
    { "dump",       0, NULL, 'Q' },
    { 0, 0, 0, 0 },                         // must be last entry, marks end of array
};

typedef struct _sFunctions {
    char        *id;
    int         mask;
} sFunctions;

static sFunctions functionAuthorisations[] = {
    { "all", 0xffff },      // must be first entry (authRead + authWrite + authMonitor + authMgmtClient + authMgmtStatus + authMgmtLog + authMgmtConnection + authPhysicalRead + authPhysicalWrite)
    { "read", authRead },
    { "write", authWrite },
    { "monitor", authMonitor },
    { "mgmt_client", authMgmtClient },
    { "mgmt_status", authMgmtStatus },
    { "mgmt_loglevel", authMgmtLog },
    { "mgmt_block", authMgmtBlock },
    { "mgmt_connection", authMgmtConnection },
    { "bus_all", authRead + authWrite + authMonitor + authPassthrough },
    { "bus_group", authRead + authWrite + authMonitor },
    { "bus_physical", authPassthrough },
    { "mgmt_all", authMgmtClient + authMgmtStatus + authMgmtLog },
    { "none", authNone },
    { NULL, 0 }                             // must be last entry, marks end of array
        
};

void Usage( char *progname )
{
    fprintf( stderr, "Usage: %s [options] hostname[:port]\n"
                     "where:\n"
                     "  hostname[:port]                      defines remote eibnet/ip tunneling server with default port of 3671\n"
                     "\n"
                     "options:\n"
                     "<client services>\n"
                     "  -s --eib_server[=ip:port]            activate eibnet/ip server       default: no, port=3671\n"
                     "  -t --tcp_server[=ip:port]            activate tcp server             default: no, port=4390\n"
                     "  -u --unix_server[=path]              activate unix socket server     default: no, path=/tmp/eibnetmux\n"
                     "  -e --eibd_server[=ip:port]           activate eibd server            default: no, port=$$$\n"
                     "\n" 
                     "<logging>\n"
                     "  -l --log_level=level                 set log level                   default: 0\n"
                     "                                       (0=none, 1=info, 2=verbose, 4=warning, 8=error, 16=critical)\n"
                     "                                       (32=fatal 64=user 128=debug 256=trace client 512=trace server)\n"
                     "                                       (1024=trace socketserver 2048=trace EIBD)\n"
                     "  -L --log_dest=udp:host:port          send log to udp receiver host @ port\n"
                     "  -L --log_dest=file:filename          write log to file\n"
                     "  -L --log_dest=syslog:facility        send log to syslog using facility\n"
                     "  -r --ring_level=level                set levels logged to ring buffer default: 128\n"
                     "  -R --ring_size=kilobytes             set size of debug ring buffer   default: 32\n"
                     "\n"
                     "<behaviour>\n"
                     "  -d --daemon                          run as daemon                   default: no\n"
                     "  -i --user=username                   run process as user             default: -\n"
                     "  -g --group=groupname                            and group            default: -\n"
                     "  -p --pidfile=file                    file to write pid to            default: -\n"
                     "  -S --security=file                   file with security restrictions default: -\n"
                     "  -A --address=ip-address              fixed IP address to use         default: -\n"
                     "  -T --testmode                        run in testmode                 default: no\n"
                     "\n", basename( progname ));
}


int ConfigLoad( int argc, char **argv )
{
    int                 c;
    struct passwd       *pwd_entry;
    struct group        *grp_entry;
    struct in_addr      fixed_address;
    
    config.system_name        = strdup( basename( argv[0] ));
    config.hostname           = malloc( 64 );
    gethostname( config.hostname, 64 );
    config.ip                 = 0;
    config.eib_ip             = INADDR_ANY;
    config.tcp_ip             = INADDR_ANY;
    config.eibd_ip            = INADDR_ANY;
    config.eibConnectionType  = eibConEIBNetIPTunnel;
    config.tunnelmode         = 0;
    config.servers            = 0;
    config.daemon             = false;
    config.log_level          = 0;
    config.log_dest           = strdup( "file:/var/log/eibnetmux.log" );
    config.ring_size          = 32;
    config.ring_level         = zlogLevelDebug;
    config.unix_path          = NULL;
    config.pidfile            = NULL;
    config.user               = 0;
    config.group              = 0;
    config.security_file      = NULL;
#ifdef WITH_AUTHENTICATION
    config.dhm                = NULL;
#endif
    config.secEIBnetip        = NULL;
    config.secClients         = NULL;
    config.secEIBD            = NULL;
    config.secUsers           = NULL;
    config.maxAuthEIBnet      = secAddrTypeAllow;
    config.maxAuthEIBD        = secAddrTypeAllow;
    config.defaultAuthEIBnet  = secAddrTypeAllow;
    config.defaultAuthEIBD    = secAddrTypeAllow;
    config.defaultAuthClient  = secAddrTypeAllow;
    config.auth_anonymous     = functionAuthorisations[0].mask;
    config.eibd_anonymous     = 0;
    config.socketclients      = SOCKETS_MAX;
    config.eibdclients        = EIBDCLIENTS_MAX;
    config.dump               = FALSE;
    
    
    opterr = 0;
    while( ( c = getopt_long( argc, argv, "Vs::t::u::e::p:di:g:l:L:r:R:c:S:A:Q", option_list, NULL )) != -1 ) {
        switch( c ) {
            case 'V':
                printf( "eibnetmux version %s", VERSION );
#ifndef WITH_AUTHENTICATION
                printf( " (no authentication support)" );
#endif
                printf( "\n" );
                exit( 0 );
                break;
            case 's':
                config.servers |= SERVER_EIBNET;
                if( configParseIPPort( optarg, &config.eib_ip, &config.eib_port, EIBNETIP_PORT_NUMBER ) != 0 ) {
                    fprintf( stderr, "Invalid IP address specified for -s\n" );
                    return( -1 );
                }
                break;
            case 't':
                config.servers |= SERVER_TCP;
                if( configParseIPPort( optarg, &config.tcp_ip, &config.tcp_port, SOCKET_TCP_PORT ) != 0 ) {
                    fprintf( stderr, "Invalid IP address specified for -t\n" );
                    return( -1 );
                }
                break;
            case 'u':
                if( config.unix_path != NULL ) free( config.unix_path );
                config.servers |= SERVER_UNIX;
                config.unix_path = strdup( (optarg != NULL) ? optarg : SOCKET_UNIX_PATH );
                break;
            case 'e':
                config.servers |= SERVER_EIBD;
                if( configParseIPPort( optarg, &config.eibd_ip, &config.eibd_port, EIBD_TCP_PORT ) != 0 ) {
                    fprintf( stderr, "Invalid IP address specified for -e\n" );
                    return( -1 );
                }
                break;
            case 'c':
                config.socketclients = (optarg != NULL) ? atoi( optarg ) : SOCKETS_MAX;
                break;
            case 'd':
                config.daemon = true;
                break;
            case 'p':
                if( config.pidfile != NULL ) free( config.pidfile );
                config.pidfile = strdup( optarg );
                break;
            case 'i':
                if( isdigit( optarg[0] )) {
                    config.user = atoi( optarg );
                } else {
                    setpwent();
                    pwd_entry = getpwnam( optarg );
                    if( pwd_entry != NULL ) {
                        config.user = pwd_entry->pw_uid;
                    }
                    endpwent();
                }
                break;
            case 'g':
                if( isdigit( optarg[0] )) {
                    config.group = atoi( optarg );
                } else {
                    setgrent();
                    grp_entry = getgrnam( optarg );
                    if( grp_entry != NULL ) {
                        config.group = grp_entry->gr_gid;
                    }
                    endgrent();
                }
                break;
            case 'l':
                config.log_level = atoi( optarg );
                break;
            case 'L':
                if( config.log_dest != NULL ) free( config.log_dest );
                config.log_dest = strdup( optarg );
                break;
            case 'r':
                config.ring_level = atoi( optarg );
                break;
            case 'R':
                config.ring_size = atoi( optarg );
                break;
            case 'S':
                if( config.security_file != NULL ) free( config.security_file );
                config.security_file = strdup( optarg );
                break;
            case 'A':
                if( inet_aton( optarg, &fixed_address ) != 0 ) {
                    fprintf( stderr, "Invalid IP address '%s' (%d - %s)\n", optarg, errno, strerror( errno ));
                } else {
                    fprintf( stderr, "Warning:\n" );
                    fprintf( stderr, "  You are overriding the standard source IP address determination mechanism.\n" );
                    fprintf( stderr, "  No check has been made for the validity of the specified IP address '%s'\n", optarg );
                    fprintf( stderr, "  It is up to you to make sure that this is the correct address.\n" );
                    fprintf( stderr, "  In particular, remember that this address is embedded in EIBnet/IP packets\n" );
                    fprintf( stderr, "  and peers expect your system to listen on it.\n" );
                    config.ip = fixed_address.s_addr;
                } 
                break;
            case 'Q':
                config.dump = TRUE;
                break;
            default:
                return( -1 );
                break;
        }
    }

    if( optind + 1 == argc ) {
        // get remote eibnet/ip tunneling server and setup IP/UDP addressing
        struct hostent  *h;
        uint32_t        *addr;
        char            *ptr;
        
        config.eibConnectionParam = strdup( argv[optind] );

        ptr = strchr( config.eibConnectionParam, ':' );
        if( ptr != NULL ) {
            *ptr++ = '\0';
        }
        
        // !!! use adns
        h = gethostbyname( config.eibConnectionParam );
        if( !h ) {
            logCritical( THIS_MODULE, msgEIBnetBadServer, config.eibConnectionParam );
            return( -1 );
        }
        addr = (uint32_t *)(h->h_addr_list[0]);
        config.eibServerIP = *addr;
        config.eibServerPort = htons( (ptr != NULL) ? atoi( ptr ) : EIBNETIP_PORT_NUMBER );
    } else {
        return( -1 );
    }
    
    return( 0 );
}


/*!
 * \brief parse command line argument for [ address ][ :port ] 
 * 
 * \param       arg                 command line argument
 * \param       p_ip                pointer to variable receiving ip address
 * \param       p_port              pointer to variable receiving port
 * \param       default_port        default port if not defined
 * 
 * \return                          0: ok, <0: error
 */
static int configParseIPPort( char *arg, uint32_t *p_ip, uint16_t *p_port, uint16_t default_port )
{
    char            *ptr = NULL;
    struct in_addr  tmp_addr;
    
    if( arg != NULL ) {
        if( (ptr = strchr( arg, ':' )) != NULL ) {
            *ptr = '\0';
        }
        if( *arg != '\0' ) {
            if( inet_aton( arg, &tmp_addr ) != 0 ) {
                *p_ip = tmp_addr.s_addr;
            } else {
                return( -1 );
            }
        } else {
            *p_ip = INADDR_ANY;
        }
        if( ptr != NULL ) {
            *p_port = atoi( ptr +1 );
            *ptr = ':';
        } else {
            *p_port = default_port;
        }
    } else {
        *p_ip = INADDR_ANY;
        *p_port = default_port;
    }
    return( 0 );
}


/*
 * read line from file
 * - implements fgets() using PTH functions
 * - block only reading thread, not whole process
 */
static char *readLine( char *buf, int maxlen, FILE *fp )
{
    int    fno;
    int    idx;
    int    len;
    
    fno = fileno( fp );
    for( idx = 0; idx < maxlen -1; idx++ ) {
        len = pth_read( fno, &buf[idx], 1 );
        if( len < 0 ) return( NULL );       // error
        if( len == 0 ) {
            buf[idx] = '\0';
            if( idx == 0 ) {
                return( NULL );
            }
            return( buf );
        }
        if( buf[idx] == '\n' ) {
            break;
        }
    }
    buf[++idx] = '\0';
    
    return( buf );
}

/*
 * read security file
 */
sSecurityConfig *configReadSecurity( void )
{
    FILE            *fp;
    char            line[BUFSIZ], buf[BUFSIZ];
    char            sectionname[20];
    char            *src, *dst;
    char            *fld_name;
    char            *fld_type, *fld_address, *fld_mask;
    char            *dhm_file;
    unsigned int    section;
    unsigned int    line_nr;
    unsigned int    error;
    unsigned int    skip;
    int             loop;
    sSecurityConfig *secConf;
    sSecurityAddr   *p_secAddr;
    sSecurityAddr   *p_newAddr;
    sSecurityUser   *p_secUser;
#ifdef WITH_AUTHENTICATION
    char            *fld_value, *fld_level, *fld_hash;
    int             result;
    sSecurityUser   *p_newUser;
#endif
    sAuthorisation  *p_auth;
    
    // open config file
    if( ( fp = fopen( config.security_file, "r" )) == NULL ) {
        logError( THIS_MODULE, msgConfigRead, config.security_file, errno, strerror( errno ));
        return( NULL );
    }
    
    // allocate security config structure
    secConf = allocMemory( THIS_MODULE, sizeof( sSecurityConfig ));
    secConf->secEIBnetip        = NULL;
    secConf->secClients         = NULL;
    secConf->secEIBD            = NULL;
    secConf->secUsers           = NULL;
    secConf->secAuthorisations  = NULL;
    secConf->maxAuthEIBnet      = config.maxAuthEIBnet;
    secConf->maxAuthEIBD        = config.maxAuthEIBD;
    secConf->defaultAuthEIBnet  = secAddrTypeAllow;
    secConf->defaultAuthEIBD    = secAddrTypeAllow;
    secConf->defaultAuthClient  = secAddrTypeAllow;
    secConf->auth_anonymous     = functionAuthorisations[0].mask;
    secConf->eibd_anonymous     = 0;
#ifdef WITH_AUTHENTICATION
    secConf->dhm                = NULL;
#endif
    
    // parse config file
    section = SECTION_UNKNOWN;
    dst = sectionname;
    line_nr = 0;
    error = 0;
    skip = false;
    dhm_file = NULL;
    while( TRUE ) {
        if( readLine( line, BUFSIZ, fp ) == NULL ) {
            /*
            if( feof( fp )) {
                break;
            }
            */
            if( line[0] == '\0' ) {
                break;
            }
            logError( THIS_MODULE, msgConfigRead, config.security_file, errno, strerror( errno ));
            error = 1;
            break;
        }
        
        line_nr++;
        
        skip = parsePrepareLine( line, buf, BUFSIZ, line_nr, skip );
        if( skip == true ) {
            skip = false;
            continue;
        }
        
        // parse line
        for( src = buf; *src; src++ ) {
            if( *src == '[' ) {
                // new section
                section = SECTION_NONE;
                dst = sectionname;
                memset( dst, '\0', sizeof( sectionname ));
                continue;
            }
            switch( section ) {
                case SECTION_NONE:
                    if( *src == ']' ) {
                        *dst = '\0';
                        section = SECTION_UNKNOWN;
                        for( loop = 0; true; loop++ ) {
                            if( sectionDefinitions[loop].name == NULL ) {
                                break;
                            }
                            if( strcasecmp( sectionname, sectionDefinitions[loop].name ) == 0 ) {
                                section = sectionDefinitions[loop].id;
                                break;
                            }
                        }
                        if( section == SECTION_UNKNOWN ) {
                            logWarning( THIS_MODULE, msgConfigSection, line_nr, sectionname );
                        }
                    } else if( strlen( sectionname ) < sizeof( sectionname ) -1 ) {
                        *dst = *src;
                        dst++;
                    }
                    break;
                case SECTION_UNKNOWN:
                    // skip
                    break;
                case SECTION_EIBNETIP:
                    // line format:
                    //      type: address [ / subnet-mask ]
                    // supported types:
                    //      allow
                    //      deny
                    //      read
                    //      write
                    dst = src;
                    fld_type = strsep( &dst, ":" );
                    fld_address = strsep( &dst, "/" ); 
                    fld_mask = dst;
                    if( fld_type == NULL || fld_address == NULL ) {
                        logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'allow | deny | read | write: address [/ subnet-mask]'" );
                        logDebug( THIS_MODULE, "(%s) | (%s)", fld_type, fld_address );
                    } else {
                        if( strcasecmp( fld_type, "maxauth" ) == 0 ) {
                            if( strcasecmp( fld_address, "all" ) == 0 ) {
                                secConf->maxAuthEIBnet = secAddrTypeAllow;
                            } else if( strcasecmp( fld_address, "deny" ) == 0 ) {
                                secConf->maxAuthEIBnet = secAddrTypeDeny;
                            } else if( strcasecmp( fld_address, "read" ) == 0 ) {
                                secConf->maxAuthEIBnet = secAddrTypeRead;
                            } else if( strcasecmp( fld_address, "write" ) == 0 ) {
                                secConf->maxAuthEIBnet = secAddrTypeWrite;
                            } else {
                                logWarning( THIS_MODULE, msgConfigAddrType, line_nr, fld_address );
                                return( NULL );
                            }
                        } else {
                            p_newAddr = configParseAddress( SECTION_EIBNETIP, fld_type, fld_address, fld_mask, line_nr );
                            if( p_newAddr != NULL ) {
                                for( p_secAddr = secConf->secEIBnetip; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
                                    if( p_secAddr->next == NULL )
                                        break;
                                }
                                if( p_secAddr != NULL ) {
                                    p_secAddr->next = p_newAddr;
                                    p_newAddr->rule = p_secAddr->rule + 1;
                                } else {
                                    secConf->secEIBnetip = p_newAddr;
                                    p_newAddr->rule = 1;
                                    secConf->defaultAuthEIBnet = secAddrTypeDeny;
                                }
                            }
                        }
                    }
                    src = src + strlen( src ) -1;          // skip to end of line
                    break;
                case SECTION_EIBD:
                    // line format:
                    //      type: address [ / subnet-mask ]
                    // supported types:
                    //      allow
                    //      deny
                    //      read
                    //      write
                    dst = src;
                    fld_type = strsep( &dst, ":" );
                    fld_address = strsep( &dst, "/" ); 
                    fld_mask = dst;
                    if( fld_type == NULL || fld_address == NULL ) {
                        logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'allow | deny | read | write: address [/ subnet-mask]'" );
                        logDebug( THIS_MODULE, "(%s) | (%s)", fld_type, fld_address );
                    } else {
                        if( strcasecmp( fld_type, "maxauth" ) == 0 ) {
                            if( strcasecmp( fld_address, "all" ) == 0 ) {
                                secConf->maxAuthEIBD = secAddrTypeAllow;
                            } else if( strcasecmp( fld_address, "deny" ) == 0 ) {
                                secConf->maxAuthEIBD = secAddrTypeDeny;
                            } else if( strcasecmp( fld_address, "read" ) == 0 ) {
                                secConf->maxAuthEIBD = secAddrTypeRead;
                            } else if( strcasecmp( fld_address, "write" ) == 0 ) {
                                secConf->maxAuthEIBD = secAddrTypeWrite;
                            } else {
                                logWarning( THIS_MODULE, msgConfigAddrType, line_nr, fld_address );
                                return( NULL );
                            }
                        } else {
                            p_newAddr = configParseAddress( SECTION_EIBD, fld_type, fld_address, fld_mask, line_nr );
                            if( p_newAddr != NULL ) {
                                for( p_secAddr = secConf->secEIBD; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
                                    if( p_secAddr->next == NULL )
                                        break;
                                }
                                if( p_secAddr != NULL ) {
                                    p_secAddr->next = p_newAddr;
                                    p_newAddr->rule = p_secAddr->rule + 1;
                                } else {
                                    secConf->secEIBD = p_newAddr;
                                    p_newAddr->rule = 1;
                                    secConf->defaultAuthEIBD = secAddrTypeDeny;
                                }
                            }
                        }
                    }
                    src = src + strlen( src ) -1;          // skip to end of line
                    break;
                case SECTION_CLIENTS:
                    // line format:
                    //      type: address [ / subnet-mask ]
                    // supported types:
                    //      allow
                    //      deny
                    dst = src;
                    fld_type = strsep( &dst, ":" );
                    fld_address = strsep( &dst, "/" ); 
                    fld_mask = dst;
                    if( fld_type == NULL || fld_address == NULL ) {
                        logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'allow | deny: address [/ subnet-mask]'" );
                        logDebug( THIS_MODULE, "(%s) | (%s)", fld_type, fld_address );
                    } else {
                        p_newAddr = configParseAddress( SECTION_CLIENTS, fld_type, fld_address, fld_mask, line_nr );
                        if( p_newAddr != NULL ) {
                            for( p_secAddr = secConf->secClients; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
                                if( p_secAddr->next == NULL )
                                    break;
                            }
                            if( p_secAddr != NULL ) {
                                p_secAddr->next = p_newAddr;
                                p_newAddr->rule = p_secAddr->rule + 1;
                            } else {
                                secConf->secClients = p_newAddr;
                                p_newAddr->rule = 1;
                                secConf->defaultAuthClient = secAddrTypeDeny;
                            }
                        }
                    }
                    src = src + strlen( src ) -1;          // skip to end of line
                    break;
#ifdef WITH_AUTHENTICATION
                case SECTION_USERS:
                    // line format:
                    //      name: hash
                    dst = src;
                    fld_name = strsep( &dst, ":" );
                    fld_hash = dst;
                    if( (fld_level = strsep( &dst, "," )) != NULL ) {
                        fld_hash = dst;
                    }
                    if( fld_name == NULL || fld_hash == NULL ) {
                        logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'name: [level,] hash'" );
                        logDebug( THIS_MODULE, "(%s) | (%s) | (%s)", fld_name, fld_level, fld_hash );
                    } else {
                        p_newUser = configParseUser( fld_name, fld_hash, fld_level, line_nr );
                        if( p_newUser != NULL ) {
                            for( p_secUser = secConf->secUsers; p_secUser != NULL; p_secUser = p_secUser->next ) {
                                if( p_secUser->next == NULL )
                                    break;
                            }
                            if( p_secUser != NULL ) {
                                p_secUser->next = p_newUser;
                            } else {
                                secConf->secUsers = p_newUser;
                            }
                        }
                    }
                    src = src + strlen( src ) -1;          // skip to end of line
                    break;
                case SECTION_AUTHORISATION:
                    // line format:
                    //      level: function [, function] ...
                    dst = src;
                    fld_level = strsep( &dst, ":" );
                    fld_name = dst;
                    if( fld_name == NULL || fld_level == NULL ) {
                        logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'level: function [, function] ...'" );
                        logDebug( THIS_MODULE, "(%s) | (%s)", fld_level, fld_name );
                    } else {
                        configParseAuthorisation( secConf, fld_level, fld_name, line_nr );
                    }
                    src = src + strlen( src ) -1;          // skip to end of line
                    break;
                case SECTION_DHM:
                    // line format:
                    //      file: path
                    //      P: value
                    //      G: value
                    // if file is defined an readable, it takes precedence over other values
                    dst = src;
                    fld_type = strsep( &dst, ":" );
                    fld_value = dst;
                    if( fld_type == NULL || fld_value == NULL ) {
                        logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'file | P | G: value'" );
                        logDebug( THIS_MODULE, "(%s) | (%s)", fld_type, fld_value );
                    } else {
                        if( strcasecmp( fld_type, "file" ) == 0 ) {
                            dhm_file = strdup( fld_value );
                        } else if( strcasecmp( fld_type, "P" ) == 0 ) {
                            if( secConf->dhm == NULL ) {
                                secConf->dhm = allocMemory( THIS_MODULE, sizeof( dhm_context ));
                                memset( secConf->dhm, 0, sizeof( dhm_context ));
                            }
                            result = mpi_read_string( &(secConf->dhm->P), 16, fld_value );
                            if( result != 0 ) {
                                logError( THIS_MODULE, msgConfigDHM_MPI, config.security_file, result );
                                error = 1;
                            }
                        } else if( strcasecmp( fld_type, "g" ) == 0 ) {
                            if( secConf->dhm == NULL ) {
                                secConf->dhm = allocMemory( THIS_MODULE, sizeof( dhm_context ));
                                memset( secConf->dhm, 0, sizeof( dhm_context ));
                            }
                            result = mpi_read_string( &(secConf->dhm->G), 16, fld_value );
                            if( result != 0 ) {
                                logError( THIS_MODULE, msgConfigDHM_MPI, config.security_file, result );
                                error = 1;
                            }
                        } else {
                            logWarning( THIS_MODULE, msgConfigSyntax, line_nr, "Format should be 'file | P | G: value'" );
                        }
                    }
                    src = src + strlen( src ) -1;          // skip to end of line
                    break;
#else
                case SECTION_USERS:
                case SECTION_AUTHORISATION:
                case SECTION_DHM:
                    fld_name = "<unknown>";
                    for( loop = 0; true; loop++ ) {
                        if( sectionDefinitions[loop].name == NULL ) {
                            break;
                        }
                        if( sectionDefinitions[loop].id == section ) {
                            fld_name = sectionDefinitions[loop].name;
                            break;
                        }
                    }
                    logWarning( THIS_MODULE, msgConfigNoAuth, fld_name, line_nr );
                    break;
#endif
            }
        }
    }
    
    fclose( fp );
    
    /*
     * only activate these settings if there was no error
     */
    if( error == 0 ) {
        /*
         * setup authorisation masks
         */
        for( p_secUser = secConf->secUsers; p_secUser != NULL; p_secUser = p_secUser->next ) {
            for( p_auth = secConf->secAuthorisations; p_auth != NULL; p_auth = p_auth->next ) {
                if( p_auth->level == p_secUser->auth_level ) {
                    p_secUser->authorisation = p_auth->function_mask;
                    break;
                }
            }
            if( p_auth == NULL ) {
                logWarning( THIS_MODULE, msgConfigLevelUndef, p_secUser->auth_level, p_secUser->name );
            }
        }
        
        /*
         * get authorisation mask for anonymous access
         */
        secConf->auth_anonymous = authNone;
        if( secConf->secAuthorisations->level == 0 ) {
            secConf->auth_anonymous = secConf->secAuthorisations->function_mask;
        }
        
#ifdef WITH_AUTHENTICATION
        /*
         * read dhm prime from file
         */
        if( dhm_file != NULL ) {
            // open dhm prime file
            if( ( fp = fopen( dhm_file, "r" )) == NULL ) {
                logError( THIS_MODULE, msgConfigDHMRead, dhm_file, strerror( errno ));
                error = 1;
            } else {
                if( secConf->dhm == NULL ) {
                    secConf->dhm = allocMemory( THIS_MODULE, sizeof( dhm_context ));
                    memset( &secConf->dhm, 0, sizeof( dhm_context ));
                }
                if( (result = mpi_read_file( &(secConf->dhm->P), 16, fp )) != 0 ||
                    (result = mpi_read_file( &(secConf->dhm->G), 16, fp )) != 0 ) {
                    logError( THIS_MODULE, msgConfigDHM_MPI, dhm_file, result );
                    error = 1;
                }
                fclose( fp );
            }
            free( dhm_file );
        }
#endif
    }
    if( error != 0 ) {
        // release memory
        configSecurityReleaseMemory( secConf );
        secConf = NULL;
    }
    
    return( secConf );
}


void configSecurityReleaseMemory( sSecurityConfig *secConf )
{
    sSecurityAddr   *p_secAddr;
    sSecurityUser   *p_secUser;
    sAuthorisation  *p_auth;
    
    while( secConf->secClients != NULL ) {
        p_secAddr = secConf->secClients;
        secConf->secClients = secConf->secClients->next;
        free( p_secAddr );
    }
    while( secConf->secEIBnetip != NULL ) {
        p_secAddr = secConf->secEIBnetip;
        secConf->secEIBnetip = secConf->secEIBnetip->next;
        free( p_secAddr );
    }
    while( secConf->secEIBD != NULL ) {
        p_secAddr = secConf->secEIBD;
        secConf->secEIBD = secConf->secEIBD->next;
        free( p_secAddr );
    }
    while( secConf->secUsers != NULL ) {
        p_secUser = secConf->secUsers;
        secConf->secUsers = secConf->secUsers->next;
        free( p_secUser->name );
        free( p_secUser );
    }
    while( secConf->secAuthorisations != NULL ) {
        p_auth = secConf->secAuthorisations;
        secConf->secAuthorisations = secConf->secAuthorisations->next;
        free( p_auth );
    }
#ifdef WITH_AUTHENTICATION
    if( secConf->dhm != NULL ) {
        dhm_free( secConf->dhm );
    }
#endif
    free( secConf );
}


/*
 * check and prepare a single line
 */
static int parsePrepareLine( char *src, char *buf, unsigned int maxlen, unsigned int line_nr, unsigned int skip )
{
    char    *dst;
    
    if( strlen( src ) == maxlen -1 && src[maxlen -1] != '\n' ) {
        if( skip == false ) {
            logError( THIS_MODULE, msgConfigLineTooLong, line_nr );
            skip = true;
        }
        return( skip );
    } else if( skip == true ) {
        skip = false;
        return( skip );
    }
    
    // prepare single line
    //      remove comments
    //      remove newlines
    //      remove whitespace
    dst = buf;
    while( *src && *src != '\n' ) {
        if( *src == '#' ) {
            // rest of line is comment - skip
            break;
        } else if( *src == '\r' || *src == '\n' ) {
            // remove CR & LF
        } else if( *src == ' ' || *src == '\t' ) {
            // just remove whitespace
        } else {
            *dst = *src;
            dst++;
        }
        src++;
    }
    *dst = '\0';
    
    return( false );
}


/*
 * parse network address / submask
 * 
 * this code is very much IPv4 specific
 */
static sSecurityAddr *configParseAddress( int section, char *txt_type, char *txt_address, char *txt_mask, unsigned int line_nr )
{
    eSecAddrType    type;
    uint32_t        addr;
    uint32_t        mask;
    sSecurityAddr   *p_secAddr;
    
    // set type
    if( section == SECTION_CLIENTS ) {
        if( strcasecmp( txt_type, "allow" ) == 0 ) {
            type = secAddrTypeAllow;
        } else if( strcasecmp( txt_type, "deny" ) == 0 ) {
            type = secAddrTypeDeny;
        } else {
            logWarning( THIS_MODULE, msgConfigAddrType, line_nr, txt_type );
            return( NULL );
        }
    } else {
        if( strcasecmp( txt_type, "allow" ) == 0 ) {
            type = secAddrTypeAllow;
        } else if( strcasecmp( txt_type, "deny" ) == 0 ) {
            type = secAddrTypeDeny;
        } else if( strcasecmp( txt_type, "read" ) == 0 ) {
            type = secAddrTypeRead;
        } else if( strcasecmp( txt_type, "write" ) == 0 ) {
            type = secAddrTypeWrite;
        } else {
            logWarning( THIS_MODULE, msgConfigAddrType, line_nr, txt_type );
            return( NULL );
        }
    }
    
    // set address
    if( inet_pton( AF_INET, txt_address, (void *)&addr ) <= 0 ) {
        logWarning( THIS_MODULE, msgConfigAddress, line_nr, txt_address );
        return( NULL );
    }
    
    // set mask
    if( inet_pton( AF_INET, txt_mask, (void *)&mask ) <= 0 ) {
        logWarning( THIS_MODULE, msgConfigMask, line_nr, txt_mask );
        return( NULL );
    }
    
    // create new address structure
    p_secAddr = allocMemory( THIS_MODULE, sizeof( sSecurityAddr ));
    p_secAddr->next = NULL;
    p_secAddr->type = type;
    p_secAddr->mask = mask;
    p_secAddr->rule = 0;
    p_secAddr->address = addr & mask;
    
    return( p_secAddr );
}


#ifdef WITH_AUTHENTICATION
/*
 * parse network address / submask
 */
static sSecurityUser *configParseUser( char *txt_name, char *txt_hash, char *txt_level, unsigned int line_nr )
{
    sSecurityUser   *p_secUser;
    unsigned char   *ptr;
    unsigned char   c;
    unsigned char   x;
    int             idx;
    
    // create new address structure
    p_secUser = allocMemory( THIS_MODULE, sizeof( sSecurityUser ));
    p_secUser->next = NULL;
    p_secUser->name = strdup( txt_name );
    ptr = (unsigned char *) txt_hash;
    for( idx = 0; idx < 32; idx++ ) {
        x = *ptr;
        if( fromHex( *ptr, &c ) != 0 ) {
            logWarning( THIS_MODULE, msgConfigHashInvalid, line_nr );
            break;
        } else {
            p_secUser->hash[idx] = (c << 4);
        }
        ptr++;
        if( fromHex( *ptr, &c ) != 0 ) {
            logWarning( THIS_MODULE, msgConfigHashInvalid, line_nr );
            break;
        } else {
            p_secUser->hash[idx] |= c;
        }
        ptr++;
    }
    p_secUser->auth_level = (txt_level != NULL) ? atoi( txt_level ) : 0;
    p_secUser->authorisation = authNone;
    
    return( p_secUser );
}


/*
 * parse authorisation definition
 */
static void configParseAuthorisation( sSecurityConfig *secConf, char *txt_level, char *txt_name, unsigned int line_nr )
{
    sAuthorisation  *p_newauth;
    sAuthorisation  **p_auth;
    int             loop;
    char            *func_id;
    char            *ptr;
    
    // check level
    if( atoi( txt_level ) < 0 ) {
        logWarning( THIS_MODULE, msgConfigLevelInvalid, txt_level, line_nr );
        return;
    }
    
    // create new address structure
    p_newauth = allocMemory( THIS_MODULE, sizeof( sAuthorisation ));
    p_newauth->level = atoi( txt_level );
    p_newauth->function_mask = authNone;
    p_newauth->next = NULL;
    
    // insert into sorted linked list
    for( p_auth = &secConf->secAuthorisations; *p_auth != NULL; p_auth = &(*p_auth)->next ) {
        if( (*p_auth)->level > p_newauth->level ) {
            p_newauth->next = *p_auth;
            *p_auth = p_newauth;
            break;
        } else if( (*p_auth)->level == p_newauth->level ) {
            logWarning( THIS_MODULE, msgConfigLevelDup, p_newauth->level );
            break;
        }
    }
    if( *p_auth == NULL ) {
        *p_auth = p_newauth;
    }
    
    // get masks of all referenced functions
    ptr = txt_name;
    for( func_id = strsep( &ptr, "," ); func_id != NULL; func_id = strsep( &ptr, "," )) {
        for( loop = 0; functionAuthorisations[loop].id != NULL; loop++ ) {
            if( strcasecmp( functionAuthorisations[loop].id, func_id ) == 0 ) {
                p_newauth->function_mask |= functionAuthorisations[loop].mask;
                break;
            }
        }
    }
    
    return;
}
#endif
