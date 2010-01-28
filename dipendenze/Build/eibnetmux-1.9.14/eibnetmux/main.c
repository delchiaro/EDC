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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>

#include <pth.h>

#ifdef WITH_AUTHENTICATION
#include <polarssl/bignum.h>
#endif

#include "eibnetmux.h"
#include "include/log.h"
#include "include/eibnetip_private.h"

#define  THIS_MODULE    logModuleMain


/*
 * Global variables
 *
 * Globals are preferred in embedded systems
 */
uint8_t                  runMode;
sConfig                  config;
sShutdownHandlers        callbacks[shutdownEntries];     // register functions called upon shutdown
pth_t                    tid_main;
time_t                   startupTime;


/*
 * eibnetmux - main()
 * 
 * start all required threads
 *      - eibnet/ip client
 *      - eibnet/ip server
 *      - socket server
 *      - eibd server
 * then wait on message port for shutdown command
 */
int main(int argc, char **argv )
{
    FILE            *fp;
    pth_attr_t      thread_attr;
    sigset_t        signal_set;
    int             signal_id;
    int             loop;
    int             errcode;
    sSecurityConfig *secConf_new;
    sSecurityConfig *secConf_old;
    sSecurityAddr   *p_secAddr;
#ifdef WITH_AUTHENTICATION
    sSecurityUser   *p_secUser;
    sAuthorisation  *p_auth;
    int             c;
    unsigned int    v;
    char            buf[512];
#endif
    char            ip_text[BUFSIZE_IPADDR];
    char            *errmsg;
    
    runMode = runStartup;
            
    /*
     * catch interrupt signals and shutdown cleanly
     */
    for( loop = 0; loop < shutdownEntries; loop++ ) {
        callbacks[loop].flag = 0;
    }
    // signal( SIGINT, AbortSignalHandler );    // catch SIGINT (abort) to clean up
    
    if( ConfigLoad( argc, argv ) != 0 ) {
        Usage( argv[0] );
        exit( -1 );
    }
    
    // initialize logger
    logSetLevel( config.log_level );
    logSetRingLevel( config.ring_level );
    if( config.log_level != 0 ) {
        if( (errmsg = logSetDest( config.log_dest, config.ring_size )) != NULL ) {
            fprintf( stderr, "Unable to setup logging - aborting: %s: %s\n", errmsg, config.log_dest );
            exit( -1 );
        }
        if( (errmsg = logInit()) != NULL ) {
            fprintf( stderr, "Unable to setup logging - aborting: %s\n", errmsg );
            exit( -1 );
        }
    }
    
    if( pth_init() != true ) {
        logFatal( THIS_MODULE, msgInitPth, strerror( errno  ));
        exit( -1 );
    }
    tid_main = pth_self();

    /*
     * read security setup
     */
    if( config.security_file != NULL ) {
        if( (secConf_new = configReadSecurity()) == NULL ) {
            logFatal( THIS_MODULE, msgConfigSecurityError );
            exit( -1 );
        } else {
            config.secEIBnetip = secConf_new->secEIBnetip;
            config.secEIBD = secConf_new->secEIBD;
            config.secClients = secConf_new->secClients;
            config.maxAuthEIBnet = secConf_new->maxAuthEIBnet;
            config.maxAuthEIBD = secConf_new->maxAuthEIBD;
            config.defaultAuthEIBnet = secConf_new->defaultAuthEIBnet;
            config.defaultAuthEIBD = secConf_new->defaultAuthEIBD;
            config.defaultAuthClient = secConf_new->defaultAuthClient;
            config.secUsers = secConf_new->secUsers;
            config.secAuthorisations = secConf_new->secAuthorisations;
            config.auth_anonymous = secConf_new->auth_anonymous;
            config.eibd_anonymous = secConf_new->eibd_anonymous;
#ifdef WITH_AUTHENTICATION
            config.dhm = secConf_new->dhm;
#endif
            free( secConf_new );
        }
    }
    
    if( config.dump == TRUE ) {
        printf( "eibnetmux config dump\n" );
        printf( "  target eibnet/ip server: %s\n", (config.eibConnectionParam != NULL) ? config.eibConnectionParam : "none - running in testmode" );
        printf( "  services:\n" );
        if( config.servers & SERVER_EIBNET ) {
            printf( "    eibnet/ip: yes [%d]\n", config.eib_port );
        } else {
            printf( "    eibnet/ip: no\n" );
        }
        if( config.servers & SERVER_TCP ) {
            printf( "    tcp: yes [%d]\n", config.tcp_port );
        } else {
            printf( "    tcp: no\n" );
        }
        if( config.servers & SERVER_UNIX ) {
            printf( "    named pipe: yes [%s]\n", config.unix_path );
        } else {
            printf( "    named pipe: no\n" );
        }
        
        printf( "  logging:\n" );
        printf( "    level: %d\n", config.log_level );
        printf( "     ring: %d\n", config.ring_level );
        printf( "     size: %d\n", config.ring_size );
        printf( "     dest: %s\n", config.log_dest );
        
        printf( "  mode:\n" );
        printf( "    daemon:   %s\n", config.daemon ? "yes" : "no" );
        printf( "    user id:  %d\n", config.user );
        printf( "    group id: %d\n", config.group );
        
        printf( "  security:\n" );
        printf( "    definitions: %s\n", config.security_file );
#ifdef WITH_AUTHENTICATION
        printf( "    users:\n" );
        for( p_secUser = config.secUsers; p_secUser != NULL; p_secUser = p_secUser->next ) {
            printf( "      %s: %d, %d (", p_secUser->name, p_secUser->auth_level, p_secUser->authorisation );
            printf( (p_secUser->authorisation & authRead) ? "R" : " " );
            printf( (p_secUser->authorisation & authWrite) ? "W" : " " );
            printf( (p_secUser->authorisation & authMonitor) ? "M" : " " );
            printf( " " );
            printf( (p_secUser->authorisation & authMgmtClient) ? "C" : " " );
            printf( (p_secUser->authorisation & authMgmtLog) ? "L" : " " );
            printf( (p_secUser->authorisation & authMgmtStatus) ? "S" : " " );
            printf( ") " );
            for( c = 0; c < 32; c++ ) {
                v = p_secUser->hash[c];
                printf( "%02x", v );
            }
            printf( "\n" );
        }
        printf( "    authorisation levels:\n" );
        for( p_auth = config.secAuthorisations; p_auth != NULL; p_auth = p_auth->next ) {
            printf( "      %3d: ", p_auth->level );
            printf( (p_auth->function_mask & authRead) ? "R" : " " );
            printf( (p_auth->function_mask & authWrite) ? "W" : " " );
            printf( (p_auth->function_mask & authMonitor) ? "M" : " " );
            printf( " " );
            printf( (p_auth->function_mask & authMgmtClient) ? "C" : " " );
            printf( (p_auth->function_mask & authMgmtLog) ? "L" : " " );
            printf( (p_auth->function_mask & authMgmtStatus) ? "S" : " " );
            printf( (p_auth->function_mask & authMgmtBlock) ? "B" : " " );
            printf( (p_auth->function_mask & authMgmtConnection) ? "X" : " " );
            printf( "\n" );
        }
#endif
        printf( "    eibnet/ip clients:\n" );
        printf( "      default auth: %d\n", config.defaultAuthEIBnet );
        printf( "      max auth....: %d\n", config.maxAuthEIBnet );
        for( p_secAddr = config.secEIBnetip; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
            printf( "      %d: %d-%s/%s\n", p_secAddr->rule, p_secAddr->type, ip_addr( p_secAddr->address, ip_text ), ip_addr( p_secAddr->mask, NULL ));
        }
        printf( "    eibd clients:\n" );
        printf( "      default auth: %d\n", config.defaultAuthEIBD );
        printf( "      max auth....: %d\n", config.maxAuthEIBD );
        for( p_secAddr = config.secEIBD; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
            printf( "      %d: %d-%s/%s\n", p_secAddr->rule, p_secAddr->type, ip_addr( p_secAddr->address, ip_text ), ip_addr( p_secAddr->mask, NULL ));
        }
        printf( "    eibnetmux clients:\n" );
        for( p_secAddr = config.secClients; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
            printf( "      %d: %d-%s/%s\n", p_secAddr->rule, p_secAddr->type, ip_addr( p_secAddr->address, ip_text ), ip_addr( p_secAddr->mask, NULL ));
        }
#ifdef WITH_AUTHENTICATION
        printf( "    dhm parameters:\n" );
        if( config.dhm == NULL ) {
            printf( "      not defined\n" );
        } else {
            c = 512;
            mpi_write_string( &(config.dhm->P), 16, buf, &c );
            printf( "c=%d\n", c );
            buf[c] = '\0';
            printf( "      p: %s\n", buf );
            c = 512;
            mpi_write_string( &(config.dhm->G), 16, buf, &c );
            buf[c] = '\0';
            printf( "c=%d\n", c );
            printf( "      g: %s\n", buf );
        }
#endif
        exit( 0 );
    }
    
    if( init_network() != 0 ) {
        logFatal( THIS_MODULE, msgInitNetwork );
        exit( -1 );
    }

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    signal( SIGPIPE, SIG_IGN );
    
    // detach and run as system daemon
    // - must happen before pid file is written as this will create a new process
    // - unfortunately, it redirects stdout/stderr to /dev/null if successful
    // - which means, we won't get any notification in case of an error
    if( config.daemon == true ) {
        if( daemon( TRUE, 0 ) != 0 ) {
            logFatal( THIS_MODULE, msgInitDaemon, strerror( errno  ));
            exit( -2 );
        }
    }

    // write pid file
    if( config.pidfile != NULL ) {
        fp = fopen( config.pidfile, "w" );
        if( fp != NULL ) {
            fprintf( fp, "%d\n", getpid() );
            fclose( fp );
        } else {
            logWarning( THIS_MODULE, msgPidFile, config.pidfile, strerror( errno  ));
        }
    }
    
    // switch personality
    // - must happen after pid file is written
    //   as user may not have write rights
    if( config.group != 0 ) {
        if( setgid( config.group ) != 0 ) {
            struct group    *grp_entry;
            char            *groupname;
            errcode = errno;
            setgrent();
            grp_entry = getgrgid( config.group );
            groupname = (grp_entry != NULL) ? grp_entry->gr_name : "<unknown>";
            endgrent();
            logFatal( THIS_MODULE, msgSwitchPersonality, "group", groupname, strerror( errcode  ));
            exit( -2 );
        }
    }
    
    if( config.user != 0 ) {
        if( setuid( config.user ) != 0 ) {
            struct passwd   *pwd_entry;
            char            *username;
            errcode = errno;
            setpwent();
            pwd_entry = getpwuid( config.user );
            username = (pwd_entry != NULL) ? pwd_entry->pw_name : "<unknown>";
            endpwent();
            logFatal( THIS_MODULE, msgSwitchPersonality, "user", username, strerror( errcode  ));
            exit( -2 );
        }
    }
    
    logInfo( THIS_MODULE, msgStartup, VERSION );
    logVerbose( THIS_MODULE, msgIpAddress, ip_addr( MyIpAddress, NULL ));
    
    // initialise
    for( loop = 0; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
        eibNetClearConnection( &eibcon[loop] );
    }
    
    runMode = runNormal;
    startupTime = time( NULL );
    
    /*
     * setup signaling for server queue
     * the same queue is used for eibnet/ip and tcp socket servers
     * they also use the same signaling mechanism (same mutex, same condition variable)
     */
    pth_mutex_init( &mtxQueueServer );
    pth_cond_init( &condQueueServer );
    
    /*
     * setup thread attributes
     */
    thread_attr = pth_attr_new();
    pth_attr_set( thread_attr, PTH_ATTR_JOINABLE, FALSE );
    
    /*
     * startup client & server threads
     */
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBnetClient" );
    if( pth_spawn( thread_attr, EIBnetClient, NULL ) == NULL ) {
        logFatal( THIS_MODULE, msgInitThread, "EIBnetClient" );
        exit( -2 );
    }
    if( config.servers & SERVER_EIBNET ) {
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBnetServer" );
        if( pth_spawn( thread_attr, EIBnetServer, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread, "EIBnetServer" );
            exit( -2 );
        }
    }
    pth_mutex_init( &mtxSocketForwarder );
    if( config.servers & SERVER_TCP ) {
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "TCPServer" );
        if( pth_spawn( thread_attr, SocketTCP, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread, "TCPServer" );
            exit( -2 );
        }
    }
    if( config.servers & SERVER_UNIX ) {
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "UnixServer" );
        if( pth_spawn( thread_attr, SocketUnix, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread, "UnixServer" );
            exit( -2 );
        }
    }
    if( config.servers & SERVER_EIBD ) {
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBDServer" );
        if( pth_spawn( thread_attr, EIBDListener, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread, "EIBDServer" );
            exit( -2 );
        }
    }
    
    /*
     * this is the main thread, responsible to terminate the threading library pth
     * if user sends INT signal or a fatal error happens
     * this thread is signalled
     * until then, block on pth_sigwait()
     * our priority is raised first, so we get called immediately after signal is posted
     * we also handle user signals which cause a reload of the security configuration
     */
    thread_attr = pth_attr_of( pth_self());
    pth_attr_set( thread_attr, PTH_ATTR_PRIO, PTH_PRIO_MAX );
    pth_attr_destroy( thread_attr );
    sigemptyset( &signal_set );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGTERM );
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    pth_sigmask( SIG_UNBLOCK, &signal_set, NULL );
    logDebug( THIS_MODULE, "Waiting for signals: shutdown (SIGINT), reload (SIGUSR1), or dump debug log (SIGUSR2)" );
    while( 1 ) {
        pth_sigwait( &signal_set, &signal_id );
        if( signal_id == SIGUSR1 ) {
            // reload security configuration
            if( (secConf_new = configReadSecurity()) != NULL ) {
                // first copy old config so we can release it later
                secConf_old = allocMemory( THIS_MODULE, sizeof( sSecurityConfig ));
                secConf_old->secEIBnetip = config.secEIBnetip;
                secConf_old->secEIBD = config.secEIBD;
                secConf_old->secClients = config.secClients;
                secConf_old->maxAuthEIBnet = config.maxAuthEIBnet;
                secConf_old->maxAuthEIBD = config.maxAuthEIBD;
                secConf_old->defaultAuthEIBnet = config.defaultAuthEIBnet;
                secConf_old->defaultAuthEIBD = config.defaultAuthEIBD;
                secConf_old->defaultAuthClient = config.defaultAuthClient;
                secConf_old->secUsers = config.secUsers;
                secConf_old->secAuthorisations = config.secAuthorisations;
                secConf_old->auth_anonymous = config.auth_anonymous;
                secConf_old->eibd_anonymous = config.eibd_anonymous;
#ifdef WITH_AUTHENTICATION
                secConf_old->dhm = config.dhm;
#endif
                // install new config
                config.secEIBnetip = secConf_new->secEIBnetip;
                config.secEIBD = secConf_new->secEIBD;
                config.secClients = secConf_new->secClients;
                config.maxAuthEIBnet = secConf_new->maxAuthEIBnet;
                config.maxAuthEIBD = secConf_new->maxAuthEIBD;
                config.defaultAuthEIBnet = secConf_new->defaultAuthEIBnet;
                config.defaultAuthEIBD = secConf_new->defaultAuthEIBD;
                config.defaultAuthClient = secConf_new->defaultAuthClient;
                config.secUsers = secConf_new->secUsers;
                config.secAuthorisations = secConf_new->secAuthorisations;
                config.auth_anonymous = secConf_new->auth_anonymous;
                config.eibd_anonymous = secConf_new->eibd_anonymous;
#ifdef WITH_AUTHENTICATION
                config.dhm = secConf_new->dhm;
#endif
                free( secConf_new );
                pth_yield( NULL );
                // release memory of old config
                configSecurityReleaseMemory( secConf_old );
                logInfo( THIS_MODULE, msgConfigSecurity );
            } else {
                logCritical( THIS_MODULE, msgConfigSecurityError );
            }
        } else if( signal_id == SIGUSR2 ) {
            logDump( THIS_MODULE );
        } else {
            // shutdown
            logDebug( THIS_MODULE, "Shutdown signal received" );
            break;
        }
    }
    
    /*
     * clean up
     */
    for( loop = 0; loop < shutdownEntries; loop++ ) {
        if( callbacks[loop].flag == 1 ) {
            logDebug( THIS_MODULE, "shutdown module %d", loop );
            (*callbacks[loop].func)();
        }
    }

    pth_kill();
    logWarning( THIS_MODULE, msgShutdown );
    return( 0 );
}

/*
 * eibnetmuxStatus
 * 
 * Return current top-level status:
 *      (length of structure)
 *      1: version major, version minor, log level, uptime, user id, group id, daemon mode
 *      2: version, log level, uptime, user id, group id, daemon mode
 */
char *eibnetmuxStatus( void )
{
    char            *status;
    char            *hdump;
    uint16_t        tmp16;
    uint16_t        idx;
    uint8_t         namelength;
    
#define STATUS_MAIN_VERSION     2
#define STATUS_MAIN_BASE_LENGTH   14
    namelength = strlen( VERSION ) +1;
    tmp16 = STATUS_MAIN_BASE_LENGTH + namelength;
    status = allocMemory( THIS_MODULE, 2 + tmp16 );
    idx = 0;
    idx = AppendBytes( idx, status, sizeof( tmp16 ), tmp16 );   // used internally, indicates size of buffer
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( tmp16 ));
    idx = AppendBytes( idx, status, 1, STATUS_MAIN_VERSION );
    memcpy( &status[idx], VERSION, namelength );
    idx += namelength;
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( logGetLevel() ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( time( NULL ) - startupTime ));
    // idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.user ));
    // idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.group ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( getuid() ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( getgid() ));
    idx = AppendBytes( idx, status, 1, config.daemon ? 1 : 0 );
    
    hdump = hexdump( THIS_MODULE, status +2, STATUS_MAIN_BASE_LENGTH + namelength );
    logDebug( THIS_MODULE, "Top-level status: %s", hdump );
    free( hdump );
    return( status );
}
