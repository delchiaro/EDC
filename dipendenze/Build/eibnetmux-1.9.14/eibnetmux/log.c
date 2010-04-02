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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "eibnetmux.h"
#include "include/log.h"


/*
 * Global variables
 */
void    *logModuleMain = NULL;
void    *logModuleConfig = NULL;
void    *logModuleEIBnetClient = NULL;
void    *logModuleEIBDServer = NULL;
void    *logModuleEIBnetServer = NULL;
void    *logModuleSocketServer = NULL;


/*
 * Local variables
 */
static unsigned int     logLevel;
static unsigned int     ringLevel;
static zlogAppender     appender_standard;
static zlogAppender     appender_ring = NULL;


/*
 * Local functions
 */
static void     *getLogger( char *name );


/*
 * messages
 */
static char *messages[] = {
    /* msgInitPth           */      "Unable to initialize pth library - aborting: %s",
    /* msgInitThread        */      "Unable to create required thread: %s",
    /* msgInitNetwork       */      "Unable to retrieve my own IP address",
    /* msgInitDaemon        */      "Unable to switch to daemon mode - aborting: %s",
    /* msgConfigRead        */      "Unable to read security definition file '%s': %d - %s",
    /* msgConfigSection     */      "Unknown section at line %d: %s",
    /* msgConfigSyntax      */      "Syntax error on line %d: %s",
    /* msgConfigAddrType    */      "Invalid security type '%s' on line %d",
    /* msgConfigAddress     */      "Invalid network address '%s' on line %d",
    /* msgConfigMask        */      "Invalid network mask '%s' on line %d",
    /* msgConfigLineTooLong */      "Line %d too long - skipped",
    /* msgConfigLevelDup    */      "Authorisation level %d defined more than once - later definition ignored",
    /* msgConfigLevelUndef  */      "Authorisation level %d for user '%s' not defined - ignored",
    /* msgConfigLevelInvalid */     "Authorisation level '%s' invalid on line %d - must be a positive number",
    /* msgConfigHashInvalid */      "Password hash on line %d contains invalid characters",
    /* msgConfigDHMRead     */      "Unable to read DHM parameter file '%s': %s",
    /* msgConfigDHM_MPI     */      "Error parsing DHM value in file '%s': %x",
    /* msgConfigSecurity    */      "New security definitions loaded and activated",
    /* msgConfigSecurityError */    "Error in new security definitions - keeping current set",
    /* msgConfigNoAuth      */      "eibnetmux compiled without authentication support - section %s unsupported - line %d skipped",
    /* msgSwitchPersonality */      "Unable to switch personality (%s %s) - aborting: %s",
    /* msgPidFile           */      "Unable to create pid file '%s': %s",
    /* msgStartup           */      "eibnetmux Ver. %s started",
    /* msgStartupEIBnetServer */    "EIBnet/IP Server started",
    /* msgStartupEIBClient  */      "Client started",
    /* msgStartupTCPServer  */      "TCP Server started",
    /* msgStartupUnixServer */      "Unix Socket Server started",
    /* msgStartupEIBDServer */      "EIBD Server started",
    /* msgShutdown          */      "Shutdown",
    /* msgMemory            */      "Out of memory: %s",
    /* msgEIBnetClientSuspend */    "Client connection suspended",
    /* msgEIBnetClientActive */     "Client connection activated",
    /* msgEIBnetClientNoAddress */  "Client cannot determine valid source ip address to communicate with server - connection cannot be established (%d)",
    /* msgEIBnetClientHeartbeat */  "Heartbeat failure - connection closed",
    /* msgEIBnetSourceIPFixed */    "Netlink support missing - using fixed source address and putting '%s' in all EIBnet/IP packets",
    /* msgEIBnetNoSourceIP  */      "Unable to determine valid source ip address to communicate with peer (%d)",
    /* msgEIBnetSocket      */      "Creating socket failed: %d",
    /* msgEIBnetTunnelEstablished */ "Tunnelling connection established with %s",
    /* msgEIBnetLoopbackEstablished */ "Tunnelling connection established, looping back to myself",
    /* msgEIBnetBadServer   */      "Invalid config for EIBnet/IP server: %s - could not resolve",
    /* msgEIBnetNoClientConnection */ "Unable to establish EIBnet/IP connection to remote server - bad config",
    /* msgEIBnetNoMCast     */      "Unable to activate multicast receiver - searching will not work (%d - %s)",
    /* msgEIBnetBadType     */      "Unsupported connection type requested: %s",
    /* msgEIBnetTypeBlocked */      "Client connection currently on type %02x - request for type %02x (%s) blocked - other clients still active",
    /* msgEIBnetMonitorActive */    "Bus monitoring activated - blocking all standard EIBnet/IP clients, no guarantee on what happens to socket clients!",
    /* msgIpAddress         */      "My IP address: %s",
    /* msgFrameSent         */      "Frame sent to %s:%d - %s",
    /* msgFrameReceived     */      "Frame received from: %s:%d - %s",
    /* msgSocketNoneAvailable */    "All sockets in use - declined",
    /* msgSocketInitError   */      "Initialisation timed out (%d seconds) - aborting socket connection",
    /* msgSocketThreadTwice */      "Tried to start SocketFromBus() twice",
    /* msgSocketConnection  */      "Connection request from %s:%d",
    /* msgSocketEstablished */      "Socket connection established: #%d",
    /* msgSocketConnectionClosed */ "Connection %d: Client closed connection - terminating socket connection",
    /* msgSocketBadPacket   */      "Connection %d: Malformed request - too short",
    /* msgSocketBadCommand  */      "Connection %d: Unknown command: %c",
    /* msgSocketUnexpectedClose */  "Connection %d: Unexpectedly closed by client - aborting",
    /* msgSocketNoData      */      "Connection %d: No data received - timeout (%d seconds).",
    /* msgSocketSendAborted */      "Connection %d: Could not send data to socket client: %s",
    /* msgSocketCommand     */      "Connection %d: Command request: %s 0x%08x",
    /* msgSocketIdentifier  */      "Connection %d: Identified as '%s'",
    /* msgSocketAuthenticate*/      "Connection %d: Authenticate user '%s'",
    /* msgSocketUnauthorised */     "Connection %d: Not authorised for '%s'",
    /* msgSocketAuthNoUser  */      "Connection %d: Unknown user '%s' or wrong password",
    /* msgSocketDHMinit     */      "Connection %d: Missing DHM prime for key exchange",
    /* msgSocketDHMFailure  */      "Connection %d: DHM failure (%08x) [%s]",
    /* msgSocketBadParam    */      "Connection %d: Bad parameter (%s)",
    /* msgSocketReadData    */      "Connection %d: %d bytes received: %s",
    /* msgSocketResult      */      "Connection %d: %s - %s",
    /* msgSocketRequestHeader */    "Connection %d: Request header received: %s",
    /* msgSocketStatusInfo  */      "Connection %d: Status info: %s %s",
    /* msgSocketForward     */      "Connection %d: Forwarding %s",
    /* msgEIBDNoneAvailable */      "All client connections in use - declined",
    /* msgEIBDThreadTwice   */      "Tried to start EIBD forwarded twice",
    /* msgEIBDSendAborted   */      "Connection %d: Could not send data packet to client: %s",
    /* msgEIBDRequestHeader */      "Connection %d: Request header received: %s- %s",
    /* msgEIBDReset         */      "Connection %d: Reset",
    /* msgEIBDConGroupMon   */      "Connection %d: Group monitor %s",
    /* msgEIBDConGroup      */      "Connection %d: New group connection, address=%s %s",
    /* msgEIBDConBroadcast  */      "Connection %d: New broadcast %s",
    /* msgEIBDConMonitor    */      "Connection %d: New monitor (%s)",
    /* msgEIBDNotImplemented */     "Connection %d: Command %04x not implemented",
    /* msgEIBDBadCommand    */      "Connection %d: Bad command %s (%04x) received",
    /* msgEIBDBadPacket     */      "Connection %d: Request header too short - %d bytes",
    /* msgEIBDResponse      */      "Connection %d: Response: %s",
    /* msgTCPNoListener     */      "Unable to start TCP listener: %s",
    /* msgTCPConnection     */      "Unable to accept TCP connection: %s",
    /* msgUnixFileExists    */      "'%s' already exists - unable to create listening socket (%d - %s)",
    /* msgUnixNoListener    */      "Unable to start socket listener: %s",
    /* msgUnixConnection    */      "Unable to accept socket connection: %s",
    /* msgSecurityBlock     */      "Blocked request from %s:%d (rule %d)",
    /* msgInternalQueue     */      "WARNING: Tried to remove request from queue although it hasn't been handled by all threads. Possible memory leak!",
};


char *logInit( void )
{
    char    path[BUFSIZ];
    char    *err;
    
    // register additional log levels
    if( zlogLevelSetName( zlogLevelCustom0, "TRS" ) != 0 ) return( zlogErrorString( zlogErrno ));
    if( zlogLevelSetName( zlogLevelCustom1, "TRT" ) != 0 ) return( zlogErrorString( zlogErrno ));
    if( zlogLevelSetName( zlogLevelCustom2, "TRE" ) != 0 ) return( zlogErrorString( zlogErrno ));
    if( zlogLevelSetName( zlogLevelCustom3, "ADM" ) != 0 ) return( zlogErrorString( zlogErrno ));
    
    // load pth appenders
    sprintf( path, "%s/app_pth_file.so", zlogPluginDir() );
    if( (err = zlogPluginLoad( path )) != NULL ) {
        return( err );
    }
    sprintf( path, "%s/app_pth_udp.so", zlogPluginDir() );
    if( (err = zlogPluginLoad( path )) != NULL ) {
        return( err );
    }
    
    if( (logModuleMain = getLogger( "Main" )) == NULL ) return( zlogErrorString( zlogErrno ));
    if( (logModuleConfig = getLogger( "Config" )) == NULL ) return( zlogErrorString( zlogErrno ));
    if( (logModuleEIBnetClient = getLogger( "EIBnet/IP Client" )) == NULL ) return( zlogErrorString( zlogErrno ));
    if( (logModuleEIBDServer = getLogger( "EIBD Server" )) == NULL ) return( zlogErrorString( zlogErrno ));
    if( (logModuleEIBnetServer = getLogger( "EIBnet/IP Server" )) == NULL ) return( zlogErrorString( zlogErrno ));
    if( (logModuleSocketServer = getLogger( "TCP Server" )) == NULL ) return( zlogErrorString( zlogErrno ));
    
    return( NULL );
}


static void *getLogger( char *name )
{
    zlogLogger      logger;
    unsigned int    effective_level;
    
    // effective_level = (logLevel & zlogLevelDebug) ? logLevel : logLevel + zlogLevelDebug;
    effective_level = logLevel | ringLevel;
    if( (logger = zlogLoggerCreate( name, effective_level )) == NULL ) {
        return( NULL );
    }
    if( zlogLoggerAddAppender( logger, appender_standard, logLevel, 1 ) != 0 ) {
        return( NULL );
    }
    if( logLevel != effective_level && appender_ring != NULL ) {
        zlogLoggerAddAppender( logger, appender_ring, ringLevel, 0 );
    }
    return( logger );
}


void logSetLevel( unsigned int level )
{
    logLevel = level;
}


void logSetRingLevel( unsigned int level )
{
    ringLevel = level;
}


char *logSetDest( char *dest, int ringsize )
{
    char    ring[20];
    
    if( (appender_standard = zlogAppenderSimple( "eibnetmux", dest )) == NULL ) return( zlogErrorString( zlogErrno ));
    if( ringsize > 0 ) {
        sprintf( ring, "ring:%d", ringsize );
        appender_ring = zlogAppenderSimple( "eibnetmux_ring", ring );
    }
    return( NULL );
}


unsigned int logGetLevel( void )
{
    return( logLevel );
}


unsigned int logGetRingLevel( void )
{
    return( ringLevel );
}


void log_message( void *l, unsigned int level, int msgid, ... )
{
    char        *msg;
    va_list     ap;
    
    va_start( ap, msgid );
    
    // - message
    if( msgid == -1 ) {
        // debug message
        msg = va_arg( ap, char * );
    } else {
        msg = messages[msgid];
    }
    zlogv( l, level, msgid, msg, ap );
    va_end( ap );
}

void logDump( void *l )
{
    zlog( l, zlogLevelInfo, -1, "*********************" );
    zlog( l, zlogLevelInfo, -1, "* Dumping debug log *" );
    zlog( l, zlogLevelInfo, -1, "*********************" );
    zlogRingDump( l );
    zlog( l, zlogLevelInfo, -1, "*********************" );
    zlog( l, zlogLevelInfo, -1, "* Debug dump end    *" );
    zlog( l, zlogLevelInfo, -1, "*********************" );
}
