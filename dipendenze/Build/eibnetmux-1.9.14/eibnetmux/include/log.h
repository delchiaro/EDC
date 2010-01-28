/*
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2008 Urs Zurbuchen <going_nuts@users.sourceforge.net>
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
 
#ifndef LOG_H_
#define LOG_H_

#include <stdint.h>

#include <zlogger/zlogger.h>


/*
 * message ids
 */
typedef enum _eLogMsgId {
    msgInitPth,
    msgInitThread,
    msgInitNetwork,
    msgInitDaemon,
    msgConfigRead,
    msgConfigSection,
    msgConfigSyntax,
    msgConfigAddrType,
    msgConfigAddress,
    msgConfigMask,
    msgConfigLineTooLong,
    msgConfigLevelDup,
    msgConfigLevelUndef,
    msgConfigLevelInvalid,
    msgConfigHashInvalid,
    msgConfigDHMRead,
    msgConfigDHM_MPI,
    msgConfigSecurity,
    msgConfigSecurityError,
    msgConfigNoAuth,
    msgSwitchPersonality,
    msgPidFile,
    msgStartup,
    msgStartupEIBnetServer,
    msgStartupEIBClient,
    msgStartupTCPServer,
    msgStartupUnixServer,
    msgStartupEIBDServer,
    msgShutdown,
    msgMemory,
    msgEIBnetClientSuspend,
    msgEIBnetClientActive,
    msgEIBnetClientNoAddress,
    msgEIBnetClientHeartbeat,
    msgEIBnetSourceIPFixed,
    msgEIBnetNoSourceIP,
    msgEIBnetSocket,
    msgEIBnetTunnelEstablished,
    msgEIBnetLoopbackEstablished,
    msgEIBnetBadServer,
    msgEIBnetNoClientConnection,
    msgEIBnetNoMCast,
    msgEIBnetBadType,
    msgEIBnetTypeBlocked,
    msgEIBnetMonitorActive,
    msgIpAddress,
    msgFrameSent,
    msgFrameReceived,
    msgSocketNoneAvailable,
    msgSocketInitError,
    msgSocketThreadTwice,
    msgSocketConnection,
    msgSocketEstablished,
    msgSocketConnectionClosed,
    msgSocketBadPacket,
    msgSocketBadCommand,
    msgSocketUnexpectedClose,
    msgSocketNoData,
    msgSocketSendAborted,
    msgSocketCommand,
    msgSocketIdentifier,
    msgSocketAuthenticate,
    msgSocketUnauthorised,
    msgSocketAuthNoUser,
    msgSocketDHMinit,
    msgSocketDHMFailure,
    msgSocketBadParam,
    msgSocketReadData,
    msgSocketResult,
    msgSocketRequestHeader,
    msgSocketStatusInfo,
    msgSocketForward,
    msgEIBDNoneAvailable,
    msgEIBDThreadTwice,
    msgEIBDSendAborted,
    msgEIBDRequestHeader,
    msgEIBDReset,
    msgEIBDConGroupMon,
    msgEIBDConGroup,
    msgEIBDConBroadcast,
    msgEIBDConMonitor,
    msgEIBDNotImplemented,
    msgEIBDBadCommand,
    msgEIBDBadPacket,
    msgEIBDResponse,
    msgTCPNoListener,
    msgTCPConnection,
    msgUnixFileExists,
    msgUnixNoListener,
    msgUnixConnection,
    msgSecurityBlock,
    msgInternalQueue,
} eLogMsgId;


/*
 * logger references
 */
extern void         *logModuleMain;
extern void         *logModuleConfig;
extern void         *logModuleEIBnetClient;
extern void         *logModuleEIBDServer;
extern void         *logModuleEIBnetServer;
extern void         *logModuleSocketServer;


/*
 * function declarations
 */
extern char         *logInit( void );
extern void         logSetLevel( unsigned int level );
extern void         logSetRingLevel( unsigned int level );
extern char         *logSetDest( char *destination, int ringsize );
extern unsigned int logGetLevel( void );
extern unsigned int logGetRingLevel( void );
extern void         log_message( void *l, unsigned int level, int msgid, ... );
extern void         logDump( void *l );


/*
 * function definiktions
 * 
 * use these in your code
 */
#define logInfo(l,...)          log_message( l, zlogLevelInfo, __VA_ARGS__ )
#define logVerbose(l,...)       log_message( l, zlogLevelVerbose, __VA_ARGS__ )
#define logWarning(l,...)       log_message( l, zlogLevelWarning, __VA_ARGS__ )
#define logError(l,...)         log_message( l, zlogLevelError, __VA_ARGS__ )
#define logCritical(l,...)      log_message( l, zlogLevelCritical, __VA_ARGS__ )
#define logFatal(l,...)         log_message( l, zlogLevelFatal, __VA_ARGS__ )
#define logTraceClient(l,...)   log_message( l, zlogLevelTrace, __VA_ARGS__ )
#define logTraceServer(l,...)   log_message( l, zlogLevelCustom0, __VA_ARGS__ )
#define logTraceSocket(l,...)   log_message( l, zlogLevelCustom1, __VA_ARGS__ )
#define logTraceEIBD(l,...)     log_message( l, zlogLevelCustom2, __VA_ARGS__ )
#define logAdmin(l,...)         log_message( l, zlogLevelCustom3, __VA_ARGS__ )
#define logDebug(l,...)         log_message( l, zlogLevelDebug, -1, __VA_ARGS__ )

#endif /*LOG_H_*/
