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
 
#ifndef EIBNETMUX_H_
#define EIBNETMUX_H_


/*
 * configuration
 */

/*********************************************
 *                                           *
 * no configurable settings below this point *
 *                                           *
 *********************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#ifdef WITH_AUTHENTICATION
#include <polarssl/dhm.h>
#endif

#include "include/types.h"
#include "include/util.h"

#include "include/eibnetip.h"
#include "include/socketserver.h"

/*
 * constants
 */
#define false                   0
#define true                    1
#define MP_SHUTDOWN             "shutdown"

#define SERVER_EIBNET           1
#define SERVER_TCP              2
#define SERVER_UNIX             4
#define SERVER_EIBD             8

#define BUFSIZE_IPADDR          17


/*
 * enum constants
 */
typedef enum _eRunMode {
    runStartup,
    runNormal,
    runShutdown,
} eRunMode;

typedef enum _eEIBConnection {
    eibConEIBD,
    eibConEIBNetIPTunnel,
    eibConEIBNetIPRouter,
    eibConTPuart,
    eibConFT12
} eEIBConnection;

typedef enum _eLogType {
    logTypeNone,
    logTypeUDP,
    logTypeSyslog,
    logTypeFile,
    logTypeRing,
} eLogType;

typedef enum _eSecAddrType {
    // keep these in "ascending" order, from less to more access
    secAddrTypeDeny,
    secAddrTypeRead,
    secAddrTypeWrite,
    secAddrTypeAllow,
} eSecAddrType;

typedef enum _eAuthFunctions {
    authNone = 0,
    authRead = 1,
    authWrite = 2,
    authMonitor = 4,
    authMgmtClient = 8,
    authMgmtStatus = 16,
    authMgmtLog = 32,
    authMgmtBlock = 64,
    authMgmtConnection = 128,
    authPassthrough = 256,
} eAuthFunctions;


/*
 * basic types
 */
typedef int         auth_t;


/*
 * declare structures
 */
typedef struct _sAuthorisation {
    int             level;
    auth_t          function_mask;
    struct _sAuthorisation  *next;
} sAuthorisation;

typedef struct _sSecurityAddr {
    eSecAddrType    type;
    uint32_t        address;            // only works for IPv4
    uint32_t        mask;               // only works for IPv4
    uint32_t        rule;
    struct _sSecurityAddr   *next;
} sSecurityAddr;

typedef struct _sSecurityUser {
    char            *name;
    unsigned char   hash[32];
    int             auth_level;
    auth_t          authorisation;
    struct _sSecurityUser   *next;
} sSecurityUser;

typedef struct _sSecurityConfig {
    sSecurityAddr   *secEIBnetip;
    sSecurityAddr   *secClients;
    sSecurityAddr   *secEIBD;
    eSecAddrType    maxAuthEIBnet;
    eSecAddrType    maxAuthEIBD;
    eSecAddrType    defaultAuthEIBnet;
    eSecAddrType    defaultAuthClient;
    eSecAddrType    defaultAuthEIBD;
    sSecurityUser   *secUsers;
    sAuthorisation  *secAuthorisations;
    auth_t          auth_anonymous;    
    auth_t          eibd_anonymous;    
#ifdef WITH_AUTHENTICATION
    dhm_context     *dhm;
#endif
} sSecurityConfig;

typedef struct {
    char            *system_name;
    char            *hostname;
    uint32_t        ip;
    uint8_t         eibConnectionType:4;
    uint8_t         daemon:1;
    uint8_t         tunnelmode;                 // monitor or not
    char            *eibConnectionParam;
    uint32_t        eibServerIP;
    uint16_t        eibServerPort;
    uint8_t         log_type;
    unsigned int    log_level;
    char            *log_dest;
    unsigned int    ring_level;
    int             ring_size;
    uint8_t         servers;
    uint32_t        eib_ip;
    uint16_t        eib_port;
    uint32_t        tcp_ip;
    uint16_t        tcp_port;
    uint32_t        eibd_ip;
    uint16_t        eibd_port;
    char            *unix_path;
    char            *pidfile;
    uid_t           user;
    gid_t           group;
    char            *security_file;
    sSecurityAddr   *secEIBnetip;
    sSecurityAddr   *secClients;
    sSecurityAddr   *secEIBD;
    eSecAddrType    maxAuthEIBnet;
    eSecAddrType    maxAuthEIBD;
    eSecAddrType    defaultAuthEIBnet;
    eSecAddrType    defaultAuthClient;
    eSecAddrType    defaultAuthEIBD;
    sSecurityUser   *secUsers;
    sAuthorisation  *secAuthorisations;
    auth_t          auth_anonymous;
    auth_t          eibd_anonymous;
#ifdef WITH_AUTHENTICATION
    dhm_context     *dhm;
#endif
    int             dump;
    uint16_t        socketclients;
    uint16_t        eibdclients;
} sConfig;

#include "include/declarations.h"

#endif /* EIBNETMUX_H_ */
