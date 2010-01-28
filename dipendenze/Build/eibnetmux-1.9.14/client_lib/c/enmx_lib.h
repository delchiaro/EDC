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
 * \if DeveloperDocs
 *   \brief Public defines, structures, function declarations
 * \endif
 */
 
#ifndef ENMX_LIB_H_
#define ENMX_LIB_H_

#include <stdint.h>

/*
 * error constants
 */
#define ENMX_NO_ERROR                 0              //!< Everything ok
#define ENMX_E_NO_ERROR               0              //!< Everything ok
#define ENMX_E_COMMUNICATION         -1              //!< Error communicating with EIBnetmux server
#define ENMX_E_SERVER_ABORTED        -2              //!< EIBnetmux server unexpectedly closed connection
#define ENMX_E_UNKNOWN_GROUP         -3              //!< KNX group unknown
#define ENMX_E_INTERNAL              -4              //!< EIBnetmux server experienced an internal error
#define ENMX_E_NO_MEMORY             -5              //!< Memory could not be allocated by the library for receive buffers, status structures, etc.
#define ENMX_E_TIMEOUT               -6              //!< Timeout while sending/receiving to EIBnetmux server
#define ENMX_E_WRONG_USAGE           -7              //!< This connection was already used for a different command
#define ENMX_E_AUTH_UNSUPPORTED      -8              //!< Authentication is not supported (either by server or by library)
#define ENMX_E_AUTH_FAILURE          -9              //!< User authentication failed (wrong username/password)
#define ENMX_E_DHM_FAILURE           -10             //!< DHM key exchange failed
#define ENMX_E_PARAMETER             -11             //!< Invalid parameter passed to library
#define ENMX_E_UNAUTHORISED          -12             //!< Not authorised to perform this function
#define ENMX_E_HOST_NOTFOUND         -13             //!< Specified host could not be found, no ip address available
#define ENMX_E_SEARCH                -14             //!< Either none or more than one EIBnetmux server(s) found. Specify target host
#define ENMX_E_SERVER_NOTRUNNING     -15             //!< EIBnetmux not running on host (or socketserver not activated)
#define ENMX_E_NOT_INITIALISED       -16             //!< Library not initialised, call enmx_init()
#define ENMX_E_NOCLIENTID            -17             //!< Client identifier must be specified
#define ENMX_E_REGISTER_CLIENT       -18             //!< Unable to register client identifier
#define ENMX_E_RESOURCE              -19             //!< System resource problem
#define ENMX_E_NO_CONNECTION         -20             //!< Invalid connection handle
#define ENMX_E_VERSIONMISMATCH       -21             //!< Library does not match/support version of EIBnetmux server
#define ENMX_E_L7_NO_CONNECTION      -22             //!< No connection with other device established
#define ENMX_E_L7_NAK_RECEIVED       -23             //!< Remote device replied with NAK
#define ENMX_E_L7_SEQUENCE           -24             //!< Remote device's answer was not what we expected
#define ENMX_E_L7_BUFSIZE            -25             //!< Buffer not large enough to receive all data
#define ENMX_E_L7_MASK               -26             //!< Invalid mask version of remote device


/*
 * connection handle
 */
typedef int         ENMX_HANDLE;                //!< Variable type to indicate an EIBnetmux connection
typedef uint16_t    ENMX_ADDRESS;               //!< Variable type for KNX group addresses as used by the library


/*!
 * \brief Variable types returned by the conversion functions
 */
typedef enum _enmx_KNXTypes {
    enmx_KNXerror,
    enmx_KNXinteger,
    enmx_KNXfloat,
    enmx_KNXchar,
    enmx_KNXstring,
} enmx_KNXTypes;


/*
 * status structures
 */
/*!
 * \addtogroup xgMgmt
 * @{
 */
/*!
 * \brief status information for an active EIBnet/IP connection to eibnetmux
 */
typedef struct _sENMX_StatusEIB {
    uint32_t                conn_id;        //!< client's unique connection id, 0 if unassigned
    uint32_t                ip;             //!< client's IP address
    uint16_t                port;           //!< client's UDP port
    uint32_t                received;       //!< number of requests received from client
    uint32_t                sent;           //!< number of requests sent to client
    uint16_t                queue_len;      //!< number of requests in queue, waiting to be sent
    uint32_t                source_ip;      //!< eibnetmux' IP address used to communicate with client
    struct _sENMX_StatusEIB   *next;        //!< link to next connection in linked list
} sENMX_StatusEIB;

/*!
 * \brief status information for an active eibnetmux socketserver connection
 */
typedef struct _sENMX_StatusSocket {
    uint32_t                conn_id;        //!< client's unique connection id, 0 if unassigned
    uint32_t                ip;             //!< client's IP address
    uint16_t                port;           //!< client's TCP port
    uint32_t                received;       //!< number of requests received from client
    uint32_t                sent;           //!< number of requests sent to client
    uint16_t                queue_len;      //!< number of requests in queue, waiting to be sent
    char                    *name;          //!< client's identifier
    char                    *user;          //!< name of authenticated user (if any)
    struct _sENMX_StatusSocket   *next;     //!< link to next connection in linked list
} sENMX_StatusSocket;

/*!
 * \brief status information for an active eibd-compatible server connection
 */
typedef struct _sENMX_StatusEIBD {
    uint32_t                conn_id;        //!< client's unique connection id, 0 if unassigned
    uint32_t                ip;             //!< client's IP address
    uint16_t                port;           //!< client's TCP port
    uint32_t                received;       //!< number of requests received from client
    uint32_t                sent;           //!< number of requests sent to client
    struct _sENMX_StatusEIBD   *next;       //!< link to next connection in linked list
} sENMX_StatusEIBD;

/*!
 * \brief status information of eibnetmux server
 */
typedef struct _sEibnetmuxStatus {
    int                     status_version;     //!< version of status information supported by eibnetmux server, indicates which fields are filled in
    struct {
        int                 status_version;         //!< version of common block status information, indicates valid fields 
        char                *version;               //!< server version string
        int                 loglevel;               //!< server's log level
        uint32_t            uptime;                 //!< current uptime of server, in seconds
        uint16_t            uid;                    //!< unix user id server is running under
        uint16_t            gid;                    //!< unix group id server is running under
        int                 daemon;                 //!< true if server is running in daemon mode
    } common;                                   //!< generic server status
    struct {
        int                 status_version;         //!< version of client block status information, indicates valid fields
        int                 connected;              //!< true if connected to upstream EIBnet/IP server such as N148/21
        uint32_t            uptime;                 //!< time in seconds since client is connected
        uint32_t            session_received;       //!< number of requests received since client is connected
        uint32_t            session_sent;           //!< number of requests sent since client is connected
        uint32_t            total_received;         //!< number of requests received since first client connection was established
        uint32_t            total_sent;             //!< number of requests sent since first client connection was established
        uint16_t            queue_len;              //!< number of requests in queue, waiting to be sent
        uint16_t            missed_heartbeat;       //!< number of EIBnet/IP heartbeats missed
        char                *target_name;           //!< name of upstream EIBnet/IP server
        uint32_t            target_ip;              //!< IP address of upstream EIBnet/IP server
        uint16_t            target_port;            //!< UDP port used for control connection by upstream EIBnet/IP server (should generally be 3601)
        uint32_t            source_ip;              //!< eibnetmux' IP address used to communicate with upstream server
        uint8_t             loopback;               //!< set to 2 if EIBnetmux operates in loopback mode and has no connection to a KNX bus
    } client;                                   //!< eibnetmux client status
    struct {
        int                 status_version;         //!< version of EIBnet/IP server block status information, indicates valid fields
        int                 active;                 //!< true if EIBnet/IP server is active
        uint16_t            port;                   //!< UDP port used to receive requests
        int                 max_connections;        //!< maxmimum number of EIBnet/IP clients
        int                 nr_clients;             //!< number of currently connected clients
        uint32_t            received;               //!< number of requests received
        uint32_t            sent;                   //!< number of requests sent
        uint16_t            queue_len;              //!< number of requests in queue, waiting to be sent
        uint16_t            default_level;          //!< default authorisation level
        uint16_t            access_block;           //!< block all access above this authorisation level
        sENMX_StatusEIB     *clients;               //!< pointer to linked list of clients
    } server;                                   //!< eibnetmux EIBnet/IP server status
    struct {
        int                 status_version;         //!< version of socketserver block status information, indicates valid fields
        int                 active_tcp;             //!< true if TCP socketserver is active 
        int                 active_unix;            //!< true if named pipe socketserver is active
        uint16_t            port;                   //!< TCP used to receive requests
        char                *path;                  //!< name of named pipe
        int                 max_connections;        //!< maximum number of socketserver clients
        int                 nr_clients;             //!< number of currently connected clients
        uint32_t            received;               //!< number of requests received
        uint32_t            sent;                   //!< number of requests sent
        uint16_t            queue_len;              //!< number of requests in queue, waiting to be sent
        int                 authentication;         //!< true if eibnetmux supports authentication
        sENMX_StatusSocket  *clients;               //!< pointer to linked list of clients
    } socketserver;                             //!< eibnetmux socketserver status
    struct {
        int                 status_version;         //!< version of eibd-compatible server block status information, indicates valid fields
        int                 active;                 //!< true if EIBD server is active
        uint16_t            port;                   //!< TCP used to receive requests
        int                 max_connections;        //!< maximum number of eibd clients
        int                 nr_clients;             //!< number of currently connected clients
        uint32_t            received;               //!< number of requests received
        uint32_t            sent;                   //!< number of requests sent
        uint16_t            queue_len;              //!< number of requests in queue, waiting to be sent
        sENMX_StatusEIBD    *clients;               //!< pointer to linked list of clients
    } eibd;                                     //!< eibnetmux eibd-server status
} sENMX_Status;
/*! @} */

/*!
 * \addtogroup xgSetup
 * @{
 */
/*!
 * \brief information of EIBnet/IP servers responding to multicast search request
 */
typedef struct _sENMX_Server {
    uint32_t                ip;                 //!< IP address of server
    uint16_t                port;               //!< UDP port address of server's EIBnet/IP control connection (usually 3601)
    char                    *version;           //!< version information
    char                    *hostname;          //!< name of host running server
    int                     eibnetmux;          //!< true if server is eibnetmux
    struct _sENMX_Server    *next;              //!< link to next server in linked list
} sENMX_Server;
/*! @} */

/*
 * function declarations
 */
extern int                  enmx_init( void );
extern ENMX_HANDLE          enmx_open( char *hostname, char *myname );
extern ENMX_HANDLE          enmx_pth_open( char *hostname, char *myname );
extern void                 enmx_close( ENMX_HANDLE conn );
extern char *               enmx_gethost( ENMX_HANDLE handle );
extern int                  enmx_auth( ENMX_HANDLE handle, char *user, char *password );
extern int                  enmx_write( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t length, unsigned char *value );
extern unsigned char *      enmx_read( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t *length );
extern unsigned char *      enmx_monitor( ENMX_HANDLE handle, ENMX_ADDRESS mask, unsigned char *buf, uint16_t *buflen, uint16_t *length );
extern int                  enmx_geterror( ENMX_HANDLE handle );
extern char *               enmx_errormessage( ENMX_HANDLE handle );
extern sENMX_Server *       enmx_getservers( int seconds );
extern sENMX_Server *       enmx_pth_getservers( int seconds );
extern void                 enmx_releaseservers( sENMX_Server *list );
extern unsigned int         enmx_frame2value( int eis, void *cemiframe, void *value );
extern unsigned int         enmx_eis2value( int eis, unsigned char *datastream, int length, void *value );
extern int                  enmx_value2eis( int eis, void *buf, unsigned char *datastream );
extern ENMX_ADDRESS         enmx_getaddress( const char *KNXgroup );
extern char *               enmx_getgroup( ENMX_ADDRESS knxaddress );
extern int                  enmx_mgmt_connect( ENMX_HANDLE handle );
extern int                  enmx_mgmt_disconnect( ENMX_HANDLE handle );
extern int                  enmx_mgmt_getloglevel( ENMX_HANDLE handle );
extern int                  enmx_mgmt_setloglevel( ENMX_HANDLE handle, uint16_t level );
extern int                  enmx_mgmt_close_session( ENMX_HANDLE handle, int session_type, uint32_t session_id );
extern sENMX_Status *       enmx_mgmt_getstatus( ENMX_HANDLE handle );
extern void                 enmx_mgmt_releasestatus( sENMX_Status *status );
extern int                  enmx_L7_connect( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress );
extern int                  enmx_L7_disconnect( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress );
extern int                  enmx_L7_readmemory( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t offset, uint16_t length, unsigned char *buf );
extern int                  enmx_L7_writememory( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t offset, uint16_t length, unsigned char *buf );
extern int                  enmx_L7_reset( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress );


/*
 * global variables
 */
extern int                  enmx_EISsizeC[];
extern int                  enmx_EISsizeKNX[];

#endif /*ENMX_LIB_H_*/
