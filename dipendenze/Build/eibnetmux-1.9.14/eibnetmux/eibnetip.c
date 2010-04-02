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

#define _GNU_SOURCE
#include <stdio.h>
#include <features.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <time.h>

#include <pth.h>

#include "eibnetmux.h"
#include "include/log.h"
#include "include/eibnetip_private.h"


/*
 * Globals
 */
EIBNETIP_CONNECTION     eibcon[EIBNETIP_MAXCONNECTIONS +1];             // saves all active connections
                                                                        //   0:   eibnet/ip client connecting to remote server
                                                                        //   1-x: eibnet/ip server


/*
 * local function declarations
 */
// handlers for various eibnet/ip layers
static void     handleCore( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType );
static void     handleDeviceManagement( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType );
static int      handleTunneling( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType );

// handlers for eibnet/ip core
static void     handleSearchRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );
static void     handleDescriptionRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );
static void     handleConnectRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType );
static void     handleConnectResponse( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );
static void     handleConnectionstateRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );
static void     handleConnectionstateResponse( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );
static void     handleDisconnectRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );
static void     handleDisconnectResponse( void *system, uint8_t *rcvdata, uint16_t rcvdatalen );

// helper functions
static uint8_t  checkConnection( void *system, EIBNETIP_CONNECTION *connection, EIBNETIP_COMMON_CONNECTION_HEADER *head );
static uint8_t  checkAcknowledgement( void *system, EIBNETIP_CONNECTION *connection, EIBNETIP_COMMON_CONNECTION_HEADER *conn_head );
static void     PrepareDeviceInformationDIB( EIBNETIP_DEVINF_DIB *dib, uint32_t my_ip );
static EIBNETIP_SUPPFAM_DIB *PrepareSupportedServicesDIB( void *system );
// static int      eibGetUsedIds( void *system, uint32_t **array, uint32_t threshold );

// cEMI functions
static void     cEMI_Mgmt_Server( void *system, uint8_t channelid, uint8_t *rcvdata, uint16_t rcvdatalen );


/**
 * implements eibnet/ip core
 * handles client & server side
 * e.g. SEARCH_REQUESTS, DESCRIPTION_REQUESTS, TUNNELLING_REQUESTS, ...
 **/
int EIBnetIPProtocolHandler( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType )
{
    // CEMI_L_DATA_MESSAGE     cemi;        // used for routing
    // EIBFRAME                eib;         //  "          "
    EIBNETIP_HEADER         *head;
    int                     not_done;
    
    // get eibnet/ip header
    head = (EIBNETIP_HEADER *) rcvdata; 
    
    // fix endian format
    head->servicetype = ntohs( head->servicetype );
    head->totalsize   = ntohs( head->totalsize );
    
    // perform some checks on packet
    // @todo: send error codes to sender
    if( head->headersize != HEADER_SIZE_10 ) {
        // wrong header size
        logDebug( system, "Protocol - Wrong header_size." );
        return( -1 );
    }
    if( head->version != EIBNETIP_VERSION_10 ) {
        // wrong version
        logDebug( system, "Protocol - Unsupported version." );
        return( -1 );
    }
    if( head->totalsize != rcvdatalen ) {
        // hmm... something went seriously wrong
        logDebug( system, "Protocol - Datasize does not match total size of packet" );
        return( -1 );
    }
    
    // pass data to next layer according to service type
    not_done = 0;
    switch( head->servicetype >> 8 ) {
        case EIBNETIP_CORE:
            handleCore( system, rcvdata, head->totalsize, secType );
            break;
        case EIBNETIP_DEVMGMT:
            handleDeviceManagement( system, rcvdata, head->totalsize, secType );
            break;
        case EIBNETIP_TUNNELING:
            not_done = handleTunneling( system, rcvdata, head->totalsize, secType );
            break;                  

        // -- not implemented --
        // case EIBNETIP_ROUTING:
        //     // hack
        //     // smoke up eib bus and pass every ip packet to bus
        //     eibCemiExtract( &cemi, &rcvdata[6] );
        //     
        //     eibCemiInitFrame( &eib, &cemi );
        // 
        //     sendEIBframe( UART_KNX0, &eib );
        //     
        //     break;

        // @todo: handle other layers
        
        default:
            logDebug( system, "Unsupported layer service type 0x%02x%02x.", head->servicetype >> 8, head->servicetype & 0xFF );
            break;
    }

    return( not_done );
}

/**
 * handles core service type
 **/
static void handleCore( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType )
{
    EIBNETIP_HEADER *head;

    // get eibnet/ip header
    head = (EIBNETIP_HEADER *) rcvdata;

    // pass data to next layer according to service type
    switch( head->servicetype ) {
        case SEARCH_REQUEST:
            handleSearchRequest( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        case DESCRIPTION_REQUEST:
            handleDescriptionRequest( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        case CONNECT_REQUEST:
            handleConnectRequest( system, &rcvdata[head->headersize], head->totalsize - head->headersize, secType );
            break;
        case CONNECT_RESPONSE:
            handleConnectResponse( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        case CONNECTIONSTATE_REQUEST:
            handleConnectionstateRequest( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        case CONNECTIONSTATE_RESPONSE:
            handleConnectionstateResponse( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        case DISCONNECT_REQUEST:
            handleDisconnectRequest( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        case DISCONNECT_RESPONSE:
            handleDisconnectResponse( system, &rcvdata[head->headersize], head->totalsize - head->headersize );
            break;
        default:
            logDebug( system, "Unsupported core service type 0x%02x.", head->servicetype );
            break;
    }
}

/**
 * handle Device Management Service Type
 **/
static void handleDeviceManagement( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType )
{
    EIBNETIP_COMMON_CONNECTION_HEADER ret_head;
    EIBNETIP_COMMON_CONNECTION_HEADER *conn_head;
    EIBNETIP_HEADER                   *req_head;
    EIBNETIP_CONNECTION               *conn;

    req_head = (EIBNETIP_HEADER *) rcvdata;
    conn_head = (EIBNETIP_COMMON_CONNECTION_HEADER *) &rcvdata[sizeof( EIBNETIP_HEADER )];

    // get connection
    conn = &eibcon[(system == EIBNETIP_SERVER) ? conn_head->channelid : 0];

    switch( req_head->servicetype ) {
        case DEVICE_CONFIGURATION_REQUEST:
            logDebug( system, "Device Management request" );
            ret_head.status = checkConnection( system, conn, conn_head );
            if( ret_head.status != E_NO_ERROR ) 
                    return; // some sort of error, do nothing
            
            // send ack
            ret_head.structlength = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
            ret_head.channelid = conn_head->channelid;
            ret_head.sequencecounter = conn_head->sequencecounter;
            eibNetIpSendControl( system, NULL, &conn->hpai, DEVICE_CONFIGURATION_ACK, (uint8_t *) &ret_head, sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ));
            cEMI_Mgmt_Server( system, conn_head->channelid, &rcvdata[sizeof( EIBNETIP_HEADER )], rcvdatalen - sizeof( EIBNETIP_HEADER ));
            break;
        case DEVICE_CONFIGURATION_ACK:
            // this is probably the acknowledgement to the device configuration request we sent back to the client
            // upon receiving a request from it (see cEMI_Mgmt_Server())
            // it is probably safe to ignore and discard
            logDebug( system, "Device Management ack" );
            // evaluate response
            (void) checkAcknowledgement( system, conn, conn_head );
            pth_cond_notify( conn->condResponse, TRUE );
            break;
        default:
            logDebug( system, "Unsupported device management service type 0x%02x.", req_head->servicetype );
            break;
    }
}

/**
 * handles tunneling service type
 **/
static int handleTunneling( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType )
{
    EIBNETIP_COMMON_CONNECTION_HEADER       ret_head;
    EIBNETIP_COMMON_CONNECTION_HEADER       *conn_head;
    EIBNETIP_HEADER                         *req_head;
    EIBNETIP_CONNECTION                     *conn;
    EIBNETIP_QUEUE                          *queue;
    CEMIFRAME                               *cemiframe;
    uint8_t                                 connid;
    // CEMI_L_DATA_MESSAGE                     cemi;
    // EIBFRAME                                eib;

    req_head = (EIBNETIP_HEADER *) rcvdata;
    conn_head = (EIBNETIP_COMMON_CONNECTION_HEADER *) &rcvdata[sizeof( EIBNETIP_HEADER )];
    cemiframe = (CEMIFRAME *) &rcvdata[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )];

    // get connection
    connid = conn_head->channelid;
    conn = &eibcon[(system == EIBNETIP_SERVER) ? connid : 0];

    switch( req_head->servicetype ) {
        case TUNNELLING_REQUEST:
            logDebug( system, "Tunneling request" );

            // check health and consistency of connection
            if( (ret_head.status = checkConnection( system, conn, conn_head )) != E_NO_ERROR ) {
                // return nack unless connection has been killed
                if( conn->hpai.hostprotocol != 0 ) {
                    ret_head.structlength    = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
                    ret_head.channelid       = conn_head->channelid;
                    ret_head.sequencecounter = conn_head->sequencecounter;
                    eibNetIpSendData( system, NULL, &conn->hpai, TUNNELLING_ACK, (uint8_t *) &ret_head, sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ));
                }
            }
            
            // check if we can forward request
            if( system == EIBNETIP_SERVER ) {
                if( config.eibConnectionType == eibConEIBNetIPTunnel && eibcon[0].channelid == 0 ) {
                    ret_head.status = E_KNX_CONNECTION;         // no connection to forward request to
                }
            }
            
            // check if client is authorised for this request
            // - rcvdata is the full eibnet/ip frame (header, connection header, cemiframe)
            // - logical/physical is determined by cemi(ntwrk)
            // - read/write is determined by cemi(apci)
            if( ret_head.status == E_NO_ERROR ) {
                switch( secType ) {
                	case secAddrTypeAllow:
                	    // all requests allowed
                		break;
                    case secAddrTypeDeny:
                        // doesn't get here - just make compiler happy
                        // full denial is already handled by eibnet/ip server thread
                        ret_head.status = E_NOT_AUTHORIZED;
                        break;
                	case secAddrTypeRead:
                        if( (cemiframe->ntwrk & EIB_DAF_GROUP) == 0 || (cemiframe->apci & 0x0080) ) {
                            // not allowed to send any requests to physical devices
                            // not allowed to send write requests to logical groups
                            ret_head.status = E_NOT_AUTHORIZED;
                        }
                		break;
                	case secAddrTypeWrite:
                	    if( (cemiframe->ntwrk & EIB_DAF_GROUP) == 0 ) {
                	        // not allowed to send requests to physical devices
                	        ret_head.status = E_NOT_AUTHORIZED;
                	    }
                		break;
                }
            }
            
            // return ack
            ret_head.structlength    = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
            ret_head.channelid       = conn_head->channelid;
            ret_head.sequencecounter = conn_head->sequencecounter;
            eibNetIpSendData( system, NULL, &conn->hpai, TUNNELLING_ACK, (uint8_t *) &ret_head, sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ));

            if( ret_head.status != E_NO_ERROR ) {
            	if( ret_head.status == E_NOT_AUTHORIZED ) {
            		// request not authorized
            		return( -2 );
            	}
                // don't forward if there was an error
                // abort connection after ACK
                return( -1 );
            }
            
            // add to forwarding queue and signal all waiting threads
            if( system == EIBNETIP_CLIENT ) {
                addRequestToQueue( system, &eibQueueServer, rcvdata, rcvdatalen );
                pth_cond_notify( &condQueueServer, TRUE );
            } else {
                addRequestToQueue( system, &eibQueueClient, rcvdata, rcvdatalen );
                pth_cond_notify( &condQueueClient, TRUE );
            }

            return( 1 );    // not done yet, still need rcvdata, allocate new buffer
            break;
        case TUNNELLING_ACK:
            logDebug( system, "Tunneling ack" );
            // evaluate response
            if( checkAcknowledgement( system, conn, conn_head ) == 0 ) {
                // clear pending flag of request for current connection
                if( system == EIBNETIP_SERVER ) {
                    for( queue = eibQueueServer; queue != NULL; queue = queue->next ) {
                        if( queue->pending_eibnet & (1 << connid) ) {
                            queue->pending_eibnet &= ~(1 << connid);
                            logDebug( system, "Cleared pending flag on connection %d (entry %d @ %08x, pending=%02x)", connid, queue->nr, queue, queue->pending_eibnet );
                            break;
                        }
                    }
                } else {        // system = EIBNETIP_CLIENT
                    eibQueueClient->pending_eibnet = 0;
                    connid = 0;
                }

                // tell tunneling sender (in eibNetIpSendWithWait()) that request has been acknowledged
                pth_cond_notify( eibcon[connid].condResponse, TRUE );
                eibcon[connid].nextsend = 0;
                eibcon[connid].counter  = 0;

                // wakeup tunneling sender to send next entry (if available)
                // otherwise, it would wait until old .nextsend
                pth_cond_notify( (system == EIBNETIP_SERVER) ? &condQueueServer : &condQueueClient, TRUE );
            }
            break;
        default:
            logDebug( system, "Unsupported tunnelling service type 0x%02x.", req_head->servicetype );
            break;
    }
    return( 0 );
}


/**
 * checks connection header
 * e.g sequence number, channelid, ...
 * increments receiver sequence counter
 **/
static uint8_t checkConnection( void *system, EIBNETIP_CONNECTION *connection, EIBNETIP_COMMON_CONNECTION_HEADER *head )
{
    if( head->channelid != connection->channelid || connection->channelid == 0 ) {
        logDebug( system, "Invalid channel id: 0x%02x", head->channelid );
        return E_CONNECTION_ID;
    }

    if( head->sequencecounter == connection->sequencecounter_rcv ) {
        // sequence numbers match - everything ok
        // next request should have new sequence number
        connection->sequencecounter_rcv++;
    } else if( head->sequencecounter == connection->sequencecounter_rcv -1 ) {
        // client missed our ack and resent request
        // resend our reply (with same sequence number)
    } else {
        // out of sequence
        logDebug( system, "Bad sequence counter: 0x%02x, expected: 0x%02x", head->sequencecounter, connection->sequencecounter_rcv );
        return E_SEQUENCE_NUMBER;
    }

    return E_NO_ERROR;
}

/**
 * checks connection header of acknowledgement
 * e.g sequence number, channelid, ...
 * increments sender sequence counter
 **/
static uint8_t checkAcknowledgement( void *system, EIBNETIP_CONNECTION *connection, EIBNETIP_COMMON_CONNECTION_HEADER *conn_head )
{
    uint8_t         result = 0;
    
    if( conn_head->channelid != connection->channelid ) {
        result = E_CONNECTION_ID;
        logDebug( system, "Wrong ack: channel id: %02x/%02x", connection->channelid, conn_head->channelid );
    }
    if( conn_head->sequencecounter != connection->sequencecounter_sent ) {
        result = E_SEQUENCE_NUMBER;
        logDebug( system, "Wrong ack: sequence counter: %02x/%02x", connection->sequencecounter_sent, conn_head->sequencecounter );
    }
    if( conn_head->status != E_NO_ERROR ) {
        result = conn_head->status;
        logDebug( system, "Wrong ack: error code : 00/%02x", conn_head->status );
    }
    if( result != 0 ) {
        // some error happened, close connection
        // client:
        //      no need to send disconnect request for client
        //      next request will return E_CONNECTION_ID
        // server:
        //      should probably send disconnect request
        eibNetClearConnection( connection );
    } else {
        connection->sequencecounter_sent++;
    }
    
    logDebug( system, "Ack checked: %02x", result );
    return( result );
}

/**
 * helper function for preparing device information dib
 * memory has to be allocated outside
 * only called on server side
 **/
static void PrepareDeviceInformationDIB( EIBNETIP_DEVINF_DIB *dib, uint32_t my_ip )
{
    int                     sock;
    struct sockaddr_in      *ipaddr;
    struct ifconf           ifnetconfig;
    struct ifreq            *ifconfig;
    struct ifreq            ifr;
    int                     result;
    int                     loop;
    char                    *ifname;
    char                    mac_address[6];
    char                    buf[BUFSIZ];
    char                    ip_text[BUFSIZE_IPADDR];
    
    // find interface for my ip address
    sock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
    ifnetconfig.ifc_len = BUFSIZ;
    ifnetconfig.ifc_buf = buf;
    ifname = "eth0";     // default: assume eth0
    if( ioctl( sock, SIOCGIFCONF, &ifnetconfig ) == 0 ) {
        ifconfig = ifnetconfig.ifc_req;
        for( loop = ifnetconfig.ifc_len / sizeof( struct ifreq ); --loop >= 0; ifconfig++ ) {
            ipaddr = (struct sockaddr_in *) &ifconfig->ifr_addr;
            logDebug( logModuleEIBnetServer, "Checking %s", ip_addr( ipaddr->sin_addr.s_addr, ip_text ));
            if( ipaddr->sin_addr.s_addr == my_ip ) {
                ifname = ifconfig->ifr_name;
                break;
            }
        }
    }
    logDebug( logModuleEIBnetServer, "Interface found: %s", ifname );
    
    memset( &mac_address, '\0', sizeof( mac_address ));
    memset( &ifr, '\0', sizeof( ifr ));
    strcpy( ifr.ifr_name, ifname );
    result = ioctl( sock, SIOCGIFHWADDR, &ifr );
    close( sock );

    if( result == 0 ) {
        memcpy( mac_address, ifr.ifr_hwaddr.sa_data, 6 );
    }

    dib->structlength                       = sizeof( EIBNETIP_DEVINF_DIB );
    dib->descriptiontypecode                = DEVICE_INFO;
    dib->knxmedium                          = CONFIG_KNXMEDIUM;
    dib->devicestatus                       = 0x01;                                 // program mode
    dib->eibaddress                         = htons( eibcon[0].knxaddress );
    dib->projectinstallationidentifier      = PROJECT_INSTALLATION_ID;
    dib->serialnumber[0]                    = CONFIG_SN0;
    dib->serialnumber[1]                    = CONFIG_SN1;
    dib->serialnumber[2]                    = CONFIG_SN2;
    dib->serialnumber[3]                    = CONFIG_SN3;
    dib->serialnumber[4]                    = CONFIG_SN4;
    dib->serialnumber[5]                    = CONFIG_SN5;
    dib->multicastaddress                   = htonl( SYSTEM_SETUP_MULTICAST_ADDRESS );
    memcpy( dib->macaddress, mac_address, 6 );
    memset( dib->name, '\0', 30 );
    snprintf( (char *)dib->name, 30, "%s %s", FRIENDLY_NAME, VERSION );
}

/**
 * helper function for preparing supported services dib
 * memory has to be allocated outside
 * only called on server side
 **/
#define NR_SUPPORTED_SERVICES   3
static EIBNETIP_SUPPFAM_DIB *PrepareSupportedServicesDIB( void *system )
{
    EIBNETIP_SUPPFAM_DIB    *supp;
    uint8_t                 *supported;
    int                     i = 0;                          // index to services data

    supported = allocMemory( system, NR_SUPPORTED_SERVICES * 2 );
    supp = allocMemory( system, sizeof( EIBNETIP_SUPPFAM_DIB ) + NR_SUPPORTED_SERVICES * 2 -1 );

    supported[i++] = EIBNETIP_CORE;
    supported[i++] = 0x01;
    
    supported[i++] = EIBNETIP_DEVMGMT;
    supported[i++] = 0x01;

    supported[i++] = EIBNETIP_TUNNELING;
    supported[i++] = 0x01;

    // supported[i++] = EIBNETIP_ROUTING;
    // supported[i++] = 0x01;
    
    /*
     * should check for correct number of service entries
     * 
    if( i != NR_SUPPORTED_SERVICES ) {
        logDebug( system, "Error in setting up SupportedServicesDIB (expected %d entries, got %d)", NR_SUPPORTED_SERVICES, i );
    }
    */
    supp->structlength = 2 + ( NR_SUPPORTED_SERVICES * 2 );
    supp->descriptiontypecode = SUPP_SVC_FAMILIES;
    memcpy( &supp->serviceidandversion, supported, NR_SUPPORTED_SERVICES * 2 );
    free( supported );
    
    return( supp );
}

/**
 * handles search requests from eibnet/ip clients
 **/
static void handleSearchRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    char                    *response;            // search response
    EIBNETIP_HPAI           *hpai_own;            // own control endpoint
    EIBNETIP_DEVINF_DIB     *dib;                 // device information dib
    EIBNETIP_SUPPFAM_DIB    *supp;                // supported services dib
    EIBNETIP_HPAI           *hpai;
    int                     packetsize = 0;
    char                    *ptr;
    int                     r;
    char                    ip_text[BUFSIZE_IPADDR];

    hpai = (EIBNETIP_HPAI *) rcvdata;
    if( system != EIBNETIP_SERVER ) {
        logDebug( system, "Client received SearchRequest from %s:%d - do nothing", ip_addr( hpai->ip, ip_text ), ntohs( hpai->port ));
        return;
    }

    // extract discovery endpoint
    logDebug( system, "SearchRequest from %s:%d", ip_addr( hpai->ip, ip_text ), ntohs( hpai->port ));

    // prepare own hpai endpoint
    hpai_own = allocMemory( system, sizeof( EIBNETIP_HPAI ));
    hpai_own->structlength = sizeof( EIBNETIP_HPAI );        // struct_length
    hpai_own->hostprotocol = hpai->hostprotocol;
    hpai_own->port         = htons( config.eib_port );
    packetsize += hpai_own->structlength;
    
    // get my ip address for peer
    if( (r = network_getsourceaddress( hpai->ip, (uint32_t *)&hpai_own->ip )) != 0 ) {
        logError( system, msgEIBnetNoSourceIP, r );
    } else {
        logDebug( system, "Source IP: %s", ip_addr( hpai_own->ip, ip_text ));
    }
    
    // prepare device information dib
    dib = allocMemory( system, sizeof( EIBNETIP_DEVINF_DIB ));
    PrepareDeviceInformationDIB( dib, hpai_own->ip );
    packetsize += dib->structlength;

    // prepare supported services dib
    supp = PrepareSupportedServicesDIB( system );
    packetsize += supp->structlength;

    // prepare search response packet        
    response = allocMemory( system, packetsize );
    ptr = response;
    ptr = mempcpy( ptr, hpai_own, hpai_own->structlength );
    ptr = mempcpy( ptr, dib, dib->structlength );
    ptr = mempcpy( ptr, supp, supp->structlength );
    
    eibNetIpSendControl( system, NULL, hpai, SEARCH_RESPONSE, (uint8_t *) response, packetsize );

    if( response != NULL) free( response );
    if( supp != NULL) free( supp );
    if( dib != NULL) free( dib );
    if( hpai_own != NULL) free( hpai_own );
}


/**
 * handles description requests from eibnet/ip clients
 **/
static void handleDescriptionRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    char                        *response;            // search response
    EIBNETIP_DEVINF_DIB         *dib;                 // device information dib
    EIBNETIP_SUPPFAM_DIB        *supp;                // supported services dib
    EIBNETIP_MANUFACTURER_DIB   *manu;                // manufacturer data
    EIBNETIP_HPAI               *hpai;
    uint32_t                    my_ip;
    int                         packetsize = 0;
    int                         r;
    char                        *ptr;
    char                        ip_text[BUFSIZE_IPADDR];

    hpai = (EIBNETIP_HPAI *) rcvdata;
    if( system != EIBNETIP_SERVER ) {
        logDebug( system, "Client received DescriptionRequest from %s:%d - do nothing", ip_addr( hpai->ip, ip_text ), ntohs( hpai->port ));
        return;
    }

    // extract discovery endpoint
    logDebug( system, "DescriptionRequest from %s:%d", ip_addr( hpai->ip, ip_text ), ntohs( hpai->port ));

    // get my ip address for peer
    if( (r = network_getsourceaddress( hpai->ip, (uint32_t *)&my_ip )) != 0 ) {
        logError( system, msgEIBnetNoSourceIP, r );
        return;
    }
    
    // prepare device information dib
    dib = allocMemory( system, sizeof( EIBNETIP_DEVINF_DIB ));
    PrepareDeviceInformationDIB( dib, my_ip );
    packetsize = dib->structlength;

    // prepare supported services dib
    supp = PrepareSupportedServicesDIB( system );
    packetsize += supp->structlength;

    // prepare manufacturer data dib
    // it's optional and there's no docmentation available - leave it out
    manu = NULL;

    // prepare description response packet        
    response = allocMemory( system, packetsize );
    ptr = response;
    ptr = mempcpy( ptr, dib, dib->structlength );
    ptr = mempcpy( ptr, supp, supp->structlength );
    if( manu != NULL ) {
        ptr = mempcpy( ptr, manu, manu->structlength );
    }
    
    eibNetIpSendControl( system, NULL, hpai, DESCRIPTION_RESPONSE, (uint8_t *) response, packetsize );

    if( response != NULL) free( response );
    if( manu != NULL) free( manu );
    if( supp != NULL) free( supp );
    if( dib != NULL) free( dib );
}


/**
 * handles Connect Requests from client
 * and establishes connection
 **/
static void handleConnectRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType )
{
    EIBNETIP_HPAI               *hpai_control;
    EIBNETIP_HPAI               *hpai_data;
    EIBNETIP_CRI_CRD            *cri;
    EIBNETIP_CONNECT_RESPONSE   *response;
    uint8_t                     error = E_NO_ERROR;
    int                         tmp = 0;
    uint8_t                     channelid = 0;
    time_t                      seconds;
    int                         nr_clients;
    int                         r;
    char                        ip_text[BUFSIZE_IPADDR];

    hpai_control = (EIBNETIP_HPAI *) rcvdata;
    if( system != EIBNETIP_SERVER ) {
        logDebug( system, "Client received Connect request from %s:%d - do nothing", ip_addr( hpai_control->ip, ip_text ), ntohs( hpai_control->port ));
        return;
    }

    // extract control endpoint
    logDebug( system, "ConnectRequest from %s:%d", ip_addr( hpai_control->ip, ip_text ), ntohs( hpai_control->port ));

    // extract data endpoint
    hpai_data = (EIBNETIP_HPAI *) &rcvdata[hpai_control->structlength];

    // extract cri
    cri = (EIBNETIP_CRI_CRD *) &rcvdata[ hpai_control->structlength + hpai_data->structlength ];

    // prepare own hpai endpoint
    response = allocMemory( system, sizeof( EIBNETIP_CONNECT_RESPONSE ));
    response->dataendpoint.structlength = sizeof( EIBNETIP_HPAI );            // struct_length
    response->dataendpoint.hostprotocol = hpai_data->hostprotocol;
    response->dataendpoint.port         = htons( config.eib_port );
    
    // get my ip address for peer
    if( (r = network_getsourceaddress( hpai_control->ip, (uint32_t *)&response->dataendpoint.ip )) != 0 ) {
        logError( system, msgEIBnetNoSourceIP, r );
        free( response );
        return;
    } else {
        logDebug( system, "Source IP: %s", ip_addr( response->dataendpoint.ip, ip_text ));
    }
    
    // check, if new connection is supported
    // check for E_NO_MORE_CONNECTIONS
    // if no error, assign channelid
    error = E_NO_MORE_CONNECTIONS;
    seconds = time( NULL ) - HEARTBEAT_REQUEST_TIMEOUT;
    nr_clients = 0;
    for( tmp = 1; tmp <= EIBNETIP_MAXCONNECTIONS; tmp++ ) {
        // garbage collection of connections
        // if a connection has not seen a heartbeat for more than 120 seconds, clear it and make it available again
        if( eibcon[tmp].channelid != 0 ) {
            if( eibcon[tmp].lastHeartBeat < seconds ) {
                eibNetClearConnection( &eibcon[tmp] );
            } else {
                nr_clients++;
            }
        }
        if( eibcon[tmp].channelid == 0 || memcmp( &eibcon[tmp].hpai, hpai_data, sizeof( EIBNETIP_HPAI )) == 0 ) {
            // found empty slot or existing client is trying to re-connect
            channelid = tmp;                // channelid is always > 0 and <= EIBNET_MAXCONNECTIONS
            error = E_NO_ERROR;
            break;
        }
    }
    
    // check for E_CONNECTION_TYPE and E_CONNECTION_OPTION
    // if valid, pass to next layer
    tmp = -2;        // packet length offset
    if( error == E_NO_ERROR ) {
        switch( cri->connectiontypecode ) {
            case DEVICE_MGMT_CONNECTION:
                // prepare crd
                response->crd.structlength            = 0x02;
                response->crd.connectiontypecode      = cri->connectiontypecode;
                response->crd.protocolindependentdata = 0;
                response->crd.protocoldependentdata   = 0;
                error = E_NO_ERROR;
                break;
            case TUNNEL_CONNECTION:
                if( cri->structlength == 0x04 ) {
                    // determine tunnelling layer
                    switch( cri->protocolindependentdata ) {
                        case TUNNEL_LINKLAYER:
                            if( config.tunnelmode == cri->protocolindependentdata ) {
                                // connection already in standard tunneling mode
                                eibcon[channelid].connectioninfo = TUNNEL_LINKLAYER;
                            } else if( nr_clients == 0 ) {
                                // connection mode can be changed
                                eibcon[channelid].connectioninfo = TUNNEL_LINKLAYER;
                                // notify our client side
                                EIBnetClientSwitchConnectionType( TUNNEL_LINKLAYER );
                            } else {
                                logWarning( system, msgEIBnetTypeBlocked, config.tunnelmode, cri->protocolindependentdata, "standard tunnel connection" );
                                error = E_CONNECTION_TYPE;
                            }
                            break;
                        case TUNNEL_RAW:
                            logWarning( system, msgEIBnetBadType, "Raw tunneling" );
                            error = E_CONNECTION_TYPE;
                            break;
                        case TUNNEL_BUSMONITOR:
#ifdef WITH_BUSMONITOR
                            if( config.tunnelmode == cri->protocolindependentdata ) {
                                // connection already in bus monitoring mode
                                eibcon[channelid].connectioninfo = TUNNEL_BUSMONITOR;
                            } else if( nr_clients == 0 ) {
                                // connection mode can be changed
                                eibcon[channelid].connectioninfo = TUNNEL_BUSMONITOR;
                                // notify our client side
                                EIBnetClientSwitchConnectionType( TUNNEL_BUSMONITOR );
                            } else {
                                logWarning( system, msgEIBnetTypeBlocked, config.tunnelmode, cri->protocolindependentdata, "bus monitoring connection" );
                                error = E_CONNECTION_TYPE;
                            }
#else
                            logWarning( system, msgEIBnetBadType, "Bus monitor" );
                            error = E_CONNECTION_TYPE;
#endif
                            break;
                        default:
                            logWarning( system, msgEIBnetBadType, "unknown type" );
                            error = E_CONNECTION_TYPE;
                            break;
                    }
                } else {
                    // structure length not ok
                    logWarning( system, msgEIBnetBadType, "invalid length" );
                    error = E_CONNECTION_TYPE;
                }

                // prepare crd
                response->crd.structlength            = 0x04;
                response->crd.connectiontypecode      = cri->connectiontypecode;
                response->crd.protocolindependentdata = (eibcon[0].knxaddress >> 8) & 0xff;
                response->crd.protocoldependentdata   = (eibcon[0].knxaddress) & 0xff;
                tmp = 0;
                break;
            case REMLOG_CONNECTION:
                error = E_CONNECTION_TYPE;
                break;
            case REMCONF_CONNECTION:
                error = E_CONNECTION_TYPE;
                break;
            case OBJSVR_CONNECTION:
                error = E_CONNECTION_TYPE;
                break;
            default:
                logDebug( system, "Unsupported connection request. code:0x%e", cri->connectiontypecode );
                break;
        }       
    }
    
    // build response
    response->channelid    = channelid;
    response->status       = error;

    // if no error occured, establish connection by adding parameters
    // to eibcon[channelid]
    if( error == E_NO_ERROR ) {
        eibcon[channelid].connectionid          = getConnectionId( system, eibGetUsedIds );
        logDebug( system, "New EIBnet/IP connection - id %d", eibcon[channelid].connectionid );
        eibcon[channelid].channelid             = channelid;
        eibcon[channelid].sequencecounter_rcv   = 0;
        eibcon[channelid].sequencecounter_sent  = 0;
        eibcon[channelid].connectiontype        = cri->connectiontypecode;
        eibcon[channelid].lastHeartBeat         = time( NULL );
        eibcon[channelid].status                = E_NO_ERROR;
        memcpy( &eibcon[channelid].hpai, hpai_data, sizeof( EIBNETIP_HPAI ));
        eibcon[channelid].knxaddress            = eibcon[0].knxaddress;
        eibcon[channelid].ipSource              = response->dataendpoint.ip;
        eibcon[channelid].ipPort                = response->dataendpoint.port;
        eibcon[channelid].nextsend              = 0;
        eibcon[channelid].counter               = 0;
        eibcon[channelid].loopback              = loopbackUndefined;
        
        logVerbose( system, msgEIBnetTunnelEstablished, ip_addr( eibcon[channelid].hpai.ip, ip_text ));
        logDebug( system, "Connection established with %s:%d", ip_addr( eibcon[channelid].hpai.ip, ip_text ), ntohs( eibcon[channelid].hpai.port ));
    }
    
    // send response frame
    eibNetIpSendControl( system, NULL, hpai_control, CONNECT_RESPONSE, (uint8_t *) response, sizeof( EIBNETIP_CONNECT_RESPONSE ) + tmp );
    
    free( response );
}

/**
 * handles Connect Response from server
 * and activates connection
 **/
static void handleConnectResponse( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    EIBNETIP_CONNECT_RESPONSE       *response;
    int                             loop;
    char                            ip_text[BUFSIZE_IPADDR];

    if( system != EIBNETIP_CLIENT ) {
        logDebug( system, "Server received Connect response - do nothing" );
        return;
    }

    response = (EIBNETIP_CONNECT_RESPONSE *) rcvdata;
    if( response->status == E_NO_ERROR && response->crd.structlength == 4 /* && response->crd.connectiontypecode == request->crd.connectiontypecode */ ) {
        /*
         * connection successfully established
         */
        eibcon[0].channelid            = response->channelid;
        eibcon[0].sequencecounter_sent = 0;
        eibcon[0].sequencecounter_rcv  = 0;
        eibcon[0].status               = E_NO_ERROR;
        eibcon[0].knxaddress           = (response->crd.protocolindependentdata << 8) | response->crd.protocoldependentdata;
        eibcon[0].statsPacketsSent     = 0;
        eibcon[0].statsPacketsReceived = 0;
        // the following values have already been set by the connection request or are not used for the client
        // eibcon[0].connectiontype       = cri->connectiontypecode;
        // eibcon[0].lastHeartBeat        = NutGetSeconds();
        // eibcon[0].nextsend             = 0;
        // eibcon[0].counter              = 0;
        
        // check for loopback mode (EIBnetmux' client connects back to its eibnet/ip server)
        // at this point, both server & client sides have setup their connections completely 
        if( eibcon[0].loopback == loopbackUndefined ) {
            for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
                if( eibcon[loop].channelid > 0 ) {
                    if( eibcon[loop].hpai.port == eibcon[0].ipPort && eibcon[loop].hpai.ip == eibcon[0].ipSource ) {
                        eibcon[0].loopback = loopbackOn;
                        eibcon[loop].loopback = loopbackOn;
                        break;
                    }
                }
            }
            if( eibcon[0].loopback == loopbackUndefined) {
                eibcon[0].loopback = loopbackOff;
            }
        }
        if( eibcon[0].loopback == loopbackOn ) {
            logInfo( system, msgEIBnetLoopbackEstablished );
        } else {
            logInfo( system, msgEIBnetTunnelEstablished, ip_addr( eibcon[0].hpai.ip, ip_text ));
        }
    } else {
        eibcon[0].status               = response->status;
        logDebug( system, "Invalid connection response from server (%02x, %02x)", response->status, response->crd.structlength );
    }
    // signal sender thread
    pth_cond_notify( eibcon[0].condResponse, TRUE );
}

/**
 * handles Connectionstate Requests from clients
 * 
 * code is defensive and allows both sides slthough it is probably only used on server side
 **/
static void handleConnectionstateRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    EIBNETIP_HPAI           *hpai_control;
    EIBNETIP_CONNECTION     *conn;
    uint8_t                 response[2];
    char                    ip_text[BUFSIZE_IPADDR];

    response[1] = E_NO_ERROR;
    
    // extract channelid
    response[0] = rcvdata[0];
    
    // extract control endpoint
    hpai_control = (EIBNETIP_HPAI *) &rcvdata[2];
    logDebug( system, "ConnectionstateRequest from %s:%d", ip_addr( hpai_control->ip, ip_text ), ntohs( hpai_control->port ));

    // get connectiion
    conn = &eibcon[(system == EIBNETIP_SERVER) ? response[0] : 0];

    // no active data connection with this channelid
    if( conn->channelid == 0 ) {
            response[1] = E_CONNECTION_ID;
    } else {
        // get status of data connection
        response[1] = conn->status;
        conn->lastHeartBeat = time( NULL );
    }

    // send response frame
    eibNetIpSendControl( system, NULL, hpai_control, CONNECTIONSTATE_RESPONSE, (uint8_t *) &response, 2 );
}

/**
 * handles Connectionstate responses from remote server
 **/
static void handleConnectionstateResponse( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    if( system != EIBNETIP_CLIENT ) {
        logDebug( system, "Server received ConnectionState response - do nothing" );
        return;
    }

    if( rcvdata[0] != eibcon[0].channelid ) {
        logDebug( system, "Wrong heartbeat" );
    } else if( rcvdata[1] != E_NO_ERROR ) {
        logDebug( system, "Heartbeat failed - wrong status, connection closed" );
        eibNetClearConnection( &eibcon[0] );
    } else {
        logDebug( system, "Heartbeat response" );
        eibcon[0].counter = 0;          // number of "outstanding" heartbeats
    }
    // signal heartbeat thread
    pth_cond_notify( eibcon[0].condResponse, TRUE );
}

        
/**
 * handles Disconnect Requests from clients
 **/
static void handleDisconnectRequest( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    EIBNETIP_HPAI           *hpai_control;
    EIBNETIP_CONNECTION     *conn;
    uint8_t                 response[2];
    char                    ip_text[BUFSIZE_IPADDR];

    response[1] = E_NO_ERROR;
    
    // extract channelid
    response[0] = rcvdata[0];
    
    // extract control endpoint
    hpai_control = (EIBNETIP_HPAI *) &rcvdata[2];
    logDebug( system, "Received DisconnectRequest from %s:%d", ip_addr( hpai_control->ip, ip_text ), ntohs( hpai_control->port ));

    // get connection
    conn = &eibcon[(system == EIBNETIP_SERVER) ? response[0] : 0];

    // close channel
    eibNetClearConnection( conn );

    // send response frame
    eibNetIpSendControl( system, NULL, hpai_control, DISCONNECT_RESPONSE, (uint8_t *) &response, 2 );
}

/**
 * handles Disconnect response from remote server
 **/
static void handleDisconnectResponse( void *system, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    // on the server: ignore
    if( system == EIBNETIP_SERVER )
        return;
    
    // on the client: signal receiption to sender thread
    pth_cond_notify( eibcon[0].condResponse, TRUE );
}


/**
 * handle Management requests
 **/
static void cEMI_Mgmt_Server( void *system, uint8_t channelid, uint8_t *rcvdata, uint16_t rcvdatalen )
{
    EIBNETIP_COMMON_CONNECTION_HEADER       *conn_head;
    CEMI_MGMT_MESSAGE                       *cemi;
    EIBNETIP_HPAI                           hpai_data;
    char                                    *request;
    uint16_t                                request_length;
    
    // on the client: do nothing
    if( system == EIBNETIP_CLIENT )
        return;
    
    request_length = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMI_MGMT_MESSAGE );
    request = allocMemory( system, request_length );
    
    // prepare connection header
    conn_head = (EIBNETIP_COMMON_CONNECTION_HEADER *) request;
    conn_head->structlength    = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
    conn_head->channelid       = eibcon[channelid].channelid;
    conn_head->status          = 0;

    // prepare cEMI message
    // from exchange of ETS 3.0 with Siemens N148/21:
    //      from ETS:  fc 00 0b 01 01 10 45
    //      from N148: fb 00 0b 01 01 00 45
    // we mirror the message of the N148
    cemi = (CEMI_MGMT_MESSAGE *) &request[sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )];
    cemi->mc      = M_PROP_READ_CON;
    cemi->ioth    = 0x00;
    cemi->iotl    = 0x0b;
    cemi->oi      = 0x01;
    cemi->pid     = 0x01;
    cemi->noe_six = 0x4500;
    cemi->data    = 0x00;
    
    // prepare receiver information
    hpai_data.structlength = sizeof( EIBNETIP_HPAI );
    hpai_data.hostprotocol = eibcon[channelid].hpai.hostprotocol;
    hpai_data.ip           = eibcon[channelid].hpai.ip;
    hpai_data.port         = eibcon[channelid].hpai.port;
            
    // finally, send device configuration management request
    // there will be an acknowledge from the client but we don't care about it
    // it will be received by our normal server receiver and then discarded
    setupSignalling( system, channelid );
    eibNetIpSendControl( system, &eibcon[channelid], &hpai_data, DEVICE_CONFIGURATION_REQUEST, (uint8_t *) request, request_length );
    releaseSignalling( channelid );
    
    free( request );
}


/**
 * Return list of all allocated connection ids
 **/
int eibGetUsedIds( void *system, uint32_t **array, int entries, uint32_t threshold )
{
    int     loop;
    
    array = allocMemory( system, EIBNETIP_MAXCONNECTIONS * sizeof( uint32_t ));
    for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
        logDebug( system, "Checking state of EIBnet connection %d: channel %d, id %d", loop, eibcon[loop].channelid, eibcon[loop].connectionid );
        if( eibcon[loop].channelid != 0 && eibcon[loop].connectionid > threshold ) {
            *array[entries++] = eibcon[loop].connectionid;
        }
    }
    return( entries );
}


/**
 * Close connection with connection id
 */
int eibNetCloseConnection( uint32_t connectionid )
{
    int                     loop;
    
    for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
        if( eibcon[loop].channelid != 0 && eibcon[loop].connectionid == connectionid ) {
            eibNetClearConnection( &eibcon[loop] );
            return( 0 );
        }
    }
    
    return( -1 );
}
