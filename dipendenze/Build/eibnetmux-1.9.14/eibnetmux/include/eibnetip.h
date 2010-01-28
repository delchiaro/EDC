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
 * 
 * eibnet/ip client
 */
 
#ifndef EIBNETMUX_IP_H_
#define EIBNETMUX_IP_H_

#include <stdint.h>


/********************************/
/* Constants and structures     */
/********************************/

/**
 * configuration EIBNET/IP
 **/
#define EIBNETIP_PORT_NUMBER                    3671
#define EIBNETIP_MULTICAST_ADDRESS              "224.0.23.12"
#define SYSTEM_SETUP_MULTICAST_ADDRESS          0xE000170C                      /* 224.0.23.12 */


/**
 * common constants
 */
#define EIBNETIP_VERSION_10             0x10
#define HEADER_SIZE_10                  0x06


/**
 * eibnetip services
 * upper byte -> use mask for checking service type
 **/
#define EIBNETIP_CORE                   0x02
#define EIBNETIP_DEVMGMT                0x03
#define EIBNETIP_TUNNELING              0x04
#define EIBNETIP_ROUTING                0x05
#define EIBNETIP_REMLOG                 0x06
#define EIBNETIP_REMCONF                0x07
#define EIBNETIP_OBJSRV                 0x08

/**
 * core eibnetip services
 **/
#define SEARCH_REQUEST                  0x0201
#define SEARCH_RESPONSE                 0x0202
#define DESCRIPTION_REQUEST             0x0203
#define DESCRIPTION_RESPONSE            0x0204
#define CONNECT_REQUEST                 0x0205
#define CONNECT_RESPONSE                0x0206
#define CONNECTIONSTATE_REQUEST         0x0207
#define CONNECTIONSTATE_RESPONSE        0x0208
#define DISCONNECT_REQUEST              0x0209
#define DISCONNECT_RESPONSE             0x020A

/**
 * device management services
 **/
#define DEVICE_CONFIGURATION_REQUEST    0x0310
#define DEVICE_CONFIGURATION_ACK        0x0311

/**
 * tunneling services
 **/
#define TUNNELLING_REQUEST              0x0420
#define TUNNELLING_ACK                  0x0421
#define TUNNEL_LINKLAYER                0x02
#define TUNNEL_RAW                      0x04
#define TUNNEL_BUSMONITOR               0x80

/**
 * routing services
 **/
#define ROUTING_INDICATION              0x0530
#define ROUTING_LOST_MESSAGE            0x0531


/**
 * connection types
 **/
#define DEVICE_MGMT_CONNECTION          0x03
#define TUNNEL_CONNECTION               0x04
#define REMLOG_CONNECTION               0x06
#define REMCONF_CONNECTION              0x07
#define OBJSVR_CONNECTION               0x08


/**
 * error codes
 **/
/**
 * common error codes
 **/
#define E_NO_ERROR                      0x00
#define E_HOST_PROTOCOL_TYPE            0x01
#define E_VERSION_NOT_SUPPORTED         0x02
#define E_SEQUENCE_NUMBER               0x04
#define E_NOT_AUTHORIZED				0x05		// defined by uzu

/**
 * connect response status codes
 **/
#define E_CONNECTION_TYPE               0x22
#define E_CONNECTION_OPTION             0x23
#define E_NO_MORE_CONNECTIONS           0x24

/**
 * connectionstate_response status codes
 **/
#define E_CONNECTION_ID                 0x21
#define E_DATA_CONNECTION               0x26
#define E_KNX_CONNECTION                0x27

/**
 * tunneling connect_ack error codes
 **/
#define E_TUNNELING_LAYER               0x29


/**
 * device management device_configuration_ack status codes
 **/
//nix


/**
 * description information block
 **/
#define DEVICE_INFO                     0x01
#define SUPP_SVC_FAMILIES               0x02
#define MFR_DATA                        0xFE


/**
 * medium codes
 **/
#define TP0     0x01
#define TP1     0x02
#define PL110   0x04
#define PL132   0x08
#define RF      0x10


/**
 * host protocol codes
 **/
#define IPV4_UDP        0x01
#define IPV4_TCP        0x02


/**
 * timeout constants in seconds
 **/
#define CONNECT_REQUEST_TIMEOUT                         10
#define CONNECTIONSTATE_REQUEST_TIMEOUT                 10
#define DEVICE_CONFIGURATION_REQUEST_TIMEOUT            10
#define HEARTBEAT_REQUEST_TIMEOUT                       120
#define HEARTBEAT_INTERVAL                              60
#define ACKNOWLEDGEMENT_TIMEOUT                         5


/**
 * eibnet/ip object type
 **/
#define EIBNET_IP_OBJECT_TYPE                           13

/**

 * eibnet/ip property definitions
 **/
#define PID_PROJECT_INSTALLATION_ID                     51
#define PID_KNX_INDIVIDUAL_ADDRESSES                    52
#define PID_ADDITIONAL_INDIVIDUAL_ADDRESSES             53
#define PID_CURRENT_IP_ASSIGNMENT_METHOD                54
#define PID_IP_ASSIGNMENT_METHOD                        55
#define PID_IP_CAPABILITIES                             56
#define PID_CURRENT_IP_ADDRESS                          57
#define PID_CURRENT_SUBNET_MASK                         58
#define PID_CURRENT_DEFAULT_GATEWAY                     59
#define PID_IP_ADDRESS                                  60
#define PID_SUBNET_MASK                                 61
#define PID_DEFAULT_GATEWAY                             62
#define PID_DHCP_BOOTP_SERVER                           63
#define PID_MAC_ADDRESS                                 64
#define PID_SYSTEM_SETUP_MULTICAST_ADDRESS              65
#define PID_ROUTING_MULTICAST_ADDRESS                   66
#define PID_TTL                                         67
#define PID_EIBNETIP_DEVICE_CAPABILITIES                68
#define PID_EIBNETIP_DEVICE_STATE                       69
#define PID_EIBNETIP_ROUTING_CAPABILITIES               70
#define PID_PRIORITY_FIFO_ENABLED                       71
#define PID_QUEUE_OVERFLOW_TO_IP                        72
#define PID_QUEUE_OVERFLOW_TO_KNX                       73
#define PID_MSG_TRANSMIT_TO_IP                          74
#define PID_MSG_TRANSMIT_TO_KNX                         75
#define PID_FRIENDLY_NAME                               76


/**
 * structures
 **/
typedef struct __attribute__((packed)) {
    uint8_t  ctrl;
    uint16_t saddr;
    uint16_t daddr;
    uint8_t  ll_length;
    uint8_t  tpci;
    uint8_t  apci;
    uint8_t  data[16];
} EIBFRAME;

typedef struct __attribute__((packed)) {
    uint8_t  headersize;
    uint8_t  version;
    uint16_t servicetype;
    uint16_t totalsize;
} EIBNETIP_HEADER;

typedef struct __attribute__((packed)) {
    EIBNETIP_HEADER head;
    uint8_t  data;                          // placeholder for data (rest follows)
} EIBNETIP_PACKET;

typedef struct __attribute__((packed)) {
    uint8_t  structlength;
    uint8_t  hostprotocol;
    uint32_t ip;
    uint16_t port;
} EIBNETIP_HPAI;

typedef struct __attribute__((packed)) {
    uint8_t  structlength;
    uint8_t  connectiontypecode;
    uint8_t  protocolindependentdata;               // these two fields should be variable length
    uint8_t  protocoldependentdata;                 // but we don't use it anyway
} EIBNETIP_CRI_CRD;

typedef struct __attribute__((packed)) {
    uint8_t  structlength;
    uint8_t  descriptiontypecode;
    uint8_t  knxmedium;
    uint8_t  devicestatus;
    uint16_t eibaddress;
    uint16_t projectinstallationidentifier;
    uint8_t  serialnumber[6];
    uint32_t multicastaddress;
    uint8_t  macaddress[6];
    uint8_t  name[30];
} EIBNETIP_DEVINF_DIB;

typedef struct __attribute__((packed)) {
    uint8_t  structlength;
    uint8_t  descriptiontypecode;
    uint8_t  serviceidandversion;
} EIBNETIP_SUPPFAM_DIB;

typedef struct __attribute__((packed)) {
    uint8_t  structlength;
    uint8_t  descriptiontypecode;
    uint16_t manufacturerID;
    uint8_t  *data;
} EIBNETIP_MANUFACTURER_DIB;

typedef struct __attribute__((packed)) {
    EIBNETIP_HPAI endpoint;
    EIBNETIP_DEVINF_DIB devicehardware;
    EIBNETIP_SUPPFAM_DIB *supported;
} EIBNETIP_SEARCH_RESPONSE;

typedef struct __attribute__((packed)) {
    EIBNETIP_DEVINF_DIB *devicehardware;
    EIBNETIP_SUPPFAM_DIB *supported;
    EIBNETIP_MANUFACTURER_DIB *manufacturer;
} EIBNETIP_DESCRIPTION_RESPONSE;

typedef struct __attribute__((packed)) {
    EIBNETIP_HPAI control_endpoint;
    EIBNETIP_HPAI data_endpoint;
    EIBNETIP_CRI_CRD crd;
} EIBNETIP_CONNECT_REQUEST;

typedef struct __attribute__((packed)) {
    uint8_t  channelid;
    uint8_t  status;
    EIBNETIP_HPAI dataendpoint;
    EIBNETIP_CRI_CRD crd;
} EIBNETIP_CONNECT_RESPONSE;

typedef struct __attribute__((packed)) {
    uint8_t  channelid;
    uint8_t  status;
    EIBNETIP_HPAI control_endpoint;
} EIBNETIP_DISCONNECT_REQUEST;

typedef struct __attribute__((packed)) {
    uint8_t  structlength;
    uint8_t  channelid;
    uint8_t  sequencecounter;
    uint8_t  status;
} EIBNETIP_COMMON_CONNECTION_HEADER;

typedef struct __attribute__((packed)) {
    uint8_t  channelid;
    uint8_t  reserved;
    EIBNETIP_HPAI endpoint;
} EIBNETIP_CONNECTSTATE_REQUEST;


/**
 * cEMI Message Codes
 **/
#define L_BUSMON_IND            0x2B
#define L_RAW_IND               0x2D
#define L_RAW_REQ               0x10
#define L_RAW_CON               0x2F
#define L_DATA_REQ              0x11
#define L_DATA_CON              0x2E
#define L_DATA_IND              0x29
#define L_POLL_DATA_REQ         0x13
#define L_POLL_DATA_CON         0x25
#define M_PROP_READ_REQ         0xFC
#define M_PROP_READ_CON         0xFB
#define M_PROP_WRITE_REQ        0xF6
#define M_PROP_WRITE_CON        0xF5
#define M_PROP_INFO_IND         0xF7
#define M_RESET_REQ             0xF1
#define M_RESET_IND             0xF0


/*
 * cEMI frame structures
 */
typedef struct __attribute__((packed)) {
    uint8_t  mc;
    uint8_t  ioth;
    uint8_t  iotl;
    uint8_t  oi;
    uint8_t  pid;
    uint16_t noe_six;
    uint8_t  data;
} CEMI_MGMT_MESSAGE;
#define NOE(mgmt_message_noe_six)       mgmt_message_noe_six >> 12
#define SIX(mgmt_message_noe_six)       mgmt_message_noe_six & 0x0FFF

typedef struct __attribute__((packed)) {
    uint8_t  mc;
    uint8_t  addil;
    uint8_t  *addi;
    uint8_t  ctrl1;
    uint8_t  ctrl2;
    uint16_t saddr;
    uint16_t daddr;
    uint8_t  datal;
    uint8_t  *data;
} CEMI_L_DATA_MESSAGE;

typedef struct {
    uint8_t  length_type:1;
    uint8_t  poll:1;
    uint8_t  repeat_flag:1;
    uint8_t  ack_frame:1;
    uint8_t  priority:2;
    uint8_t  res:2;
} sCEMIctrl;

typedef struct {
    uint8_t  address_type:1;
    uint8_t  hopcount:3;
    uint8_t  res:4;
} sCEMIntwrk;

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

#endif /*EIBNETMUX_IP_H_*/
