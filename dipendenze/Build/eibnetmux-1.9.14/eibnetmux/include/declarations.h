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
 * Function and variable declarations
 */
 
#ifndef DECLARATIONS_H_
#define DECLARATIONS_H_

/*
 * function declarations
 */
// main.c
extern char     *eibnetmuxStatus( void );

// config.c
extern int      ConfigLoad( int argc, char **argv );
extern sSecurityConfig *configReadSecurity( void );
extern void     configSecurityReleaseMemory( sSecurityConfig *secConf );
extern void     Usage( char *progname );

// network.c
extern int      init_network( void );
extern int      network_getsourceaddress( uint32_t dest, uint32_t *src );

// util.c
extern void     Shutdown( void );
extern char     *hexdump( void *logger, void *string, int len );
extern char     *ip_addr( uint32_t ip, char *buf );
extern char     *knx_group( void *logger, uint16_t knxaddress );
extern char     *knx_physical( void *logger, uint16_t knxaddress );
extern void     *allocMemory( void *logger, size_t size );
// extern void     *mempcpy( void *dest, void *source, uint16_t len );
extern void     AbortSignalHandler( int signal );
extern uint16_t AppendBytes( uint16_t index, char *buf, uint16_t size, uint32_t value );
extern int      round_double( double real );
extern uint16_t min16( uint16_t v1, uint16_t v2 );
extern int      fromHex( unsigned char c, unsigned char *r );
extern uint32_t getConnectionId( void *logger, int (*getids)( void *system, uint32_t **array, int entries, uint32_t threshold ));
extern int      readFromSocket( void *logger, int sock, int clientid, void *ptr, uint16_t bytes, uint16_t maxbytes, unsigned int timeout );

// server.c
extern char     *EIBnetServerStatus( void );
extern void     *EIBnetServer( void *arg );

// client.c
extern char     *EIBnetClientStatus( void );
extern void     EIBnetClientSwitchConnectionType( uint8_t type );
extern void     EIBnetClientSetState( uint8_t newstate );
extern void     *EIBnetClient( void *arg );

// eibnetip.c
extern int      eibGetUsedIds( void *system, uint32_t **array, int entries, uint32_t threshold );
extern int      eibNetCloseConnection( uint32_t connectionid );

// socketserver.c
extern void     *SocketTCP( void *arg );
extern void     *SocketUnix( void *arg );
extern int      socketGetUsedIds( void *system, uint32_t **array, int entries, uint32_t threshold );

// eibdserver.c
extern char     *eibdServerStatus( void );
extern void     *EIBDListener( void *arg );

/*
 * global variables declarations
 */
extern boolean                  exitSelected;
extern uint8_t                  runMode;
extern sConfig                  config;
extern uint32_t                 MyIpAddress;
extern sShutdownHandlers        callbacks[shutdownEntries];
extern pth_cond_t               condQueueServer;
extern pth_cond_t               condQueueClient;
extern pth_cond_t               condQueueSocket;
extern pth_t                    tid_main;
extern pth_mutex_t              mtxSocketForwarder;
extern pth_mutex_t              mtxQueueServer;
extern time_t                   startupTime;


#endif /*DECLARATIONS_H_*/
