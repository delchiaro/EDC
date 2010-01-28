<?php
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
 * socket client library for php
 */

/**
 * eibnetmux - PHP client library
 * 
 * EIBnetmux extends the IP-reach of the KNX bus and supports multiple concurrent clients.
 * In addition, it features a very simple, TCP/IP socket-based protocol which allows applications
 * to easily retrieve and set data from/on the bus.
 * This empowers developers to focus on their applications and implement these great and
 * long-wished for features without having to implement the rather complex,
 * not very well documented, timing critical, UDP-based EIBnet/IP protocol.
 * 
 * In particular, web application developers will like the possibility to use a 
 * simple scripting language such as PHP to gain access to the KNX bus.
 * 
 * This file implements the PHP client library. It consists of two important classes:
 * - eibnetmux		Class implementing the client interface with the eibnetmux server.
 * - KNXgroup		A class for handling a KNX logical group
 *  
 * @package		eibnetmux PHP client library
 * @author		Urs Zurbuchen
 * @copyright 	2006-2009 Urs Zurbuchen <going_nuts@users.sourceforge.net>
 * @license 	http://www.opensource.org/licenses/gpl-3.0.html GPL
 * @link		http://eibnetmux.sourceforge.net
 * 
 */

/**
 * Exception class for eibnetmux server errors.
 * 
 * @package		eibnetmux PHP client library
 */
class eibnetmuxServerError extends Exception {}
/**
 * Exception class for PHP client library errors.
 * 
 * @package		eibnetmux PHP client library
 */
class eibnetmuxLibError extends Exception {}

/**
 * A class for handling a KNX logical group
 *
 * Use this class to work with a KNX Logical Group, to read its
 * value from the bus or to set it. This class encapsulates the
 * interfaces with the eibnetmux class to communicate with the server
 * relieving you from it.
 *
 * @package		eibnetmux PHP client library
 */
class KNXgroup {
	/**#@+
	 * @access		private
	 */
	/**
	 * Address of group as used on bus.
	 * 
	 * This is a 16-bit integer.
	 * The format is: 0mmm msss gggg gggg where m=maingroup, s=subgroup, g=group
	 */
	private		$knxaddress;
	/**
	 * Data type of logical group.
	 * 
	 * Neither a group's address nor the requests/responses communicated on the bus
	 * contain any indication of the type of data the devices associated with this group
	 * expect. It must be specified when a group is instantiated to allow correct conversions
	 * for reads & writes.
	 */
	private		$eis;
	
	/**
	 * Error id to pass when throwing eibnetmuxLibError exception.
	 */
	const		errorNoConnection = 1001;
	/**#@-*/
	
	/**
	 * Instantiate a KNX logical group.
	 * 
	 * @param		string		$group		name of group in the form main/sub/group, e.g. 3/2/18
	 * @param		integer		$eis_type	data type expected by devices associated with this group (1-15)
	 */
	public function __construct( $group, $eis_type )
	{
		$temp = explode( "/", $group );
		$this->knxaddress = ($temp[0] * 2048) + ($temp[1] * 256) + $temp[2];
		$this->eis = $eis_type;
	}
	
	/**
	 * Read value of KNX logical group from bus.
	 * 
	 * This function accesses the KNX bus via the eibnetmux server (using an eibnetmux object).
	 * It sends a read request for the KNX logical group and waits for any device to respond.
	 * If a response is received, the sent value is converted according to the EIS data type,
	 * and finally returned to the caller.
	 * 
	 * @param		object		$conn		Object of class eibnetmux
	 * @return 		mixed					Result can be integer or string. Use getValueType() to find out.
	 */
	public function read( $conn )
	{
		$r = $conn->read( $this->knxaddress );
		switch( $r['status'] ) {
			case 0:
				return( $this->decode( $r['value'], $r['length'], $this->eis ));
			case -1:
				throw new eibnetmuxLibError( "connection to server not established", self::errorNoConnection );
			default:
				$this->throwError( $r['status'] );
		}
	}
	
	/**
	 * Send value to KNX logical group on bus.
	 * 
	 * This function accesses the KNX bus via the eibnetmux server (using an eibnetmux object).
	 * It converts the passed value according to the EIS data type to the KNX data format and
	 * sends it in a write request for the KNX logical group.
	 * 
	 * @param		object		$conn		Object of class eibnetmux
	 * @param		mixed		$value		Value to send to bus (string or integer, depending on group's EIS)
	 */
	public function write( $conn, $value )
	{
		$data = $this->encode( $value, $this->eis );
		$r = $conn->write( $this->knxaddress, $data );
		switch( $r ) {
			case 0:
				return( 0 );
			case -1:
				throw new eibnetmuxLibError( "connection to server not established", self::errorNoConnection );
			default:
				$this->throwError( $r['status'] );
		}
	}
	
	/**
	 * Return the type of value read from bus for KNX logical group.
	 * 
	 * The EIS data type specifies the data type of a KNX logical group on the bus.
	 * If an application doesn't know a group's data type, use this function
	 * to know how to correctly interpret the returned value.
	 * 
	 * @return 		string					Type of result: 'number' or 'text'
	 */
	public function getValueType()
	{
		switch( $this->eis ) {
			case 1:
			case 2:
			case 3:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
			case 11:
			case 14:
				$type = "number";
				break;
			case 12:
			case 13:
			case 15:
				$type = "text";
				break;
		}
		return( $type );
	}
	
	/**
	 * Get group name
	 * 
	 * @return 		string					Name of group, format main/sub/group, e.g. 2/1/9
	 */
	public function getGroupName()
	{
		$main  = ($this->knxaddress & 0x7800) >> 11;
		$sub   = ($this->knxaddress & 0x0300) >> 8;
		$group = ($this->knxaddress & 0x00ff);
		
		return( "$main/$sub/$group" );
	}
	
	/**
	 * Raise exception corresponding with error.
	 * 
	 * @access		private
	 */
	private function throwError( $code )
	{
		switch( $code ) {
			case 1:
				throw new eibnetmuxServerError( "socket closed", $code );
			case 2:
				throw new eibnetmuxServerError( "no sockets available", $code );
			case 3:
				throw new eibnetmuxServerError( "bad request", $code );
			case 4:
				throw new eibnetmuxServerError( "unknown command", $code );
			case 5:
				throw new eibnetmuxServerError( "timeout", $code );
			case 6:
				throw new eibnetmuxServerError( "unauthorised", $code );
			case 7:
				throw new eibnetmuxServerError( "invalid password", $code );
			case 8:
				throw new eibnetmuxServerError( "diffie-hellman-merkle error", $code );
			default:
				throw new eibnetmuxServerError( "unknown error", $code );
		}
	}
	
	/**
	 * Decode value received from KNX bus to PHP data type.
	 * 
	 * @access		private
	 */
	private function decode( $value, $length, $eis )
	{
		switch( $eis ) {
			case 1:		// switch
			case 7:		// ?
				$result = ord( $value[0] ) & 0x01;
				break;
			case 2:		// dim, step
				$result = ord( $value[0] ) & 0x07;
				if( ord( $value[0] ) & 0x08 ) {
					$result = -$result;
				}
				break;
			case 3:		// time
				$result = (ord( $value[1] ) & 0x1f) * 3600 +
							(ord( $value[2] ) & 0x3f) * 60 +
							(ord( $value[3] ) & 0x3f);
				break;
			case 4:		// date
				$year = ord( $value[3] );
				if( $year < 90 ) $year += 100;
				$result = mktime( 0, 0, 0, ord( $value[2] ) & 0x0f, ord( $value[1] ) & 0x1f, $year + 1900 );
				break;
			case 5:		// 1 byte float
				$exponent = (ord( $value[1] ) & 0x78) >> 3;
				$mantissa = (ord( $value[1] ) & 0x07) << 8 | ord( $value[2] );
				if( (ord( $value[1] ) & 0x80) != 0 ) {
					$mantissa = $mantissa - 2048;
				}
				$result = $mantissa * 0.01 * pow( 2, $exponent );
				break;
			case 6:		// scale 
			case 14:	// 8-bit integer
				$result = ord( $value[1] );
				break;
			case 8:		// ?
				$result = ord( $value[0] ) & 0x03;
				break;
			case 9:		// 32-bit float
				$result = unpack( "f", pack( "C4", ord( $value[1] ), ord( $value[2] ), ord( $value[3] ), ord( $value[4] ) ));
					/*
					$exponent = ((ord( $value[1] ) & 0x7f) << 1) | ((ord( $value[1] ) & 0x80) >> 7);
					$exponent -= 127;
					$mantissa = ((ord( $value[2] ) & 0x7f) << 16) | (ord( $value[3] ) << 8) | ord( $value[4] );
					if( (ord( $value[1] ) & 0x80) != 0 ) {
						$mantissa = $mantissa - 2048;
					}
					$result = $mantissa * 0.01 * pow( 2, $exponent );
					*/
				break;
			case 10:	// 16-bit integer
				$result = (ord( $value[1] ) << 8) | ord( $value[2] );
				break;
			case 11:	// 32-bit integer
				$result = (ord( $value[1] ) << 24) | (ord( $value[2] ) << 16) | (ord( $value[3] ) << 8) | ord( $value[4] );
				break;
			case 12:	// access ?
				$result = dechex( ord( $value[4] ) ) . ((ord( $value[1] ) & 0xf0) >> 4) . ((ord( $value[2] ) & 0x0f)) . ((ord( $value[3] ) & 0xf0) >> 4) . ((ord( $value[4] ) & 0x0f)) . ((ord( $value[3] ) & 0xf0) >> 4) . ((ord( $value[3] ) & 0x0f));
				break;
			case 13:	// character
				$result = ord( $value[1] );
				break;
			case 15:	// 14-byte text
				$result = "";
				for( $loop = 1; $loop < $length; $loop++ ) {
					$result .= $value[$loop];
				}
				break;
		}
		return( $result );
	}
	
	/**
	 * Encode PHP data type to value usable on KNX bus.
	 * 
	 * The encoding is done according to EIS data type of KNX logical group.
	 * The result is formatted as follows:
	 * - length (16-bit)
	 * - value (byte stream)
	 * 
	 * The byte stream can be used directly as the data part of a CEMI frame.
	 * 
	 * @access		private
	 */
	private function encode( $value, $eis )
	{
		switch( $eis ) {
			case 1:		// switch
			case 7:		// ?
    			$value = $value & 0x01;
				$data = pack( "nC", 0x01, $value );
				break;
			case 2:		// dim, step
				$value = $value & 0x07;
				$data = pack( "nC", 0x01, $value );
				break;
			case 8:		// ?
				$value = $value & 0x03;
				$data = pack( "nC", 0x01, $value );
				break;
			case 6:		// scale
			case 13:	// character
			case 14:	// 8-bit integer
				$value = $value & 0xff;
				$data = pack( "nCC", 0x02, 0x00, $value );
				break;
			case 10:	// 16-bit integer
				$data = pack( "nCn", 0x03, 0x00, $value );
				break;
			case 11:	// 32-bit integer
				$data = pack( "nCN", 0x05, 0x00, $value );
				break;
			case 9:
				$data = pack( "nCf", 0x05, 0x00, $value );
				break;
			case 15:
				$len = strlen( $value );
				$data = pack( "nC$len", $len, $value );
				break;
			case 3:		// time (hh:mm:ss or seconds)
				if( strpos( $value, ':' ) != 0 ) {
					$tc = explode( ":", $value );
					$data = pack( "nCCCC", 0x04, 0x00, $tc[0] & 0x1f, $tc[1] & 0x3f, $tc[2] & 0x3f );
				} else {
					$hours = int($value / 3600);
					$minutes = int(($value % 3600) / 60);
					$seconds = $value % 60;
					$data = pack( "nCCCC", 0x04, 0x00, $hours & 0x1f, $minutes & 0x3f, $seconds & 0x3f );
				}
				break;
			case 4:		// date (yyyy/mm/dd or seconds since epoch)
				if( strpos( $value, '/' ) != 0 ) {
					$dc = explode( "/", $value );
					if( $dc[0] > 1990 ) {
						$dc[0] -= 1900;
					} else {
						throw new eibnetmuxLibError( "Invalid date" );	// earliest year is 1990
					}
					if( $dc[0] >= 99 ) {
						$dc[0] -= 100;
					}
					$data = pack( "nCCCC", 0x04, 0x00, $dc[1] & 0x0f, $dc[2] & 0x1f, $dc[0] );
				} else {
					$hours = int($value / 3600);
					$minutes = int(($value % 3600) / 60);
					$seconds = $value % 60;
					$data = pack( "nCCCC", 0x04, 0x00, $hours & 0x1f, $minutes & 0x3f, $seconds & 0x3f );
				}
				break;
			case 5:		// 8-bit float
			case 12:	// access ?
				$length = -1;	// not yet supported
				break;
		}
		return( $data );
	}
	
	/**
	 * Return API version.
	 * 
	 * @return		integer						-1: no connection established, >0: version
	 */
	function getAPIversion()
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			return( 1 );
		}
	}
}

/**
 * Class implementing the client interface with the eibnetmux server.
 *
 * Use this class to access the KNX bus via an eibnetmux server.
 * It creates and sends the correct requests to the server,
 * receives the responses and extracts the required information.
 *
 * @package		eibnetmux PHP client library
 */
class eibnetmux {
	/**#@+
	 * @access		private
	 */
	/**
	 * Connection id.
	 */
	private 	$connection = 0;
	/**
	 * Client identifier.
	 */
	private 	$ident = "";
	/**
	 * Name of host running eibnetmux.
	 */
	private 	$hostname = "";
	/**
	 * Port number of eibnetmux.
	 */
	private 	$port = 0;
	
	/**
	 * Error id to pass when throwing eibnetmuxLibError exception.
	 */
	const		errorConnectionEstablished = 1;
	/**#@-*/
	
	/**
	 * Instantiate an eibnetmux connection
	 * 
	 * @param		string		$identifier	name or type of application/client connecting to eibnetmux
	 * @param		string		$hostname	name of host running eibnetmux
	 * @param		integer		$port		port on which eibnetmux is listening on
	 */
	public function __construct( $identifier, $hostname = "", $port = 4390 )
	{
		$this->connection = 0;
		$this->ident = $identifier;
		$this->hostname = $hostname;
		$this->port = $port;
		if( $hostname != "" ) {
			$r = $this->open( $hostname, $port );
			if( $r < 0 ) {
				throw new eibnetmuxLibError( "Unable to establish connection to server" );
			} else if( $r > 0 ) {
				$this->throwError( $r );
			}
		}
	}
	
	/**
	 * Open connection to eibnetmux server.
	 * 
	 * @param		string		$hostname	name of host running eibnetmux
	 * @param		integer		$port		port on which eibnetmux is listening on
	 * @return		integer					Result code: 0=ok, <0: error
	 */
	public function open( $hostname = "localhost", $port = 4390 )
	{
		if( $this->connection != 0 ) {
			return( -1 );
		}
		if( ($this->connection = fsockopen( $hostname, $port )) === FALSE ) {
			$this->connection = 0;
			return( -2 );
		}
		$head = pack( "Cn", 0x61, strlen( $this->ident ));	// 'a'
		fwrite( $this->connection, $head );
		fwrite( $this->connection, $this->ident );

		$ack = fread( $this->connection, 3 );
		$response = unpack( "Cstatus/ncode", $ack );
		if( $response['status'] != 0x61 ) {
			return( $response['code'] );
		}
		$this->hostname = $hostname;
		$this->port = $port;
		return( 0 );
	}
	
	/**
	 * Close connection to eibnetmux server.
	 * 
	 * @return		integer					Result code: 0=ok, <0: error
	 */
	public function close()
	{
		if( $this->connection == 0 ) {
			return( -1 );
		}
		$head = pack( "Cn", 0x58, 0x00 );	// 'X'
		fwrite( $this->connection, $head );
		$ack = fread( $this->connection, 3 );
		fclose( $this->connection );
		$this->connection = 0;
		$this->hostname = "";
		$this->port = 0;
		return( 0 );
	}
	
	/**
	 * Authenticate to eibnetmux server.
	 * 
	 * The eibnetmux server may be configured to restrict publicly accessible functionality.
	 * For example, the administrator may chose to generally disallow sending to the bus
	 * unless the user has been assigned special access rights.
	 * 
	 * Such users must authenticate to the server to take advantage of special access rights.
	 * Authentication is based on username & password which must be specified by the caller.
	 * 
	 * @param 		string		$user			name of user to authenticate for
	 * @param 		string		$password		user's password
	 * @return		integer						Result code: 0=ok, <0: error
	 */
	public function authenticate( $user, $password )
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			// currently no encryption support - working on it
			// so, just pass username & password in the clear
			$head = pack( "Cn", 0x41, strlen( $user ) +1 + strlen( $password ) +1 );	// 'A'
			fwrite( $this->connection, $head );
			$packformat = sprintf( "a%da%d", strlen( $user ) +1, strlen( $password ) +1 );
			$data = pack( $packformat, $user, $password );
			fwrite( $this->connection, $data );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/nlength", $ack );
			if( $response['status'] != 0x41 ) {
				return( -1 );
			} else {
				return( $response['code'] );
			}
		}
	}

	/**
	 * Not yet implemented.
	 * 
	 * @access		private
	 */
	private function authenticate_with_encryption( $not_complete__dont_use )
	{
		// not implemented yet
		return( -1 );
		
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			// initiate key exchange
			$head = pack( "Cn", 0x4B, 0 );	// 'K'
			fwrite( $this->connection, $head );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/nlength", $ack );
			if( $response['status'] != 0x4B ) {
				return( -1 );
			} else {
				/*
				 * format is:
				 * 		length of prime			2 bytes
				 * 		prime					x bytes
				 * 		length of generator		2 bytes
				 * 		genersator				x bytes
				 * 		length of public key	2 bytes
				 * 		public key				x bytes
				 */
				$length = fread( $this->connection, 2 );
				$prime = fread( $this->connection, $length );
				$length = fread( $this->connection, 2 );
				$generator = fread( $this->connection, $length );
				$length = fread( $this->connection, 2 );
				$server_publickey = fread( $this->connection, $length );
			}
		}
		return( -1 );
	}
	
	/**
	 * Read value of KNX logical group from bus.
	 * 
	 * This function accesses the KNX bus via the eibnetmux server (using our established connection).
	 * It sends a read request for the KNX logical group and waits for any device to respond.
	 * If a response is received, the sent value is returned to the caller.
	 * It is the caller's responsibility to interpret it.
	 * 
	 * @param		integer		$knxaddress	Address of KNX logical group
	 * @return 		array					Result is an array with elements 'status', 'length', and 'value'
	 */
	public function read( $knxaddress )
	{
		$result = array();
		
		if( $this->connection == 0 ) {
			$result['status'] = -1;
		} else {
			$head = pack( "Cn", 0x52, $knxaddress );	// 'R'
			fwrite( $this->connection, $head );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/nlength", $ack );
			if( $response['status'] == 0x52 ) {
				$result['status'] = 0;
				$result['length'] = $response['length'];
				$result['value'] = fread( $this->connection, $result['length'] );
			} else {
				$result['status'] = $response['length'];
			}
		}
		return( $result );
	}
	
	/**
	 * Send value to KNX logical group on bus.
	 * 
	 * This function accesses the KNX bus via the eibnetmux server (using our established connection).
	 * The value to send must be a binary string of the following format:
	 * - length (16-bit integer)
	 * - data (byte stream, 'length' bytes)
	 * 
	 * @param		integer		$knxaddress	Address of KNX logical group
	 * @param		string		$data		Binary string containing data to send
	 * @return 		integer					Result code: 0: ok, -1: library error, >0: server error
	 */
	public function write( $knxaddress, $data )
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			$head = pack( "Cn", 0x57, $knxaddress );	// 'W'
			fwrite( $this->connection, $head );
			fwrite( $this->connection, $data );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/ncode", $ack );
			if( $response['status'] == 0x57 ) {
				return( 0 );
			} else {
				return( $response['code'] );
			}
		}
	}
	
	/**
	 * Raise exception corresponding with error.
	 * 
	 * @access		private
	 */
	private function throwError( $code )
	{
		switch( $code ) {
			case 1:
				throw new eibnetmuxServerError( "socket closed", $code );
			case 2:
				throw new eibnetmuxServerError( "no sockets available", $code );
			case 3:
				throw new eibnetmuxServerError( "bad request", $code );
			case 4:
				throw new eibnetmuxServerError( "unknown command", $code );
			case 5:
				throw new eibnetmuxServerError( "timeout", $code );
			case 6:
				throw new eibnetmuxServerError( "unauthorised", $code );
			case 7:
				throw new eibnetmuxServerError( "invalid password", $code );
			case 8:
				throw new eibnetmuxServerError( "diffie-hellman-merkle error", $code );
			default:
				throw new eibnetmuxServerError( "unknown error", $code );
		}
	}
	
	/**
	 * Return API version of eibnetmux PHP client library interface.
	 * 
	 * @return		integer						-1: no connection established, >0: version
	 */
	function mgmt_getAPIversion()
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			return( 3 );
		}
	}
	
	/**
	 * Get 16-bit code from eibnetmux server.
	 * 
	 * @param	character	$function	eibnetmux server command
	 * @param	integer		$label		Name of array element returning code received from eibnetmux server
	 * @return	array					Result array, elements 'status', '$label' (if status=0)
	 * 
	 * @access	private
	 */
	private function getcode( $function, $label )
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			$head = pack( "Cn", $function, 0 );
			fwrite( $this->connection, $head );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/n$label", $ack );
			return( $response );
		}
	}
	
	/**
	 * Send 16-bit code to eibnetmux server.
	 * 
	 * @param	character	$function	eibnetmux server command
	 * @param	integer		$level		Code to send to eibnetmux server
	 * @return	integer					Result code: 0=ok, <0: library error, >0: server error
	 * 
	 * @access	private
	 */
	private function sendcode( $function, $code )
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			$head = pack( "Cn", $function, $code );
			fwrite( $this->connection, $head );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/ncode", $ack );
			return( $response['code'] );
		}
	}
	
	/**
	 * Return log level of eibnetmux server.
	 * 
	 * The eibnetmux server client interface does not feature a command to directly
	 * request and return the server's log level. Instead, the server's status is
	 * retrieved and the log level extracted.
	 * 
	 * @return	array					Result array, elements 'status', 'level' (if status=0)
	 */
	function mgmt_getloglevel()
	{
		$result = $this->mgmt_getstatus();
		if( $result['status'] != 0 ) {
			return( $result );
		}
		$r = array();
		$r['status'] = 0;
		$r['level'] = $result['value']['common']['level'];
		return( $r );
	}
	
	/**
	 * Set log level of eibnetmux server.
	 * 
	 * @param	integer		$level		New log level of eibnetmux server
	 * @return	integer					Result code: 0=ok, <0: library error, >0: server error
	 */
	function mgmt_setloglevel( $level )
	{
		return( $this->sendcode( 0x4c, $level ));			// 'L'
	}
	
	/**
	 * Return access block level of eibnetmux server.
	 * 
	 * @return	array					Result array, elements 'status', 'level' (if status=0)
	 */
	function mgmt_getaccessblock()
	{
		return( $this->getcode( 0x62, 'level' ));			// 'b'
	}
	
	/**
	 * Set access block level of eibnetmux server.
	 * 
	 * @param	integer		$level		New access block level of eibnetmux server
	 * @return	integer					Result code: 0=ok, <0: library error, >0: server error
	 */
	function mgmt_setaccessblock( $level )
	{
		return( $this->sendcode( 0x42, $level ));			// 'B'
	}
	
	/**
	 * Manage connection of eibnetmux server's client to N148/21 IP Interface.
	 * 
	 * The eibnetmux server does not directly connect to the KNX bus but talks to a
	 * Siemens N148/21 IP interface (or compatible device). This device only supports
	 * one concurrent connection (which was the primary reason to develop eibnetmux
	 * in the first place). Sometimes although rarely, it is desired to use this 
	 * connection for something else than the eibnetmux server (e.g. to directly
	 * connect ETS to the N148/21). Usually, you would have to stop the server to
	 * free the connection to the device, impacting all its connected clients.
	 * 
	 * Using this function, the eibnetmux server client connection can be temporarily
	 * closed and released to allow an other application to connect to the N148/21.
	 * 
	 * @param	integer		$state		0: disconnect client, 1: connect client
	 * @return	integer					Result code: 0=ok, <0: library error, >0: server error
	 */
	function mgmt_connect( $state )
	{
		if( $this->connection == 0 ) {
			return( -1 );
		} else {
			$head = pack( "Cn", 0x43, ($state & 0x01) );
			fwrite( $this->connection, $head );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/ncode", $ack );
			return( $response['code'] );
		}
	}
	
    /**
     * Forcibly close a client session
     * 
     * @param   integer		session_type    1: EIBnet/IP clients, 2: socket clients
     * @param   integer		session_id      id of session to close
     * @return                  			Result code: 0=ok, <0: library error, >0: server error
     */
    function mgmt_close_session( $session_type, $session_id )
    {
		if( $this->connection == 0 ) {
			return( -1 );
		}
		if( $session_type < 1 || $session_type > 2 ) {
			return( -2 );
		}
		$head = pack( "Cn", 0x63, $session_type );		// 'c'
		fwrite( $this->connection, $head );
		$connid = pack( "N", $session_id );
		fwrite( $this->connection, $connid );
		
		$ack = fread( $this->connection, 3 );
		$response = unpack( "Cstatus/ncode", $ack );
		return( $response['code'] );
    }
	
	/**
	 * Get status of eibnetmux server.
	 * 
	 * @return	array					Result array containing information about the eibnetmux server's status. Elements 'status' (must be 0), 'common', 'client', 'server', 'socketserver'
	 */
	function mgmt_getstatus()
	{
		$result = array();
		
		if( $this->connection == 0 ) {
			$result['status'] = -1;
		} else {
			$head = pack( "Cn", 0x53, 0 );			// 'S'
			fwrite( $this->connection, $head );
			
			$ack = fread( $this->connection, 3 );
			$response = unpack( "Cstatus/nlength", $ack );
			if( $response['status'] != 0x53 ) {
    			$result['status'] = $response['length'];
    			return( $result );
			}
			$version = fread( $this->connection, 1 );
			$response = unpack( "Cversion", $version );
			if( $response['version'] >= 1 ) {
				$versionMatch = true;
				
				/*
				 * eibnetmux status
				 */
				$stream = fread( $this->connection, 3 );
				$common = unpack( "nlength/C_version", $stream );
				$stream = fread( $this->connection, $common['length'] -3 );
				if( $common['_version'] == 1 ) {
					$common = unpack( "Cv_major/Cv_minor/nlevel/Nuptime/nuser/ngroup/Cdaemon", $stream );
				} else if( $common['_version'] == 2 ) {
					$stringlength = strpos( $stream, 0 ) +1;
					$common = unpack( "a" . $stringlength . "version/nlevel/Nuptime/nuser/ngroup/Cdaemon", $stream );
				} else {
					$versionMatch = false;
				}
				$common['uptime'] = $this->convertTime( $common['uptime'] );
				
				/*
				 * EIBnet/IP client status
				 */
				$stream = fread( $this->connection, 3 );
				$client_head = unpack( "nlength/C_version", $stream );
				$stream = fread( $this->connection, $client_head['length'] -3 );
				if( $client_head['_version'] == 1 ) {
					$client = unpack( "Cactive/Nuptime/Nreceived/Nsent/Nreceived_total/Nsent_total/nqueue/nmissed", $stream );
				} else if( $client_head['_version'] == 2 ) {
					$client = unpack( "Cactive/Nuptime/Nreceived/Nsent/Nreceived_total/Nsent_total/nqueue/nmissed/Nsourceip", $stream );
					unset( $client['sourceip'] ); 		// server sends it "garbled"
				} else if( $client_head['_version'] >= 3 ) {
					$client = unpack( "Cactive/Nuptime/Nreceived/Nsent/Nreceived_total/Nsent_total/nqueue/nmissed/nnamelength", $stream );
					if( $client_head['_version'] == 3 ) {
    					if( $client['namelength'] > 0 ) {
    						$client2 = unpack( "a" . $client['namelength'] ."targetname/Ntargetip/ntargetport/Nsourceip", substr( $stream, 27 ));
    					} else {
    						$client2 = unpack( "Ntargetip/ntargetport/Nsourceip", strpos( $stream, 27 ));
    					}
					} else {
    					if( $client['namelength'] > 0 ) {
    						$client2 = unpack( "a" . $client['namelength'] ."targetname/Ntargetip/ntargetport/Nsourceip/Cloopback", substr( $stream, 27 ));
    					} else {
    						$client2 = unpack( "Ntargetip/ntargetport/Nsourceip/Cloopback", strpos( $stream, 27 ));
    					}
					}
					$client = array_merge( $client, $client2 );
					$client['targetip'] = long2ip( $client['targetip'] );
					$client['sourceip'] = long2ip( $client['sourceip'] );
				} else {
					$versionMatch = false;
				}
				$client['uptime'] = $this->convertTime( $client['uptime'] );
				
				/*
				 * EIBnet/IP server status
				 */
				$stream = fread( $this->connection, 3 );
				$server_head = unpack( "nlength/C_version", $stream );
				$stream = fread( $this->connection, $server_head['length'] -3 );
				if( $server_head['_version'] <= 3 ) {
					$server = unpack( "Cactive/nport/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue", $stream );
					if( $server_head['_version'] == 1 ) {
						for( $loop = 0; $loop < $server['nr_clients']; $loop++ ) {
							$stream = fread( $this->connection, 16 );
							$server['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent/nqueue", $stream );
							$server['clients'][$loop]['ip'] = long2ip( $server['clients'][$loop]['ip'] );
						}
					} else if( $server_head['_version'] == 2 ) {
						for( $loop = 0; $loop < $server['nr_clients']; $loop++ ) {
							$stream = fread( $this->connection, 20 );
							$server['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent/nqueue/Vsourceip", $stream );
							$server['clients'][$loop]['ip'] = long2ip( $server['clients'][$loop]['ip'] );
							$server['clients'][$loop]['sourceip'] = long2ip( $server['clients'][$loop]['sourceip'] );
						}
					} else {
						for( $loop = 0; $loop < $server['nr_clients']; $loop++ ) {
							$stream = fread( $this->connection, 20 );
							$server['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent/nqueue/Nsourceip", $stream );
							$server['clients'][$loop]['ip'] = long2ip( $server['clients'][$loop]['ip'] );
							$server['clients'][$loop]['sourceip'] = long2ip( $server['clients'][$loop]['sourceip'] );
						}
					}
				} else if( $server_head['_version'] == 4 ) {
					$server = unpack( "Cactive/nport/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue/ndefault_level/naccess_block", $stream );
					$server['defaultAuth'] = $this->convertAuth( $server['default_level'] );
					$server['maxAuth'] = $this->convertAuth( $server['access_block'] );
					for( $loop = 0; $loop < $server['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 24 );
						$server['clients'][$loop] = unpack( "Nconn_id/Nip/nport/Nreceived/Nsent/nqueue", $stream );
						$server['clients'][$loop]['ip'] = long2ip( $server['clients'][$loop]['ip'] );
					}
				} else {
					$versionMatch = false;
				}
				
				/*
				 * Socket server status
				 */
				$stream = fread( $this->connection, 3 );
				$socket_head = unpack( "nlength/C_version", $stream );
				$stream = fread( $this->connection, $socket_head['length'] -3 );
				if( $socket_head['_version'] == 1 ) {
					$stringlength = strpos( $stream, 0, 4 ) -3;
					$socket = unpack( "Cactive_tcp/Cactive_pipe/nport/a". $stringlength . "pipe/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue", $stream );
					for( $loop = 0; $loop < $socket['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 14 );
						$socket['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent", $stream );
						$socket['clients'][$loop]['identifier'] = "-";
						$socket['clients'][$loop]['ip'] = long2ip( $socket['clients'][$loop]['ip'] );
					}
				} else if( $socket_head['_version'] == 2 ) {
					$stringlength = strpos( $stream, 0, 4 ) -3;
					$socket = unpack( "Cactive_tcp/Cactive_pipe/nport/a". $stringlength . "pipe/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue/ntable_length", $stream );
					for( $loop = 0; $loop < $socket['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 16 );
						$socket['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent/nnamelength", $stream );
						if( $socket['clients'][$loop]['namelength'] > 0 ) {
							$socket['clients'][$loop]['identifier'] = fread( $this->connection, $socket['clients'][$loop]['namelength'] );
						} else {
							$socket['clients'][$loop]['identifier'] = '-';
						}
						$socket['clients'][$loop]['ip'] = long2ip( $socket['clients'][$loop]['ip'] );
					}
				} else if( $socket_head['_version'] == 3 ) {
					$stringlength = strpos( $stream, 0, 4 ) -3;
					$socket = unpack( "Cactive_tcp/Cactive_pipe/nport/a". $stringlength . "pipe/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue/Cauthentication", $stream );
					for( $loop = 0; $loop < $socket['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 16 );
						$socket['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent/nnamelength", $stream );
						if( $socket['clients'][$loop]['namelength'] > 0 ) {
							$socket['clients'][$loop]['identifier'] = fread( $this->connection, $socket['clients'][$loop]['namelength'] );
						} else {
							$socket['clients'][$loop]['identifier'] = '-';
						}
						$socket['clients'][$loop]['ip'] = long2ip( $socket['clients'][$loop]['ip'] );
					}
				} else if( $socket_head['_version'] == 4 ) {
					$stringlength = strpos( $stream, 0, 4 ) -3;
					$socket = unpack( "Cactive_tcp/Cactive_pipe/nport/a". $stringlength . "pipe/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue/Cauthentication", $stream );
					for( $loop = 0; $loop < $socket['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 16 );
						$socket['clients'][$loop] = unpack( "Nip/nport/Nreceived/Nsent/nnamelength", $stream );
						if( $socket['clients'][$loop]['namelength'] > 0 ) {
							$socket['clients'][$loop]['identifier'] = fread( $this->connection, $socket['clients'][$loop]['namelength'] );
						} else {
							$socket['clients'][$loop]['identifier'] = '-';
						}
						$socket['clients'][$loop]['ip'] = long2ip( $socket['clients'][$loop]['ip'] );
						$stream = fread( $this->connection, 2 );
						$temp = unpack( "nnamelength", $stream );
						if( $temp['namelength'] > 0 ) {
							$socket['clients'][$loop]['user'] = fread( $this->connection, $temp['namelength'] );
						} else {
							$socket['clients'][$loop]['user'] = '-';
						}
					}
				} else if( $socket_head['_version'] == 5 ) {
					$stringlength = strpos( $stream, 0, 4 ) -3;
					$socket = unpack( "Cactive_tcp/Cactive_pipe/nport/a". $stringlength . "pipe/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue/Cauthentication", $stream );
					for( $loop = 0; $loop < $socket['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 20 );
						$socket['clients'][$loop] = unpack( "Nconn_id/Nip/nport/Nreceived/Nsent/nnamelength", $stream );
						if( $socket['clients'][$loop]['namelength'] > 0 ) {
							$socket['clients'][$loop]['identifier'] = fread( $this->connection, $socket['clients'][$loop]['namelength'] );
						} else {
							$socket['clients'][$loop]['identifier'] = '-';
						}
						$socket['clients'][$loop]['ip'] = long2ip( $socket['clients'][$loop]['ip'] );
						$stream = fread( $this->connection, 2 );
						$temp = unpack( "nnamelength", $stream );
						if( $temp['namelength'] > 0 ) {
							$socket['clients'][$loop]['user'] = fread( $this->connection, $temp['namelength'] );
						} else {
							$socket['clients'][$loop]['user'] = '-';
						}
					}
				} else {
					$versionMatch = false;
				}
				
				if( $versionMatch == true ) {
					$result['status'] = 0;
					$result['value'] = array(
						"common"	=> $common,
						"client"	=> $client,
						"server"	=> $server,
						"socket"	=> $socket );
				} else {
					$result['status'] = -3;
				}
			}
			if( $response['version'] >= 2 ) {
				/*
				 * EIBD server status
				 */
				$stream = fread( $this->connection, 3 );
				$eibd_head = unpack( "nlength/C_version", $stream );
				$stream = fread( $this->connection, $eibd_head['length'] -3 );
				if( $eibd_head['_version'] == 1 ) {
					$eibd = unpack( "Cactive/nport/Cmax_clients/Cnr_clients/Nreceived_total/Nsent_total/nqueue", $stream );
					for( $loop = 0; $loop < $eibd['nr_clients']; $loop++ ) {
						$stream = fread( $this->connection, 20 );
						$eibd['clients'][$loop] = unpack( "Nconn_id/Nip/nport/Nreceived/Nsent", $stream );
						$eibd['clients'][$loop]['ip'] = long2ip( $eibd['clients'][$loop]['ip'] );
					}
				} else {
					$versionMatch = false;
				}
				
				if( $versionMatch == true ) {
					$result['value']['eibd'] = $eibd;
				} else {
					$result['status'] = -3;
				}
			}
			if( $response['version'] < 1 || $response['version'] > 2 ) {
				print( "Version mismatch - response=" ); print_r( $response ); print( "\n" );
				$stream = fread( $this->connection, $response['length'] -1 );
				$result['status'] = -2;
			}
		}
		return( $result );
	}
	
	/**
	 * Convert authorisation level to human readable text.
	 * 
	 * @param	integer		$level		authorisation level
	 * @return	string					Authorisation level as text
	 * 
	 * @access	private
	 */
	private function convertAuth( $level )
	{
		switch( $level ) {
    		case 0:
    			return( "Deny all" );
    		case 1:
    			return( "Allow read" );
    		case 2:
    			return( "Allow KNX group read/write" );
    		case 3:
    			return( "Allow all access" );
		}
		return( "Unknown" );
	}
	
	/**
	 * Convert number of seconds to human readable time.
	 * 
	 * @param	integer		$seconds	Time as number of seconds
	 * @return	string					Time in human readable form, like "d days, hh:mm:ss"
	 * 
	 * @access	private
	 */
	private function convertTime( $seconds )
	{
		$days = $seconds / 86400;
		$seconds %= 86400;
		$hours = $seconds / 3600;
		$seconds %= 3600;
		$minutes = $seconds / 60;
		$seconds %= 60;
		
		if( $days > 0 ) {
			$r = sprintf( "%d days, %02d:%02d:%02d", $days, $hours, $minutes, $seconds );
		} else {
			$r = sprintf( "%02d:%02d:%02d", $hours, $minutes, $seconds );
		}
		
		return( $r );
	}
}
