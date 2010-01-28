#include "prepared.c"
#include "eibtrace.c"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <eibnetmux/enmx_lib.h>
#include "mylib.h"

int prepared ( char* user, char* pwd, char* ip, int porta, char* dbname, Energia energia);

 // prepared( "root", "labdomvinci", "10.0.0.55", "3306", "konnex",);

int main( int argc, char **argv )
{
    Energia energia;
    
    uint16_t                value_size;
    struct timeval          tv;
    struct tm               *ltime;
    uint16_t                buflen;
    unsigned char           *buf;
    CEMIFRAME               *cemiframe;
    int                     enmx_version;
    int                     c;
    int                     quiet = 0;
    int                     total = -1;
    int                     count = 0;
    int                     spaces = 1;
    char                    *user = NULL;
    char                    pwd[255];
    char                    *target;
    char                    *eis_types;
    int                     type;
    int                     seconds;
    unsigned char           value[20];
    uint32_t                *p_int = 0;
    double                  *p_real;

    opterr = 0;
    while( ( c = getopt( argc, argv, "c:u:q" )) != -1 )
    {
        switch( c )
        {
            case 'c':
                total = atoi( optarg );
                break;
            case 'u':
                user = strdup( optarg );
                break;
            case 'q':
                quiet = 1;
                break;
            default:
                fprintf( stderr, "Invalid option: %c\n", c );
                Usage( argv[0] );
                exit( -1 );
        }
    }

    if( optind == argc )
    {
        target = NULL;
    } 
    else if( optind + 1 == argc )
    {
        target = argv[optind];
    } else {
        Usage( argv[0] );
        exit( -1 );
    }

    // catch signals for shutdown
    signal( SIGINT, Shutdown );
    signal( SIGTERM, Shutdown );

    // request monitoring connection
    enmx_version = enmx_init();
    sock_con = enmx_open( target, "eibtrace" );
    if( sock_con < 0 )
    {
        fprintf( stderr, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        exit( -2 );
    }


    // authenticate
    if( user != NULL )
    {
        if( getpassword( pwd ) != 0 )
        {
            fprintf( stderr, "Error reading password - cannot continue\n" );
            exit( -6 );
        }
        if( enmx_auth( sock_con, user, pwd ) != 0 )
        {
            fprintf( stderr, "Authentication failure\n" );
            exit( -3 );
        }
    }


    if( quiet == 0 )
    {
        printf( "Connection to eibnetmux '%s' established\n", enmx_gethost( sock_con ));
    }




    buf = malloc( 10 );
    buflen = 10;
    if( total != -1 )
    {
        spaces = floor( log10( total )) +1;
    }

   // while( total == -1 || count < total )
    while(1)
    {
        buf = enmx_monitor( sock_con, 0xffff, buf, &buflen, &value_size );
        if( buf == NULL ) {
            switch( enmx_geterror( sock_con ))
            {
                case ENMX_E_COMMUNICATION:
                case ENMX_E_NO_CONNECTION:
                case ENMX_E_WRONG_USAGE:
                case ENMX_E_NO_MEMORY:
                    fprintf( stderr, "Error on write: %s\n", enmx_errormessage( sock_con ));
                    enmx_close( sock_con );
                    exit( -4 );
                    break;
                case ENMX_E_INTERNAL:
                    fprintf( stderr, "Bad status returned\n" );
                    break;
                case ENMX_E_SERVER_ABORTED:
                    fprintf( stderr, "EOF reached: %s\n", enmx_errormessage( sock_con ));
                    enmx_close( sock_con );
                    exit( -4 );
                    break;
                case ENMX_E_TIMEOUT:
                    fprintf( stderr, "No value received\n" );
                    break;
            }
        } 
        else
        {
            count++;
            cemiframe = (CEMIFRAME *) buf;

            gettimeofday( &tv, NULL );
            ltime = localtime( &tv.tv_sec );

            if( total != -1 )
            {
                printf( "%*d: ", spaces, count );
            }
            energia.data.day            = ltime->tm_mday;
            energia.data.year           = ltime->tm_year + 1900;
            energia.data.month          = ltime->tm_mon +1;
            //energia.data.hour           = ltime->tm_hour;
            //energia.data.minute         = ltime->tm_min;
            
            //energia.data.neg            = 0;
            //energia.data.second         = ltime->tm_sec;
            //energia.data.second_part    = (uint32_t)tv.tv_usec / 1000;
            //energia.data.time_type;

            sprintf( energia.timestamp, "%02d:%02d:%02d:%03d", ltime->tm_hour, ltime->tm_min, ltime->tm_sec, (uint32_t)tv.tv_usec / 1000 );



            sprintf( energia.mittente, "%8s  ", knx_physical( cemiframe->saddr ));


            sprintf( energia.destinatario, "%8s", (cemiframe->ntwrk & EIB_DAF_GROUP) ? knx_group( cemiframe->daddr ) : knx_physical( cemiframe->daddr ));
           
            sprintf(energia.valore, "%s", hexdump( &cemiframe->apci, cemiframe->length, cemiframe->length ) );
            //sprintf(energia.valore, "%s", hexdump( &cemiframe->apci, cemiframe->length, cemiframe->length ));
            
            /*
            if( cemiframe->apci & (A_WRITE_VALUE_REQ | A_RESPONSE_VALUE_REQ) )
            {
                printf( " : " );
                p_int = (uint32_t *)value;
                p_real = (double *)value;

                
                switch( cemiframe->length )
                {
                    case 1:     // EIS 1, 2, 7, 8
                        
                        type = enmx_frame2value( 1, cemiframe, value );
                        printf( "%s | ", (*p_int == 0) ? "off" : "on" );
                        type = enmx_frame2value( 2, cemiframe, value );
                        printf( "%d | ", *p_int );
                        type = enmx_frame2value( 7, cemiframe, value );
                        printf( "%d | ", *p_int );
                        type = enmx_frame2value( 8, cemiframe, value );
                        printf( "%d", *p_int );
                        eis_types = "1, 2, 7, 8";
                        

                        sprintf(energia.valore, "%s", cemiframe )
                        break;


                    case 2:     // 6, 13, 14
                        
                        type = enmx_frame2value( 6, cemiframe, value );
                        printf( "%d%% | %d", *p_int * 100 / 255, *p_int );
                        type = enmx_frame2value( 13, cemiframe, value );
                        if( *p_int >=  0x20 && *p_int < 0x7f )
                        {
                            printf( " | %c", *p_int );
                            eis_types = "6, 14, 13";
                        }
                        else
                        {
                            eis_types = "6, 14";
                        }
                        
                        break;


                    case 3:     // 5, 10
                        type = enmx_frame2value( 5, cemiframe, value );
                        printf( "%.2f | ", *p_real );
                        type = enmx_frame2value( 10, cemiframe, value );
                        printf( "%d", *p_int );
                        eis_types = "5, 10";
                        break;


                    case 4:     // 3, 4
                        type = enmx_frame2value( 3, cemiframe, value );
                        seconds = *p_int;
                        ltime->tm_hour = seconds / 3600;
                        seconds %= 3600;
                        ltime->tm_min = seconds / 60;
                        seconds %= 60;
                        ltime->tm_sec = seconds;
                        printf( "%02d:%02d:%02d | ", ltime->tm_hour, ltime->tm_min, ltime->tm_sec );
                        type = enmx_frame2value( 4, cemiframe, value );
                        ltime = localtime( (time_t *)p_int );
                        printf( "%04d/%02d/%02d", ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday );
                        eis_types = "3, 4";
                        break;


                    case 5:     // 9, 11, 12
                        type = enmx_frame2value( 11, cemiframe, value );
                        printf( "%d | ", *p_int );
                        type = enmx_frame2value( 9, cemiframe, value );
                        printf( "%.2f", *p_real );
                        type = enmx_frame2value( 12, cemiframe, value );
                        // printf( "12: <->" );
                        eis_types = "9, 11, 12";
                        break;


                    default:    // 15
                        // printf( "%s", string );
                        eis_types = "15";
                        break;
                }
                
            }
            */
           
        }
         prepared( "root", "labdomvinci", "10.0.0.55", 3306, "konnex", energia);
    }


    
    return( 0 );
}