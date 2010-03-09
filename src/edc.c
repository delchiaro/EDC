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
#include <pthread.h>
#include <semaphore.h>

#include <eibnetmux/enmx_lib.h>
#include "mylib.h"


int prepared ( char* user, char* pwd, char* ip, int porta, char* dbname, Energia energia);


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

    if (mysql_library_init(0, NULL, NULL)) //inizializza la CLI di my_sql
    {
        printf(NULL, "mysql_library_init() failed");
        return 3;
    }


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




    buf = malloc( 27 );
    buflen = 10;
    if( total != -1 )
    {
        spaces = floor( log10( total )) +1;
    }

    
    Filtro *filtro;
    MYSQL *conn;
    initFiltro(filtro);
    start_db_connection(&conn, "root","labdomvinci","10.0.0.55", 3306, "konnex");
    while(1)
    {

        buf = enmx_monitor( sock_con, 0xffff, buf, &buflen, &value_size );

        if( buf == NULL )
        {
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

            str_unfill(energia.destinatario, ' ');


            while( select_filtro(conn, energia.destinatario, &filtro) > 0 )
            {
                
                close_db_connection(&conn);
                start_db_connection(&conn, "root","labdomvinci","10.0.0.55", 3306, "konnex");
            }
           float vald, reversevald;

         /* vald = (float) (cemiframe->data[0]<<24 | cemiframe->data[1]<<16 | cemiframe->data[2]<<8 | cemiframe->data[3]);
          reversevald = (float) (cemiframe->data[3]<<24 | cemiframe->data[2]<<16 | cemiframe->data[1]<<8 | cemiframe->data[0]);
          printf("\nval = %f\nrevers = %f\n", vald, reversevald);
          */
           int i;
           for( i = 0; i < 16; i++)
           {
               printf("%x ", cemiframe->data[i]);
           }
           printf("\n");


           float fl;
           uint8_t* p1 = (uint8_t*)&fl;
           *p1 = cemiframe->data[3];
           p1++;
           *p1 = cemiframe->data[2];
           p1++;
           *p1 = cemiframe->data[1];
           p1++;
           *p1 = cemiframe->data[0];

           
           //memmove( &fl,cemiframe->data,4);
           printf("MY float = %f\n",fl);
           printf("My int = %d\n",(int)fl);
           printf("My bool = %d\n",cemiframe->apci);
           
/*            enmx_frame2value( filtro->EIS, cemiframe, value );


            p_int = (uint32_t *)value;
            p_real = (double *)value;
           
            energia.valore = *p_real;
            printf("EIS = %d", filtro->EIS);
            printf("value string = %s", value);
            printf("\nvalue int = %d", *p_int);
            printf("\nvalue bool = %d", *(my_bool*)value);
            printf("\nvalue float = %f\n\n", *p_real);
  */
            
            if( filtro->writable )
            {
                while( insert_dati(conn, energia) > 0 )
                {
                    close_db_connection(conn);
                    start_db_connection(conn, "root","labdomvinci","10.0.0.55", 3306, "konnex");
                }
            }
        }
        
        //prepared( "root", "labdomvinci", "10.0.0.55", 3306, "konnex", energia);
    }
    close_db_connection(&conn);

    mysql_library_end();//termina la libreria mysql
    return( 0 );
}