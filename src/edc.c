
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

/*
typedef struct
{
    enum Type { boolean, integer, floating };
    union
    {
        my_bool boolean;
        int integer;
        float floating;
    }value;
    enum Type type;
}Value;
*/

#include "prepared.c"



int prepared ( char* user, char* pwd, char* ip, int porta, char* dbname, Energia energia);
int edc_frame2value( CEMIFRAME *cemiframe, long eis, float *returned );


/*
int scanDestinatario(char *EIBtarget, char* EIBuser, char* EIBpwd, char DB)
{
    sock_con = enmx_open( target, "eibtrace" );
    if( sock_con < 0 )
    {
        fprintf( stderr, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        exit( -2 );
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


    Filtro filtro ;
    MYSQL *conn = NULL;

    initFiltro(&filtro);

    start_db_connection(&conn, "root","labdomvinci","10.0.0.55", 3306, "konnex");

    enmx_monitor( sock_con, 0xffff, buf, &buflen, &value_size );
}*/

typedef struct
{
    char eibTarget[23]; // IP:PORT
    char eibUser[20];
    char eibPwd[20];
    char dbIP[16];
    int dbPort;
    char dbUser[20];
    char dbPwd[20];
    char dbDatabase[20];

}EDC_Parameter;


void processParameterHelp()
{
            puts("-t      eibnetmuxTarget (ip:port)");
            puts("-eu     eibnetmuxUser");
            puts("-ep     eibnetmuxPwd");
            puts("-ip     dbIpAddress");
            puts("-port   dbPort");
            puts("-user   dbUsername");
            puts("-pwd    dbPassword");
            puts("-db     databaseName");
            exit(0);
}
EDC_Parameter processParameter(int argc, char** argv)
{
    /*  -t      eibnetmuxTarget (ip:port)
     *  -eu     eibnetmuxUser
     *  -ep     eibnetmuxPwd
     *
     *  -ip     dbIpAddress
     *  -port   dbPort
     *  -user   dbUsername
     *  -pwd    dbPassword
     *  -db     databaseName
     */
    
    if( argc == 1) processParameterHelp();
    EDC_Parameter param;
    strcpy(param.dbDatabase, "");
    param.dbPort = 0;
    strcpy(param.dbIP,"");
    strcpy(param.dbPwd,"");
    strcpy(param.dbUser,"");
    strcpy(param.eibPwd,"");
    strcpy(param.eibTarget,"");
    strcpy(param.eibUser,"");
    
    int i;
    for(i = 0; i < argc; i++)
    {
        if( strcmp(argv[i], "-t") == 0)
        {
            i++;
            strcpy(param.eibTarget, argv[i]);
        }
        else if( strcmp(argv[i], "-eu") == 0)
        {
            i++;
            strcpy(param.eibUser, argv[i]);
        }
        else if( strcmp(argv[i], "-ep") == 0)
        {
            i++;
            strcpy(param.eibPwd, argv[i]);
        }


        else if( strcmp(argv[i], "-ip") == 0)
        {
            i++;
            strcpy(param.dbIP, argv[i]);
        }
        else if( strcmp(argv[i], "-port") == 0)
        {
            i++;
            strcpy(param.dbPort, atoi(argv[i]));
        }
        else if( strcmp(argv[i], "-user") == 0)
        {
            i++;
            strcpy(param.dbUser, argv[i]);
        }
        else if( strcmp(argv[i], "-pwd") == 0)
        {
            i++;
            strcpy(param.dbPwd, argv[i]);
        }
        else if( strcmp(argv[i], "-db") == 0)
        {
            i++;
            strcpy(param.dbDatabase, argv[i]);
        }
        else if( strcmp(argv[i], "-?") == 0)
        {
            processParameterHelp();
        }
        
    }
    
}

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

    int                     total = -1;
    int                     count = 0;
    int                     spaces = 1;
    char                    *user = NULL;
    char                    pwd[255];
    char                    *target;

    EDC_Parameter param;
    param = processParameter(argc, argv);

    printf("database = %s , ip = %s",param.dbDatabase, param.dbIP);


    //Connessione verso eibnetmux **********************************************
    enmx_version = enmx_init();
    sock_con = enmx_open( param.eibTarget, "EDC" );
    if( sock_con < 0 )
    {
        fprintf( stderr, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        return -2;
    }
    // Autenticazione verso il server EIBnetumx
    if( strcmp(param.eibUser, "") == 0 )
    {
        if( getpassword( param.eibPwd ) != 0 )
        {
            fprintf( stderr, "Error reading password - cannot continue\n" );
            return -6;
        }

        if( enmx_auth( sock_con, param.eibUser, param.eibPwd ) != 0 )
        {
            fprintf( stderr, "Authentication failure\n" );
            return -3;
        }
    }

    printf( "Connection to eibnetmux '%s' established\n", enmx_gethost( sock_con ));
    //**************************************************************************


    if (mysql_library_init(0, NULL, NULL)) //inizializza la CLI di my_sql
    {
        printf(NULL, "mysql_library_init() failed");
        return 3;
    }


    buf = malloc( 27 );
    buflen = 10;
    if( total != -1 )
    {
        spaces = floor( log10( total )) +1;
    }

    
    Filtro filtro ;
    MYSQL *conn = NULL;

    initFiltro(&filtro);


    
    start_db_connection(&conn, param.dbUser,param.dbPwd,param.dbIP, param.dbPort, param.dbDatabase);

    


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

            //conversione dei dati:

            float fl;
            edc_frame2value( cemiframe, filtro.EIS, &fl );

            energia.valore = fl;

            if( filtro.writable )
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



int edc_frame2value( CEMIFRAME *cemiframe, long eis, float *returned )
{
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
     *  return 0: no errors                                                  *
     *  return 1: EIS non identificato                                       *
     *  return 2: EIS non gestito da questa funzione                         *
     *
     *
     *
     *
     *
     *
     *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    printf("EIS = %d\n", eis);

    switch( eis )
    {
        //conversione bool 1 byte:
        case 1:
        case 2:
        case 7:
        case 8:
        {
            if( cemiframe->apci == 128 ) *returned = 0.0;
            else *returned = 1.0;

            printf("APCI = %d\n", cemiframe->apci -128 );
            printf("valore = %f\n", *returned );
            break;
        }

        //conversione int 2 byte
        case 6:
        case 14:
        {
            enmx_frame2value(eis, cemiframe, (void*)&returned);
            break;
        }


        //conversione floaot 2byte
        case 5:

        //conversione floaot 4byte
        case 9:
        case 10:
        case 11:
        case 12:
        {
            uint8_t* p1 = (uint8_t*)returned;
           *p1 = cemiframe->data[3];
           p1++;
           *p1 = cemiframe->data[2];
           p1++;
           *p1 = cemiframe->data[1];
           p1++;
           *p1 = cemiframe->data[0];
            break;
        }
        case 3:
        case 4:
        {
            //data e ora
            return 2;
        }
        default: return 1;
    }
}
