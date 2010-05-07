
#include "dbconnection.h"
#include "eibtrace.h"


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



typedef struct
{
    char eibTarget[37]; // IP:PORT
    char eibUser[50];
    char eibPwd[50];
    char dbIP[30];
    int dbPort;
    char dbUser[50];
    char dbPwd[50];
    char dbDatabase[50];

}EDC_Parameter;

void init_EDC_Parameter(EDC_Parameter *param)
{
    strcpy(param->dbDatabase, "");
    param->dbPort = 0;
    strcpy(param->dbIP, "");
    strcpy(param->dbPwd, "");
    strcpy(param->dbUser, "");
    strcpy(param->eibPwd, "");
    strcpy(param->eibTarget, "");
    strcpy(param->eibUser, "");
}

void processParameterHelp();
EDC_Parameter processParameter(int argc, char** argv);
EDC_Parameter processParameterFile(char* path);


int main( int argc, char **argv )
{
    Energia energia;


    ENMX_HANDLE     sock_con = 0;
    //unsigned char   conn_state = 0;
    
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
    EDC_Parameter param;

    param = processParameter(argc, argv);
    if (mysql_library_init(0, NULL, NULL)) //inizializza la CLI di my_sql
    {
        printf(NULL, "mysql_library_init() failed");
        return 3;
    }




    //Connessione verso eibnetmux **********************************************
    enmx_version = enmx_init();


    //scanDestinatario(param.eibTarget);


    sock_con = enmx_open( param.eibTarget, "EDC" );
    if( sock_con < 0 )
    {
        fprintf( stderr, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        return -2;
    }


    printf( "Connection to eibnetmux '%s' established\n", enmx_gethost( sock_con ));
    //**************************************************************************





    buf = malloc( 27 );
    buflen = 10;
    if( total != -1 )
    {
        spaces = floor( log10( total )) +1;
    }


    Filtro filtro ;
    MYSQL *conn = NULL;

    initFiltro(&filtro);



    //start_db_connection(&conn, param.dbUser,param.dbPwd,param.dbIP, param.dbPort, param.dbDatabase);
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
            if( edc_frame2value( cemiframe, filtro.EIS, &fl ) == 0 )
            {
                energia.valore = fl;

                if( filtro.writable )
                {
                    while( insert_dati(conn, energia) > 0 )
                    {
                         close_db_connection(&conn);
                         start_db_connection(&conn, "root","labdomvinci","10.0.0.55", 3306, "konnex");
                    }
                }
            }
            else
            {
                printf("Conversione valore impossibile**\n");
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

    printf("EIS = %d\n", (int)eis);

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
            return 0;
        }


        //conversione int 1 - 2 - 4 byte
        case 6:  //1 byte
        case 11: //4 byte
        case 14: //1 byte
        {
            int value;
            enmx_frame2value(eis, cemiframe, (void*)&value);
            *returned = value;
            return 0;
        }


        //conversione float 2byte
        case 5:
        {
            unsigned char value[20];
            double *f;
            f = (double *)value;
            enmx_frame2value(eis, cemiframe, value);
            *returned = *f;
            return 0;
        }

        //conversione floaot 4byte
        case 9:
        case 10:
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
            return 0;
        }
        case 3:
        case 4:
        {
            //data e ora
            printf("ERRORE EIS DATA NON CONVERTIBILE\n");
            return 2;
        }
        default:
        {
            printf("ERRORE EIS NON RICONOSCIUTO\n");
            return 1;
        }
    }
    return 0;
}





void processParameterHelp()
{
    puts("-f      configFilePath");
    puts("-t      eibnetmuxTarget (ip:port)");
    puts("-eu     eibnetmuxUser");
    puts("-ep     eibnetmuxPwd");
    puts("-ip     dbIpAddress");
    puts("-port   dbPort");
    puts("-user   dbUsername");
    puts("-pwd    dbPassword");
    puts("-db     databaseName");
    puts("\n\nDefault: -f settings.eds");
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
    EDC_Parameter param;
    init_EDC_Parameter(&param);

    if( argc <= 1)
    {
        processParameterHelp();
        param = processParameterFile("settings.eds");
    }
    else
    {



        int i;
        for(i = 1; i < argc; i++)
        {


            if( strcmp(argv[i], "-f") == 0)
            {
                i++;
                param = processParameterFile(argv[i]);
            }
            if( strcmp(argv[i], "-t") == 0)
            {
                i++;
                strcpy(param.eibTarget,argv[i]);
            }
            else if( strcmp(argv[i], "-eu") == 0)
            {
                i++;
                strcpy(param.eibUser, argv[i]);
            }
            else if( strcmp(argv[i], "-ep") == 0)
            {
                i++;
                strcpy(param.eibPwd , argv[i]);
            }


            else if( strcmp(argv[i], "-ip") == 0)
            {
                i++;
                strcpy(param.dbIP , argv[i]);
            }

            else if( strcmp(argv[i], "-port") == 0)
            {
                i++;
                param.dbPort = atoi(argv[i]);
            }

            else if( strcmp(argv[i], "-user") == 0)
            {
                i++;
                strcpy(param.dbUser ,  argv[i]);
            }

            else if( strcmp(argv[i], "-pwd") == 0)
            {
                i++;
                strcpy(param.dbPwd , argv[i]);
            }

            else if( strcmp(argv[i], "-db") == 0)
            {
                i++;
                strcpy(param.dbDatabase, argv[i]);
            }

            else if( strcmp(argv[i], "-?") == 0)
            {
                processParameterHelp();
                exit(0);
            }

        }
    }

    return param;

}


EDC_Parameter processParameterFile(char* path)
{
    /* 
     EDC_CONFIG_FILE 0.1
     dbname:  <dbname>
     dbhost:  <dbhost>
     dbport:  <dbport>
     dbuser:  <dbUser>
     dbpwd:   <dbpwd>
     
     eibpwd:  <eibnetmuxPwd>
     eibuser: <eibnetmuxUser>
     eibtarget:   <eibHost:eibPort>

     * le righe possono essere inserite in qualsiasi ordine, ma il file deve iniziarecon EDC_CONFIG_FILE versione
     */
    EDC_Parameter param;
    init_EDC_Parameter(&param);
        
    FILE* file = NULL;
    file = fopen(path, "r");
    if( file == NULL)
    {
        printf("CANNOT OPEN FILE: NO FILE OR INACCESSIBLE FILE");
        exit(1);
    }
    char buf[100];
    char buf2[100];
    char bufversion[10];
    double version;


    fscanf(file, "%s %s", buf, bufversion);
    if( strcmp(buf, "EDC_CONFIG_FILE") == 0 )
    {
        version = atof(bufversion);
        while( !feof(file) )
        {
            fscanf(file, "%s %s", buf, buf2);
            if(strcmp(buf, "dbname:") == 0)
            {
                strcpy( param.dbDatabase, buf2);
            }

            else if(strcmp(buf, "dbhost:") == 0)
            {
                strcpy( param.dbIP, buf2);
            }

            else if(strcmp(buf, "dbport:") == 0)
            {
                param.dbPort = atoi(buf2);
            }

            else if(strcmp(buf, "dbuser:") == 0)
            {
                strcpy( param.dbUser, buf2);
            }

            else if(strcmp(buf, "dbpwd:") == 0)
            {
                strcpy( param.dbPwd, buf2);
            }

            else if(strcmp(buf, "eibuser:") == 0)
            {
                strcpy( param.eibUser, buf2);
            }

            else if(strcmp(buf, "eibpwd:") == 0)
            {
                strcpy( param.eibPwd, buf2);
            }

            else if(strcmp(buf, "eibtarget:") == 0)
            {
                strcpy( param.eibTarget, buf2);
            }

            else
            {
                printf("ERROR WHILE PARSING FILE");
                exit(1);
            }
            
            
        }
    }
    else
    {
        printf("FILE HEADER DON'T FOUND");
        exit(1);
    }

    return param;
}




// funzione da eseguire al posto del main.
// Questa funzione, dopo essersi connessa ad un server eibnetmux specificato dal parametro,
// sniffa tutti i pacchetti che passano similmente al main, estrae però solo il destinatario
// ed inserisce nel database, nella tabella filtro, tutti i destinatari che passano.
// Questa funzione è stata per ora soppiantata dalla routine creata da Hu che legge un file nello standard ETS(credo)
// contenente tutte le informazioni su EIS, destinatario, descrizione e che vengano caricati nella tabella filtro.
int scanDestinatario(char *target) 
{

    char* destinatario;

    ENMX_HANDLE     sock_con = 0;
    //unsigned char   conn_state = 0;

    uint16_t                value_size;
    struct timeval          tv;
    struct tm               *ltime;
    uint16_t                buflen;
    unsigned char           *buf;
    CEMIFRAME               *cemiframe;

    int                     total = -1;

    int                     spaces = 1;

    sock_con = enmx_open( target, "eibtrace" );
    if( sock_con < 0 )
    {
        fprintf( stderr, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        exit( -2 );
    }

    buf = malloc( 50 );
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
            cemiframe = (CEMIFRAME *) buf;

            sprintf( destinatario, "%8s", (cemiframe->ntwrk & EIB_DAF_GROUP) ? knx_group( cemiframe->daddr ) : knx_physical( cemiframe->daddr ));
            str_unfill(destinatario, ' ');


            puts(target);

            Filtro filtro;
            filtro.valid = 1;
            select_filtro(conn, destinatario, &filtro);
            if(filtro.valid == 1)
            {
                while( insert_filtro(conn, destinatario) > 0 )
                 {
                    close_db_connection(&conn);
                    start_db_connection(&conn, "root","labdomvinci","10.0.0.55", 3306, "konnex");
                }
            }


        }

        //prepared( "root", "labdomvinci", "10.0.0.55", 3306, "konnex", energia);
    }
    close_db_connection(&conn);
}
