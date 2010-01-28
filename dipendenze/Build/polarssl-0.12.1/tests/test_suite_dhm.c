#include "fct.h"
#include <polarssl/dhm.h>

static int myrand( void *r )
{
    if ( r != NULL )
        r = NULL;

    return( rand() );
}


int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}


FCT_BGN()
{
    FCT_SUITE_BGN(test_suite_dhm)
    {

        FCT_TEST_BGN(diffie_hellman_full_exchange_1)
        {
            dhm_context ctx_srv;
            dhm_context ctx_cli;
            unsigned char ske[1000];
            unsigned char *p = ske;
            unsigned char pub_cli[1000];
            unsigned char sec_srv[1000];
            unsigned char sec_cli[1000];
            int ske_len = 0;
            int pub_cli_len = 0;
            int sec_srv_len = 1000;
            int sec_cli_len = 1000;
            int x_size;
        
            memset( &ctx_srv, 0x00, sizeof( dhm_context ) );
            memset( &ctx_cli, 0x00, sizeof( dhm_context ) );
            memset( ske, 0x00, 1000 );
            memset( pub_cli, 0x00, 1000 );
            memset( sec_srv, 0x00, 1000 );
            memset( sec_cli, 0x00, 1000 );
        
            fct_chk( mpi_read_string( &ctx_srv.P, 10, "23" ) == 0 );
            fct_chk( mpi_read_string( &ctx_srv.G, 10, "5" ) == 0 );
            x_size = mpi_size( &ctx_srv.P );
        
            fct_chk( dhm_make_params( &ctx_srv, x_size, ske, &ske_len, &myrand, NULL ) == 0 );
            ske[ske_len++] = 0;
            ske[ske_len++] = 0;
            fct_chk( dhm_read_params( &ctx_cli, &p, ske + ske_len ) == 0 );
        
            pub_cli_len = x_size;
            fct_chk( dhm_make_public( &ctx_cli, x_size, pub_cli, pub_cli_len, &myrand, NULL ) == 0 );
        
            fct_chk( dhm_read_public( &ctx_srv, pub_cli, pub_cli_len ) == 0 );
        
            fct_chk( dhm_calc_secret( &ctx_srv, sec_srv, &sec_srv_len ) == 0 );
            fct_chk( dhm_calc_secret( &ctx_cli, sec_cli, &sec_cli_len ) == 0 );
        
            fct_chk( sec_srv_len == sec_cli_len );
            fct_chk( sec_srv_len != 0 );
            fct_chk( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(diffie_hellman_full_exchange_2)
        {
            dhm_context ctx_srv;
            dhm_context ctx_cli;
            unsigned char ske[1000];
            unsigned char *p = ske;
            unsigned char pub_cli[1000];
            unsigned char sec_srv[1000];
            unsigned char sec_cli[1000];
            int ske_len = 0;
            int pub_cli_len = 0;
            int sec_srv_len = 1000;
            int sec_cli_len = 1000;
            int x_size;
        
            memset( &ctx_srv, 0x00, sizeof( dhm_context ) );
            memset( &ctx_cli, 0x00, sizeof( dhm_context ) );
            memset( ske, 0x00, 1000 );
            memset( pub_cli, 0x00, 1000 );
            memset( sec_srv, 0x00, 1000 );
            memset( sec_cli, 0x00, 1000 );
        
            fct_chk( mpi_read_string( &ctx_srv.P, 10, "93450983094850938450983409623" ) == 0 );
            fct_chk( mpi_read_string( &ctx_srv.G, 10, "9345098304850938450983409622" ) == 0 );
            x_size = mpi_size( &ctx_srv.P );
        
            fct_chk( dhm_make_params( &ctx_srv, x_size, ske, &ske_len, &myrand, NULL ) == 0 );
            ske[ske_len++] = 0;
            ske[ske_len++] = 0;
            fct_chk( dhm_read_params( &ctx_cli, &p, ske + ske_len ) == 0 );
        
            pub_cli_len = x_size;
            fct_chk( dhm_make_public( &ctx_cli, x_size, pub_cli, pub_cli_len, &myrand, NULL ) == 0 );
        
            fct_chk( dhm_read_public( &ctx_srv, pub_cli, pub_cli_len ) == 0 );
        
            fct_chk( dhm_calc_secret( &ctx_srv, sec_srv, &sec_srv_len ) == 0 );
            fct_chk( dhm_calc_secret( &ctx_cli, sec_cli, &sec_cli_len ) == 0 );
        
            fct_chk( sec_srv_len == sec_cli_len );
            fct_chk( sec_srv_len != 0 );
            fct_chk( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(diffie_hellman_full_exchange_2)
        {
            dhm_context ctx_srv;
            dhm_context ctx_cli;
            unsigned char ske[1000];
            unsigned char *p = ske;
            unsigned char pub_cli[1000];
            unsigned char sec_srv[1000];
            unsigned char sec_cli[1000];
            int ske_len = 0;
            int pub_cli_len = 0;
            int sec_srv_len = 1000;
            int sec_cli_len = 1000;
            int x_size;
        
            memset( &ctx_srv, 0x00, sizeof( dhm_context ) );
            memset( &ctx_cli, 0x00, sizeof( dhm_context ) );
            memset( ske, 0x00, 1000 );
            memset( pub_cli, 0x00, 1000 );
            memset( sec_srv, 0x00, 1000 );
            memset( sec_cli, 0x00, 1000 );
        
            fct_chk( mpi_read_string( &ctx_srv.P, 10, "93450983094850938450983409623982317398171298719873918739182739712938719287391879381271" ) == 0 );
            fct_chk( mpi_read_string( &ctx_srv.G, 10, "9345098309485093845098340962223981329819812792137312973297123912791271" ) == 0 );
            x_size = mpi_size( &ctx_srv.P );
        
            fct_chk( dhm_make_params( &ctx_srv, x_size, ske, &ske_len, &myrand, NULL ) == 0 );
            ske[ske_len++] = 0;
            ske[ske_len++] = 0;
            fct_chk( dhm_read_params( &ctx_cli, &p, ske + ske_len ) == 0 );
        
            pub_cli_len = x_size;
            fct_chk( dhm_make_public( &ctx_cli, x_size, pub_cli, pub_cli_len, &myrand, NULL ) == 0 );
        
            fct_chk( dhm_read_public( &ctx_srv, pub_cli, pub_cli_len ) == 0 );
        
            fct_chk( dhm_calc_secret( &ctx_srv, sec_srv, &sec_srv_len ) == 0 );
            fct_chk( dhm_calc_secret( &ctx_cli, sec_cli, &sec_cli_len ) == 0 );
        
            fct_chk( sec_srv_len == sec_cli_len );
            fct_chk( sec_srv_len != 0 );
            fct_chk( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();
}
FCT_END();
