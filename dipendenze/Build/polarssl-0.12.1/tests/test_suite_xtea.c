#include "fct.h"
#include <polarssl/xtea.h>

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
    FCT_SUITE_BGN(test_suite_xtea)
    {

        FCT_TEST_BGN(xtea_encrypt_ecb_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "000102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "4142434445464748" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "497df3d072612cb5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_encrypt_ecb_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "000102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "4141414141414141" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "e78f2d13744341d8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_encrypt_ecb_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "000102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "5a5b6e278948d77f" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "4141414141414141" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_encrypt_ecb_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "4142434445464748" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "a0390589f8b8efa5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_encrypt_ecb_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "4141414141414141" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "ed23375a821a8c2d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_encrypt_ecb_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "70e1225d6e4e7655" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "4141414141414141" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_decrypt_ecb_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "000102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "497df3d072612cb5" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_DECRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "4142434445464748" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_decrypt_ecb_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "000102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "e78f2d13744341d8" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_DECRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "4141414141414141" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_decrypt_ecb_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "000102030405060708090a0b0c0d0e0f" );
            unhexify( src_str, "4141414141414141" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_DECRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "5a5b6e278948d77f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_decrypt_ecb_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "a0390589f8b8efa5" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_DECRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "4142434445464748" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_decrypt_ecb_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ed23375a821a8c2d" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_DECRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "4141414141414141" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_decrypt_ecb_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            xtea_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "4141414141414141" );
        
            xtea_setup( &ctx, key_str );
            xtea_crypt_ecb( &ctx, XTEA_DECRYPT, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcmp( (char *) dst_str, "70e1225d6e4e7655" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(xtea_selftest)
        {
            fct_chk( xtea_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();
}
FCT_END();
