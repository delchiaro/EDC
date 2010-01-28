#include "fct.h"
#include <polarssl/config.h>
#include <polarssl/md2.h>
#include <polarssl/md4.h>
#include <polarssl/md5.h>

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
    FCT_SUITE_BGN(test_suite_mdx)
    {
#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_1)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "8350e5a3e24c153df2275c9f80692773" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_2)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "a" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "32ec01ec4a6dac72c0ab96fb34c0b5d1" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_3)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "abc" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "da853b0d3f88d99b30283a69e6ded6bb" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_4)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "message digest" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "ab4f496bfb2a530b219ff33031fe06b0" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_5)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "4e8ddff3650292ab5a4108c3aa47940b" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_6)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "da33def2a42df13975352846c30338cd" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_test_vector_rfc1319_7)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
        
            md2( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d5976f79d83d3a0dc9806c3c66f3efd8" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_1)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "31d6cfe0d16ae931b73c59d7e0c089c0" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_2)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "a" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "bde52cb31de33e46245e05fbdbd6fb24" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_3)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "abc" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "a448017aaf21d8525fc10ae87aa6729d" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_4)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "message digest" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d9130a8164549fe818874806e1c7014b" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_5)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d79e1c308aa5bbcdeea8ed63df412da9" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_6)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "043f8582f241db351ce627e153e7f0e4" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_test_vector_rfc1320_7)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
        
            md4( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "e33b4ddc9c38f2199c3e7b164fcc0536" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_1)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d41d8cd98f00b204e9800998ecf8427e" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_2)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "a" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "0cc175b9c0f1b6a831c399e269772661" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_3)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "abc" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "900150983cd24fb0d6963f7d28e17f72" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_4)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "message digest" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "f96b697d7cb7938d525a2f31aaf161d0" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_5)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "c3fcd3d76192e4007dfb496cca67e13b" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_6)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d174ab98d277d9f5a5611c2c9f419d9f" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_test_vector_rfc1321_7)
        {
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[33];
        
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 33);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
        
            md5( src_str, strlen( (char *) src_str ), output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "57edf4a22be3c955ac49da2e2107b67a" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(hmac_md2_hash_file_openssl_test_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            md2_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "65046fb54ae83e4f52ec102e3a139a84", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(hmac_md2_hash_file_openssl_test_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            md2_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "545addf6466d11b94782312d42f55817", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(hmac_md2_hash_file_openssl_test_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            md2_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "cefddfc3ffbcb83136e78c75fe0860ce", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(hmac_md4_hash_file_openssl_test_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            md4_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "eabd0fbefb82fb0063a25a6d7b8bdc0f", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(hmac_md4_hash_file_openssl_test_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            md4_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "cec3c5e421a7b783aa89cacf78daf6dc", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(hmac_md4_hash_file_openssl_test_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            md4_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "ad5f0a04116109b397b57f9cc9b6df4b", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_hash_file_openssl_test_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "42552882f00bd4633ea81135a184b284", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_hash_file_openssl_test_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "a16a842891786d01fe50ba7731db7464", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_hash_file_openssl_test_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "e97f623936f98a7f741c4bd0612fecc2", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_1)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" );
            src_len = unhexify( src_str, "4869205468657265" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "9294727a3638bb1c13f48ef8158bfc9d", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_2)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "4a656665" );
            src_len = unhexify( src_str, "7768617420646f2079612077616e7420666f72206e6f7468696e673f" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "750c783e6ab0b503eaa86e310a5db738", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_3)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "56be34521d144c88dbb8c733f0e8b3f6", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_4)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "0102030405060708090a0b0c0d0e0f10111213141516171819" );
            src_len = unhexify( src_str, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "697eaf0aca3a3aea3a75164746ffaa79", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_5)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" );
            src_len = unhexify( src_str, "546573742057697468205472756e636174696f6e" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "56461ef2342edc00f9bab995", 12 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_6)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(hmac_md5_test_vector_rfc2202_7)
        {
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[33];
            int key_len, src_len;
        
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 33);
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461" );
        
            md5_hmac( key_str, key_len, src_str, src_len, output );
            hexify( hash_str, output, 16 );
        
            fct_chk( strncmp( (char *) hash_str, "6f630fad67cda0ee1fb1f562db3aa53e", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_hash_file_1)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md2_file( "data_files/hash_file_1", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "b593c098712d2e21628c8986695451a8" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_hash_file_2)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md2_file( "data_files/hash_file_2", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "3c027b7409909a4c4b26bbab69ad9f4f" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_hash_file_3)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md2_file( "data_files/hash_file_3", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "6bb43eb285e81f414083a94cdbe2989d" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md2_hash_file_4)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md2_file( "data_files/hash_file_4", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "8350e5a3e24c153df2275c9f80692773" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_hash_file_1)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md4_file( "data_files/hash_file_1", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "8d19772c176bd27153b9486715e2c0b9" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_hash_file_2)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md4_file( "data_files/hash_file_2", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "f2ac53b8542882a5a0007c6f84b4d9fd" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_hash_file_3)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md4_file( "data_files/hash_file_3", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "195c15158e2d07881d9a654095ce4a42" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_hash_file_4)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md4_file( "data_files/hash_file_4", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "31d6cfe0d16ae931b73c59d7e0c089c0" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_hash_file_1)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md5_file( "data_files/hash_file_1", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "52bcdc983c9ed64fc148a759b3c7a415" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_hash_file_2)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md5_file( "data_files/hash_file_2", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d17d466f15891df10542207ae78277f0" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_hash_file_3)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md5_file( "data_files/hash_file_3", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d945bcc6200ea95d061a2a818167d920" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_hash_file_4)
        {
            unsigned char hash_str[65];
            unsigned char output[33];
        
            memset(hash_str, 0x00, 65);
            memset(output, 0x00, 33);
        
            md5_file( "data_files/hash_file_4", output);
            hexify( hash_str, output, 16 );
        
            fct_chk( strcmp( (char *) hash_str, "d41d8cd98f00b204e9800998ecf8427e" ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(md2_selftest)
        {
            fct_chk( md2_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(md4_selftest)
        {
            fct_chk( md4_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(md5_selftest)
        {
            fct_chk( md5_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif

    }
    FCT_SUITE_END();
}
FCT_END();
