#include "fct.h"
#include <polarssl/arc4.h>

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
    FCT_SUITE_BGN(test_suite_arc4)
    {

        FCT_TEST_BGN(test_vector_arc4_cryptlib)
        {
            unsigned char src_str[1000];
            unsigned char key_str[1000];
            unsigned char dst_str[2000];
            int src_len, key_len;
            arc4_context ctx;
        
            memset(src_str, 0x00, 1000);
            memset(key_str, 0x00, 1000);
            memset(dst_str, 0x00, 2000);
        
            src_len = unhexify( src_str, "0000000000000000" );
            key_len = unhexify( key_str, "0123456789abcdef" );
        
            arc4_setup(&ctx, key_str, key_len);
            arc4_crypt(&ctx, src_str, src_len);
            hexify( dst_str, src_str, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "7494c2e7104b0879" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_vector_arc4_commerce)
        {
            unsigned char src_str[1000];
            unsigned char key_str[1000];
            unsigned char dst_str[2000];
            int src_len, key_len;
            arc4_context ctx;
        
            memset(src_str, 0x00, 1000);
            memset(key_str, 0x00, 1000);
            memset(dst_str, 0x00, 2000);
        
            src_len = unhexify( src_str, "dcee4cf92c" );
            key_len = unhexify( key_str, "618a63d2fb" );
        
            arc4_setup(&ctx, key_str, key_len);
            arc4_crypt(&ctx, src_str, src_len);
            hexify( dst_str, src_str, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "f13829c9de" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_vector_arc4_ssh_arcfour)
        {
            unsigned char src_str[1000];
            unsigned char key_str[1000];
            unsigned char dst_str[2000];
            int src_len, key_len;
            arc4_context ctx;
        
            memset(src_str, 0x00, 1000);
            memset(key_str, 0x00, 1000);
            memset(dst_str, 0x00, 2000);
        
            src_len = unhexify( src_str, "527569736c696e6e756e206c61756c75206b6f727669737373616e692c2074e4686be470e46964656e2070e4e46c6ce42074e47973696b75752e204b6573e479f66e206f6e206f6e6e69206f6d616e616e692c206b61736b6973617675756e206c61616b736f7420766572686f75752e20456e206d6120696c6f697473652c20737572652068756f6b61612c206d75747461206d657473e46e2074756d6d757573206d756c6c652074756f6b61612e205075756e746f2070696c76656e2c206d692068756b6b75752c207369696e746f20766172616e207475756c6973656e2c206d69206e756b6b75752e2054756f6b7375742076616e616d6f6e206a61207661726a6f74207665656e2c206e69697374e420737964e46d656e69206c61756c756e207465656e2e202d2045696e6f204c65696e6f" );
            key_len = unhexify( key_str, "29041972fb42ba5fc7127712f13829c9" );
        
            arc4_setup(&ctx, key_str, key_len);
            arc4_crypt(&ctx, src_str, src_len);
            hexify( dst_str, src_str, src_len );
        
            fct_chk( strcmp( (char *) dst_str, "358186999001e6b5daf05eceeb7eee21e0689c1f00eea81f7dd2caaee1d2763e68af0ead33d66c268bc946c484fbe94c5f5e0b86a59279e4f824e7a640bd223210b0a61160b7bce986ea65688003596b630a6b90f8e0caf6912a98eb872176e83c202caa64166d2cce57ff1bca57b213f0ed1aa72fb8ea52b0be01cd1e412867720b326eb389d011bd70d8af035fb0d8589dbce3c666f5ea8d4c7954c50c3f340b0467f81b425961c11843074df620f208404b394cf9d37ff54b5f1ad8f6ea7da3c561dfa7281f964463d2cc35a4d1b03490dec51b0711fbd6f55f79234d5b7c766622a66de92be996461d5e4dc878ef9bca030521e8351e4baed2fd04f9467368c4ad6ac186d08245b263a2666d1f6c5420f1599dfd9f438921c2f5a463938ce0982265eef70179bc553f339eb1a4c1af5f6a547f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(arc4_selftest)
        {
            fct_chk( arc4_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();
}
FCT_END();
