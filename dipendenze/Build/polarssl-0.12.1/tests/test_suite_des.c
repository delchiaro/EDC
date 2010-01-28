#include "fct.h"
#include <polarssl/des.h>

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
    FCT_SUITE_BGN(test_suite_des)
    {

        FCT_TEST_BGN(des_encrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "0000000000000000" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "8CA64DE9C1B123A7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FFFFFFFFFFFFFFFF" );
            unhexify( src_str, "FFFFFFFFFFFFFFFF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "7359B2163E4EDC58" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "3000000000000000" );
            unhexify( src_str, "1000000000000001" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "958E6E627A05557B" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "1111111111111111" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "F40379AB9E0EC533" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789ABCDEF" );
            unhexify( src_str, "1111111111111111" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "17668DFC7292532D" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "0123456789ABCDEF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "8A5AE1F81AB8F2DD" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "0000000000000000" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "8CA64DE9C1B123A7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FEDCBA9876543210" );
            unhexify( src_str, "0123456789ABCDEF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "ED39D950FA74BCC4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "7CA110454A1A6E57" );
            unhexify( src_str, "01A1D6D039776742" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "690F5B0D9A26939B" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0131D9619DC1376E" );
            unhexify( src_str, "5CD54CA83DEF57DA" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "7A389D10354BD271" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "07A1133E4A0B2686" );
            unhexify( src_str, "0248D43806F67172" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "868EBB51CAB4599A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "3849674C2602319E" );
            unhexify( src_str, "51454B582DDF440A" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "7178876E01F19B2A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "04B915BA43FEB5B6" );
            unhexify( src_str, "42FD443059577FA2" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "AF37FB421F8C4095" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0113B970FD34F2CE" );
            unhexify( src_str, "059B5E0851CF143A" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "86A560F10EC6D85B" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0170F175468FB5E6" );
            unhexify( src_str, "0756D8E0774761D2" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0CD3DA020021DC09" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "43297FAD38E373FE" );
            unhexify( src_str, "762514B829BF486A" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "EA676B2CB7DB2B7A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "07A7137045DA2A16" );
            unhexify( src_str, "3BDD119049372802" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "DFD64A815CAF1A0F" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "04689104C2FD3B2F" );
            unhexify( src_str, "26955F6835AF609A" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "5C513C9C4886C088" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_19)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "37D06BB516CB7546" );
            unhexify( src_str, "164D5E404F275232" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0A2AEEAE3FF4AB77" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_20)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1F08260D1AC2465E" );
            unhexify( src_str, "6B056E18759F5CCA" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "EF1BF03E5DFA575A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_21)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "584023641ABA6176" );
            unhexify( src_str, "004BD6EF09176062" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "88BF0DB6D70DEE56" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_22)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "025816164629B007" );
            unhexify( src_str, "480D39006EE762F2" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "A1F9915541020B56" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_23)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "49793EBC79B3258F" );
            unhexify( src_str, "437540C8698F3CFA" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "6FBF1CAFCFFD0556" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_24)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "4FB05E1515AB73A7" );
            unhexify( src_str, "072D43A077075292" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "2F22E49BAB7CA1AC" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_25)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "49E95D6D4CA229BF" );
            unhexify( src_str, "02FE55778117F12A" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "5A6B612CC26CCE4A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_26)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "018310DC409B26D6" );
            unhexify( src_str, "1D9D5C5018F728C2" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "5F4C038ED12B2E41" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_27)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1C587F1C13924FEF" );
            unhexify( src_str, "305532286D6F295A" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "63FAC0D034D9F793" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_28)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0101010101010101" );
            unhexify( src_str, "0123456789ABCDEF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "617B3A0CE8F07100" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_29)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1F1F1F1F0E0E0E0E" );
            unhexify( src_str, "0123456789ABCDEF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "DB958605F8C8C606" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_30)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "E0FEE0FEF1FEF1FE" );
            unhexify( src_str, "0123456789ABCDEF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "EDBFD1C66C29CCC7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_31)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "FFFFFFFFFFFFFFFF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "355550B2150E2451" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_32)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FFFFFFFFFFFFFFFF" );
            unhexify( src_str, "0000000000000000" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "CAAAAF4DEAF1DBAE" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_33)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789ABCDEF" );
            unhexify( src_str, "0000000000000000" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "D5D44FF720683D0D" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_encrypt_openssl_test_vector_34)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FEDCBA9876543210" );
            unhexify( src_str, "FFFFFFFFFFFFFFFF" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "2A2BB008DF97C2F2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "8CA64DE9C1B123A7" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0000000000000000" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FFFFFFFFFFFFFFFF" );
            unhexify( src_str, "7359B2163E4EDC58" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "FFFFFFFFFFFFFFFF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "3000000000000000" );
            unhexify( src_str, "958E6E627A05557B" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "1000000000000001" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "F40379AB9E0EC533" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "1111111111111111" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789ABCDEF" );
            unhexify( src_str, "17668DFC7292532D" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "1111111111111111" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1111111111111111" );
            unhexify( src_str, "8A5AE1F81AB8F2DD" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0123456789ABCDEF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "8CA64DE9C1B123A7" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0000000000000000" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FEDCBA9876543210" );
            unhexify( src_str, "ED39D950FA74BCC4" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0123456789ABCDEF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "7CA110454A1A6E57" );
            unhexify( src_str, "690F5B0D9A26939B" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "01A1D6D039776742" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0131D9619DC1376E" );
            unhexify( src_str, "7A389D10354BD271" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "5CD54CA83DEF57DA" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "07A1133E4A0B2686" );
            unhexify( src_str, "868EBB51CAB4599A" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0248D43806F67172" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "3849674C2602319E" );
            unhexify( src_str, "7178876E01F19B2A" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "51454B582DDF440A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "04B915BA43FEB5B6" );
            unhexify( src_str, "AF37FB421F8C4095" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "42FD443059577FA2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0113B970FD34F2CE" );
            unhexify( src_str, "86A560F10EC6D85B" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "059B5E0851CF143A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0170F175468FB5E6" );
            unhexify( src_str, "0CD3DA020021DC09" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0756D8E0774761D2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "43297FAD38E373FE" );
            unhexify( src_str, "EA676B2CB7DB2B7A" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "762514B829BF486A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "07A7137045DA2A16" );
            unhexify( src_str, "DFD64A815CAF1A0F" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "3BDD119049372802" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "04689104C2FD3B2F" );
            unhexify( src_str, "5C513C9C4886C088" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "26955F6835AF609A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_19)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "37D06BB516CB7546" );
            unhexify( src_str, "0A2AEEAE3FF4AB77" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "164D5E404F275232" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_20)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1F08260D1AC2465E" );
            unhexify( src_str, "EF1BF03E5DFA575A" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "6B056E18759F5CCA" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_21)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "584023641ABA6176" );
            unhexify( src_str, "88BF0DB6D70DEE56" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "004BD6EF09176062" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_22)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "025816164629B007" );
            unhexify( src_str, "A1F9915541020B56" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "480D39006EE762F2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_23)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "49793EBC79B3258F" );
            unhexify( src_str, "6FBF1CAFCFFD0556" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "437540C8698F3CFA" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_24)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "4FB05E1515AB73A7" );
            unhexify( src_str, "2F22E49BAB7CA1AC" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "072D43A077075292" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_25)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "49E95D6D4CA229BF" );
            unhexify( src_str, "5A6B612CC26CCE4A" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "02FE55778117F12A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_26)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "018310DC409B26D6" );
            unhexify( src_str, "5F4C038ED12B2E41" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "1D9D5C5018F728C2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_27)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1C587F1C13924FEF" );
            unhexify( src_str, "63FAC0D034D9F793" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "305532286D6F295A" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_28)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0101010101010101" );
            unhexify( src_str, "617B3A0CE8F07100" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0123456789ABCDEF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_29)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "1F1F1F1F0E0E0E0E" );
            unhexify( src_str, "DB958605F8C8C606" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0123456789ABCDEF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_30)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "E0FEE0FEF1FEF1FE" );
            unhexify( src_str, "EDBFD1C66C29CCC7" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0123456789ABCDEF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_31)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000" );
            unhexify( src_str, "355550B2150E2451" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "FFFFFFFFFFFFFFFF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_32)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FFFFFFFFFFFFFFFF" );
            unhexify( src_str, "CAAAAF4DEAF1DBAE" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0000000000000000" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_33)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789ABCDEF" );
            unhexify( src_str, "D5D44FF720683D0D" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0000000000000000" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_decrypt_openssl_test_vector_34)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FEDCBA9876543210" );
            unhexify( src_str, "2A2BB008DF97C2F2" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "FFFFFFFFFFFFFFFF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_cbc_encrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
            int src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789abcdef" );
            unhexify( iv_str, "fedcba9876543210" );
            src_len = unhexify( src_str, "37363534333231204E6F77206973207468652074696D6520" );
        
            des_setkey_enc( &ctx, key_str );
            des_crypt_cbc( &ctx, DES_ENCRYPT, src_len, iv_str, src_str, output );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcasecmp( (char *) dst_str, "ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba68" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_cbc_decrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des_context ctx;
            int src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789abcdef" );
            unhexify( iv_str, "fedcba9876543210" );
            src_len = unhexify( src_str, "ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba68" );
        
            des_setkey_dec( &ctx, key_str );
            des_crypt_cbc( &ctx, DES_DECRYPT, src_len, iv_str, src_str, output );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcasecmp( (char *) dst_str, "37363534333231204E6F77206973207468652074696D6520" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(3des_ecb_2key_encrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des3_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000FFFFFFFFFFFFFFFF" );
            unhexify( src_str, "0000000000000000" );
        
            if( 2 == 2 )
                des3_set2key_enc( &ctx, key_str );
            else if( 2 == 3 )
                des3_set3key_enc( &ctx, key_str );
            else
                fct_chk( 0 );
        
            des3_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "9295B59BB384736E" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(3des_ecb_2key_encrypt_openssl_test_vector_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des3_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FFFFFFFFFFFFFFFF3000000000000000" );
            unhexify( src_str, "FFFFFFFFFFFFFFFF" );
        
            if( 2 == 2 )
                des3_set2key_enc( &ctx, key_str );
            else if( 2 == 3 )
                des3_set3key_enc( &ctx, key_str );
            else
                fct_chk( 0 );
        
            des3_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "199E9D6DF39AA816" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(3des_ecb_2key_decrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des3_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0000000000000000FFFFFFFFFFFFFFFF" );
            unhexify( src_str, "9295B59BB384736E" );
        
            if( 2 == 2 )
                des3_set2key_dec( &ctx, key_str );
            else if( 2 == 3 )
                des3_set3key_dec( &ctx, key_str );
            else
                fct_chk( 0 );
        
            des3_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "0000000000000000" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(3des_ecb_2key_decrypt_openssl_test_vector_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des3_context ctx;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "FFFFFFFFFFFFFFFF3000000000000000" );
            unhexify( src_str, "199E9D6DF39AA816" );
        
            if( 2 == 2 )
                des3_set2key_dec( &ctx, key_str );
            else if( 2 == 3 )
                des3_set3key_dec( &ctx, key_str );
            else
                fct_chk( 0 );
        
            des3_crypt_ecb( &ctx, src_str, output );
            hexify( dst_str, output, 8 );
        
            fct_chk( strcasecmp( (char *) dst_str, "FFFFFFFFFFFFFFFF" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(3des_cbc_3key_encrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des3_context ctx;
            int src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789abcdeff1e0d3c2b5a49786fedcba9876543210" );
            unhexify( iv_str, "fedcba9876543210" );
            src_len = unhexify( src_str, "37363534333231204E6F77206973207468652074696D6520" );
        
            if( 3 == 2 )
                des3_set2key_enc( &ctx, key_str );
            else if( 3 == 3 )
                des3_set3key_enc( &ctx, key_str );
            else
                fct_chk( 0 );
        
            des3_crypt_cbc( &ctx, DES_ENCRYPT, src_len, iv_str, src_str, output );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcasecmp( (char *) dst_str, "3FE301C962AC01D02213763C1CBD4CDC799657C064ECF5D4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(3des_cbc_3key_decrypt_openssl_test_vector_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            des3_context ctx;
            int src_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            unhexify( key_str, "0123456789abcdeff1e0d3c2b5a49786fedcba9876543210" );
            unhexify( iv_str, "fedcba9876543210" );
            src_len = unhexify( src_str, "3FE301C962AC01D02213763C1CBD4CDC799657C064ECF5D4" );
        
            if( 3 == 2 )
                des3_set2key_dec( &ctx, key_str );
            else if( 3 == 3 )
                des3_set3key_dec( &ctx, key_str );
            else
                fct_chk( 0 );
        
            des3_crypt_cbc( &ctx, DES_DECRYPT, src_len, iv_str, src_str, output );
            hexify( dst_str, output, src_len );
        
            fct_chk( strcasecmp( (char *) dst_str, "37363534333231204E6F77206973207468652074696D6520" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(des_selftest)
        {
            fct_chk( des_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();
}
FCT_END();
