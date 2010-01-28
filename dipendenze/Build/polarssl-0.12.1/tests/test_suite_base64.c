#include "fct.h"
#include <polarssl/base64.h>

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
    FCT_SUITE_BGN(test_suite_base64)
    {

        FCT_TEST_BGN(test_case_base64_encode_1)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_2)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "f" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zg==" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_3)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "fo" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm8=" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_4)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foo" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9v" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_5)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foob" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYg==" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_6)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "fooba" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYmE=" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_7)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foobar" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYmFy" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_1)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_2)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zg==" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_3)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm8=" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "fo" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_4)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9v" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "foo" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_5)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9vYg==" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "foob" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_6)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9vYmE=" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "fooba" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_7)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9vYmFy" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "foobar" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_encode_buffer_size_just_right)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 9;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foobar" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYmFy" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_encode_buffer_size_too_small)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 8;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foobar" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL );
            if( POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_decode_illegal_character)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "zm#=" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_INVALID_CHARACTER );
            if( POLARSSL_ERR_BASE64_INVALID_CHARACTER == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_decode_too_much_equal_signs)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "zm===" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_INVALID_CHARACTER );
            if( POLARSSL_ERR_BASE64_INVALID_CHARACTER == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_decode_invalid_char_after_equal_signs)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            int len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "zm=masd" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_INVALID_CHARACTER );
            if( POLARSSL_ERR_BASE64_INVALID_CHARACTER == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_selftest)
        {
            fct_chk( base64_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();
}
FCT_END();
