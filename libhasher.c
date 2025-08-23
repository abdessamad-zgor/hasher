#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tomcrypt.h"

#define _16_BYTES 16
#define _20_BYTES 20
#define _24_BYTES 24
#define _28_BYTES 28
#define _32_BYTES 32
#define _40_BYTES 40
#define _48_BYTES 48
#define _64_BYTES 64

char *to_hex_repr(unsigned char *data, int length)
{
    int i = 0;
    char *base = "0123456789abcdef";
    int lenbase = strlen(base);
    char *repr = malloc(length * 2 * sizeof(char));
    while(i < length)
    {
        repr[i] = base[(int)data[i] / lenbase];
        repr[i + 1] = base[(int)data[i] % lenbase];
        i += 2;
    }
    return repr;
}

char *md5_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_16_BYTES * sizeof(unsigned char));

    md5_init(&hs);
    md5_process(&hs,(const unsigned char*)str, len);
    md5_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _16_BYTES);
    return out;
}

char *md4_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_16_BYTES * sizeof(unsigned char));

    md4_init(&hs);
    md4_process(&hs,(const unsigned char*)str, len);
    md4_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _16_BYTES);
    return out;
}

char *md2_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_16_BYTES * sizeof(unsigned char));

    md2_init(&hs);
    md2_process(&hs,(const unsigned char*)str, len);
    md2_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _16_BYTES);
    return out;
}

char *blake2s_128_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_16_BYTES * sizeof(unsigned char));

    blake2s_128_init(&hs);
    blake2s_process(&hs,(const unsigned char*)str, len);
    blake2s_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _16_BYTES);
    return out;
}

char *rmd128_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_16_BYTES * sizeof(unsigned char));

    rmd128_init(&hs);
    rmd128_process(&hs,(const unsigned char*)str, len);
    rmd128_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _16_BYTES);
    return out;
}

char *blake2s_160_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_20_BYTES * sizeof(unsigned char));

    blake2s_160_init(&hs);
    blake2s_process(&hs,(const unsigned char*)str, len);
    blake2s_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _20_BYTES);
    return out;
}

char *blake2b_160_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_20_BYTES * sizeof(unsigned char));

    blake2b_160_init(&hs);
    blake2b_process(&hs,(const unsigned char*)str, len);
    blake2b_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _20_BYTES);
    return out;
}

char *rmd160_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_20_BYTES * sizeof(unsigned char));

    rmd160_init(&hs);
    rmd160_process(&hs,(const unsigned char*)str, len);
    rmd160_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _20_BYTES);
    return out;
}

char *sha1_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_20_BYTES * sizeof(unsigned char));

    sha1_init(&hs);
    sha1_process(&hs,(const unsigned char*)str, len);
    sha1_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _20_BYTES);
    return out;
}

char *tiger2_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_24_BYTES * sizeof(unsigned char));

    tiger2_init(&hs);
    tiger2_process(&hs,(const unsigned char*)str, len);
    tiger2_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _24_BYTES);
    return out;
}

char *tiger_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_24_BYTES * sizeof(unsigned char));

    tiger_init(&hs);
    tiger_process(&hs,(const unsigned char*)str, len);
    tiger_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _24_BYTES);
    return out;
}

char *blake2s_224_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_28_BYTES * sizeof(unsigned char));

    blake2s_224_init(&hs);
    blake2s_process(&hs,(const unsigned char*)str, len);
    blake2s_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _28_BYTES);
    return out;
}

char *sha224_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_28_BYTES * sizeof(unsigned char));

    sha224_init(&hs);
    sha224_process(&hs,(const unsigned char*)str, len);
    sha224_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _28_BYTES);
    return out;
}

char *sha3_224_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_28_BYTES * sizeof(unsigned char));

    sha3_224_init(&hs);
    sha3_process(&hs,(const unsigned char*)str, len);
    sha3_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _28_BYTES);
    return out;
}

char *keccak_224_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_28_BYTES * sizeof(unsigned char));

    keccak_224_init(&hs);
    keccak_process(&hs,(const unsigned char*)str, len);
    keccak_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _28_BYTES);
    return out;
}

char *sha512_224_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_28_BYTES * sizeof(unsigned char));

    sha512_224_init(&hs);
    sha512_224_process(&hs,(const unsigned char*)str, len);
    sha512_224_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _28_BYTES);
    return out;
}

char *blake2b_256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    blake2b_256_init(&hs);
    blake2b_process(&hs,(const unsigned char*)str, len);
    blake2b_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *blake2s_256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    blake2s_256_init(&hs);
    blake2s_process(&hs,(const unsigned char*)str, len);
    blake2s_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *rmd256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    rmd256_init(&hs);
    rmd256_process(&hs,(const unsigned char*)str, len);
    rmd256_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *sha256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    sha256_init(&hs);
    sha256_process(&hs,(const unsigned char*)str, len);
    sha256_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *sha3_256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    sha3_256_init(&hs);
    sha3_process(&hs,(const unsigned char*)str, len);
    sha3_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *keccak_256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    keccak_256_init(&hs);
    keccak_process(&hs,(const unsigned char*)str, len);
    keccak_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *sha512_256_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_32_BYTES * sizeof(unsigned char));

    sha512_256_init(&hs);
    sha512_256_process(&hs,(const unsigned char*)str, len);
    sha512_256_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _32_BYTES);
    return out;
}

char *rmd320_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_40_BYTES * sizeof(unsigned char));

    rmd320_init(&hs);
    rmd320_process(&hs,(const unsigned char*)str, len);
    rmd320_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _40_BYTES);
    return out;
}

char *blake2b_384_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_48_BYTES * sizeof(unsigned char));

    blake2b_384_init(&hs);
    blake2b_process(&hs,(const unsigned char*)str, len);
    blake2b_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _48_BYTES);
    return out;
}


char *sha384_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_48_BYTES * sizeof(unsigned char));

    sha384_init(&hs);
    sha384_process(&hs,(const unsigned char*)str, len);
    sha384_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _48_BYTES);
    return out;
}

char *sha3_384_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_48_BYTES * sizeof(unsigned char));

    sha3_384_init(&hs);
    sha3_process(&hs,(const unsigned char*)str, len);
    sha3_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _48_BYTES);
    return out;
}

char *keccak_384_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_48_BYTES * sizeof(unsigned char));

    keccak_384_init(&hs);
    keccak_process(&hs,(const unsigned char*)str, len);
    keccak_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _48_BYTES);
    return out;
}

char *blake2b_512_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_64_BYTES * sizeof(unsigned char));

    blake2b_512_init(&hs);
    blake2b_process(&hs,(const unsigned char*)str, len);
    blake2b_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _64_BYTES);
    return out;
}

char *sha512_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_64_BYTES * sizeof(unsigned char));

    sha512_init(&hs);
    sha512_process(&hs,(const unsigned char*)str, len);
    sha512_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _64_BYTES);
    return out;
}

char *sha3_512_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_64_BYTES * sizeof(unsigned char));

    sha3_512_init(&hs);
    sha3_process(&hs,(const unsigned char*)str, len);
    sha3_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _64_BYTES);
    return out;
}

char *keccak_512_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_64_BYTES * sizeof(unsigned char));

    keccak_512_init(&hs);
    keccak_process(&hs,(const unsigned char*)str, len);
    keccak_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _64_BYTES);
    return out;
}

char *whirlpool_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(_64_BYTES * sizeof(unsigned char));

    whirlpool_init(&hs);
    whirlpool_process(&hs,(const unsigned char*)str, len);
    whirlpool_done(&hs, tc_out);

    out = to_hex_repr(tc_out, _64_BYTES);
    return out;
}
