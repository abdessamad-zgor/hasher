#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tomcrypt.h"

#define MD5_SIZE 16

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
    unsigned char *tc_out = malloc(MD5_SIZE * sizeof(unsigned char));

    md5_init(&hs);
    md5_process(&hs, str, len);
    md5_done(&hs, tc_out);

    out = to_hex_repr(tc_out, MD5_SIZE);
    return out;
}
