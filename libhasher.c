#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tomcrypt.h"

#define MD5_SIZE 16

char *md5_hash(char *str) 
{
    hash_state hs;
    int len = strlen(str);
    char *out;
    unsigned char *tc_out = malloc(MD5_SIZE * sizeof(unsigned char));

    md5_init(&hs);
    md5_process(&hs, str, len);
    md5_done(&hs, tc_out);

    out = tc_out;
    return out;
}
