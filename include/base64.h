
#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>
#include <string.h>

int base64_encode(char *, size_t, char *, size_t);
size_t base64_decode(char *, char *, size_t);

#endif
