#include <stdio.h>
#include <string.h>

void printhexDump(const char *buffer, size_t len)
{
    if (buffer == NULL || len <= 0)
    {
        return;
    }
    printf("0x%x: (len=%d)[", buffer, len);
    for (size_t i = 0; i < len; i++)
    {
        printf("%.2X ", (unsigned char)buffer[i]);
    }
    printf("]\n");
}

void main()
{
    char buffer[4];
    int a = 1;

    memcpy(buffer, &a, 4);
    printhexDump(buffer, 4);
}