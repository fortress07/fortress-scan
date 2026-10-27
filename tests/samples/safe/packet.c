/* Bản viết đúng của vulnerable/packet.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX_IDS 1024

struct header {
    uint32_t count;
    char tag[16];
};

static int read_header(int sock, struct header *h)
{
    unsigned char raw[4];
    if (recv(sock, raw, sizeof raw, 0) != 4)
        return -1;
    h->count = ntohl(*(uint32_t *)raw);
    return 0;
}

int handle(int sock)
{
    struct header h;
    char name[32];
    if (read_header(sock, &h) < 0)
        return -1;
    if (h.count > MAX_IDS)
        return -1;
    uint32_t *ids = calloc(h.count, sizeof(uint32_t));
    if (!ids)
        return -1;
    ssize_t n = recv(sock, name, sizeof name - 1, 0);
    if (n <= 0) {
        free(ids);
        return -1;
    }
    name[n] = '\0';
    snprintf(h.tag, sizeof h.tag, "%s", name);
    printf("%s\n", name);
    free(ids);
    ids = NULL;
    return 0;
}
