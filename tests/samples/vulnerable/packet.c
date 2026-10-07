/* Máy chủ nhận gói tin: mẫu lỗi bộ nhớ và chèn lệnh, KHÔNG dùng trong sản phẩm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
    char cmd[64];
    if (read_header(sock, &h) < 0)
        return -1;
    uint32_t *ids = malloc(h.count * sizeof(uint32_t));
    if (!ids)
        return -1;
    recv(sock, name, sizeof name, 0);
    strcpy(h.tag, name);
    printf(name);
    snprintf(cmd, sizeof cmd, "logger %s", name);
    system(cmd);
    free(ids);
    if (h.count == 0)
        free(ids);
    return 0;
}
