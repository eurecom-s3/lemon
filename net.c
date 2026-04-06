#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "lemon.h"

/*
 * net.c - TCP client dump path: connect to ctx->opts.address:port and stream dump().
 */

extern int dump(const struct lemon_ctx *restrict ctx, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args);

/* File descriptor wrapper for write_on_socket() / dump(). */
struct net_args {
    int sockfd;
};

/*
 * write_on_socket() - write(2) loop over a connected TCP socket
 * @args: Pointer to struct net_args (sockfd).
 * @data: Payload or NULL for zero-filled malloc buffer of @size bytes.
 * @size: Bytes to send.
 *
 * Returns 0 on success, or errno on failure.
 */
static int write_on_socket(void *restrict args, const void *restrict data, const unsigned long size) {
    ssize_t r;
    unsigned long total;
    struct net_args *net_args = (struct net_args *)args;
    void *dummy_buffer = NULL;
    int ret = 0;

    /* NULL data means the eBPF read was skipped or failed: send zeros instead. */
    if(data == NULL && size > 0) {
        dummy_buffer = malloc(size);
        if(dummy_buffer == NULL) {
            RETURN_ERRNO("Fail to allocate dummy buffer");
        }
        memset(dummy_buffer, 0x00, size);
        data = dummy_buffer;
    }

    total = r = 0;
    while(total < size) {
        r = write(net_args->sockfd, data + total, size - total);
        if(r == -1) {
            if(errno == EINTR) continue;
            ret = errno;
            ERRNO("Fail to write on socket");
            goto cleanup;
        }
        
        total += r;
    }

    cleanup:
        if(dummy_buffer) free(dummy_buffer);

    return ret;
}

/*
 * dump_on_net() - socket + connect + dump(); close preserves first error
 * @ctx: Network mode options (address in network byte order, port).
 *
 * Returns 0 on success, or errno (always non-negative here) on failure.
 */
int dump_on_net(const struct lemon_ctx *restrict ctx) {
    int sockfd;
    struct sockaddr_in dest_addr;
    struct net_args net_args;
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        RETURN_ERRNO("Fail to open network socket");
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(ctx->opts.port);
    dest_addr.sin_addr.s_addr = ctx->opts.address; /* Already network byte order from inet_pton. */

    if ((ret = connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr))) < 0) {
        ret = errno;
        ERRNO("Fail to connect to remote host");
        close(sockfd);
        return ret;
    }

    net_args.sockfd = sockfd;
    ret = dump(ctx, write_on_socket, (void *)&net_args);

    if(sockfd >= 0) {
        if(close(sockfd)) { if (!ret) ret = errno; ERRNO("Fail to close the connection"); }
    }
    
    return ret;
}
