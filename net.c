#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "lemon.h"

extern int dump(const struct options *restrict opts, const struct ram_regions *restrict ram_regions, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args);

/* Arguments passed to write_on_socket() */
struct net_args {
    bool udp;
    int sockfd;
};

/*
 * write_on_socket() - Sends data over a TCP socket.
 * @args: pointer to an integer file descriptor (the socket)
 * @data: pointer to the buffer to send
 * @size: number of bytes to send
 *
 * Returns 0 on success.
 */

int write_on_socket(void *restrict args, const void *restrict data, const unsigned long size) {
    unsigned long r;
    unsigned long total;
    struct net_args *net_args = (struct net_args *)args;

        total = r = 0;
        while(total < size) {
            r = write(net_args->sockfd, data + total, size - total);
            if(r == -1) {
                if(errno == EINTR) continue;
                perror("Fail to write on socket");
                return errno;
            }
            
            total += r;
        }

    return 0;
}

/*
 * dump_on_net() - Sends the memory dump over the network.
 * @opts: user-provided options, including destination address
 * @ram_regions: memory regions to dump
 *
 * On success, it returns 0. On failure, a negative value or errno is returned.
 */

int dump_on_net(const struct options *restrict opts, const struct ram_regions *restrict ram_regions) {
    int sockfd;
    struct sockaddr_in dest_addr;
    struct net_args net_args;
    int ret;

    /* Create socket */
    sockfd = socket(AF_INET, opts->udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Fail to open network socket");
        return errno;
    }

    /* Setup destination address */
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(opts->port);
    dest_addr.sin_addr.s_addr = opts->address;

    /* Connect to the destination */
    if ((ret = connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr))) < 0) {
        perror("Fail to connect to remote host");
        return errno;
    }

    /* Setup arguments for write_on_socket */
    net_args.sockfd = sockfd;
    net_args.udp = opts->udp;

    /* Dump! */
    ret = dump(opts, ram_regions, write_on_socket, (void *)&net_args);

    if(sockfd) {
        if(close(sockfd)) { perror("Fail to close the connection"); ret = errno; }
    }
    
    return ret;
}

    