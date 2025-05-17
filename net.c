#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <aio.h>

#include "lemon.h"

extern int dump(const struct options *restrict opts, const struct ram_regions *restrict ram_regions, int (*write_f)(void *restrict, void *restrict, const unsigned long), void *restrict args);

/* Arguments passed to write_on_socket() */
struct net_args {
    bool async;
    bool udp;
    int sockfd;
    struct aiocb aio_cb;
};

/*
 * write_on_socket() - Sends data over a TCP socket.
 * @args: pointer to an integer file descriptor (the socket)
 * @data: pointer to the buffer to send
 * @size: number of bytes to send
 *
 * Returns 0 on success.
 */

int write_on_socket(void *restrict args, void *restrict data, const unsigned long size) {
    unsigned long r;
    unsigned long total;
    struct net_args *net_args = (struct net_args *)args;
     struct aiocb *aiocb = &net_args->aio_cb;

        total = r = 0;
        while(total < size) {
            /* If realtime use async writes */
            if(net_args->async) {
                (*aiocb).aio_buf = data + total;
                (*aiocb).aio_nbytes = size - total;
                
                if(aio_write(aiocb) < 0) {
                    perror("Fail in aio_write");
                    return errno;
                }

                /* Steal CPU time while waiting for writing completation */
                while(aio_error(aiocb) == EINPROGRESS) {}

                /* Get total number of written data */
                r = aio_return(aiocb);
                if(r < 0) {
                    perror("Fail in aio_write (after write completation)");
                    return errno;
                }
            }
            else {
                r = write(net_args->sockfd, data + total, size - total);
                if(r == -1) {
                    if(errno == EINTR) continue;
                    perror("Fail to write on socket");
                    return errno;
                }
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
    net_args.async = opts->realtime;
    net_args.sockfd = sockfd;
    net_args.udp = opts->udp;
    memset(&(net_args.aio_cb), 0, sizeof(struct aiocb));

    /* If in realtime mode, use async write */
    if(opts->realtime) { net_args.aio_cb.aio_fildes = sockfd; }

    /* Dump! */
    ret = dump(opts, ram_regions, write_on_socket, (void *)&net_args);

    if(sockfd) {
        if(close(sockfd)) { perror("Fail to close the connection"); ret = errno; }
    }
    
    return ret;
}

    