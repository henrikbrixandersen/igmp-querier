/**
 * Copyright (c) 2013, Henrik Brix Andersen <henrik@brixandersen.dk>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <unistd.h>

#include <libnet.h>

#define VERSION "0.1.0"

void usage()
{
    printf("USAGE: igmp-querier [-dhv]\n");
}

int
main(int argc, char **argv)
{
    int c, debug;
    libnet_t *l = NULL;
    libnet_ptag_t igmp, ipv4;
    uint32_t mgroup, mgroup_all_hosts;
    char errbuf[LIBNET_ERRBUF_SIZE];

    while ((c = getopt(argc, argv, "dhv")) != -1) {
        switch (c) {
        case 'd':
            debug = 1;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);
            break;

        case 'v':
            printf("%s\n", VERSION);
            exit(EXIT_SUCCESS);
            break;

        default:
            usage();
            exit(EXIT_FAILURE);
            break;
        }
    }

    /* Initialize libnet */
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Could not initialize libnet: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Resolve multicast group (General Query) */
    mgroup = libnet_name2addr4(l, "0.0.0.0", LIBNET_DONT_RESOLVE);
    if (mgroup == -1) {
        fprintf(stderr, "Could not resolve multicast group 0.0.0.0: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Build IGMP membership query (layer 4) */
    igmp = libnet_build_igmp(IGMP_MEMBERSHIP_QUERY,
        0, 0, mgroup, NULL, 0, l, 0);
    if (igmp == -1) {
        fprintf(stderr, "Could not build IGMP packet: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Resolve multicast group (All Hosts) */
    mgroup_all_hosts = libnet_name2addr4(l, "224.0.0.1", LIBNET_DONT_RESOLVE);
    if (mgroup_all_hosts == -1) {
        fprintf(stderr, "Could not resolve multicast group 224.0.0.1: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Build IPv4 header (layer 3) */
    ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_IGMP_H,
        0, 0, 0, 1, IPPROTO_IGMP, 0, (uint32_t)0, mgroup_all_hosts, NULL, 0, l, 0);
    if (ipv4 == -1) {
        fprintf(stderr, "Could not build IPv4 header: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Transmit */
    if (debug) {
        libnet_diag_dump_pblock(l);
    }
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Could not transmit IGMP packet: %s", libnet_geterror(l));
        goto fail;
    }

    libnet_destroy(l);
    exit(EXIT_SUCCESS);
fail:
    libnet_destroy(l);
    exit(EXIT_FAILURE);
}
