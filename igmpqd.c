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

#include <errno.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

#include <libnet.h>

#include "daemon.h"

#define VERSION "0.1.0"

typedef struct igmpqd_options {
    int           debug;
    int           daemonize;
    int           help;
    int           version;
    long          interval;
    char         *interface;
    char         *username;
    uid_t         uid;
    char         *groupname;
    gid_t         gid;
    uint32_t      mgroup;
} igmpqd_options_t;

void
usage(char *command)
{
    printf("usage: %s [-dfhv] [-m MGROUP] [-u USER] [-g GROUP] [-i INTERFACE] [-s INTERVAL]\n",
        command);
}

int
parse_command_line(int argc, char **argv, igmpqd_options_t *options)
{
    char *endptr = NULL;
    struct passwd *passwd = NULL;
    struct group *group = NULL;
    uint32_t network;
    int c;

    while ((c = getopt(argc, argv, "dfg:hi:m:s:u:v")) != -1) {
        switch (c) {
        case 'd':
            options->debug = 1;
            break;

        case 'f':
            options->daemonize = 0;
            break;

        case 'g':
            errno = 0;
            options->groupname = optarg;
            group = getgrnam(optarg);
            if (group == NULL) {
                if (errno) {
                    fprintf(stderr, "Error: Could not get GID for group '%s': %s\n", optarg, strerror(errno));
                } else {
                    fprintf(stderr, "Error: Can not drop privileges to nonexistent group '%s'\n", optarg);
                }
                return -1;
            }
            options->gid = group->gr_gid;
            break;

        case 'h':
            options->help = 1;
            break;

        case 'i':
            options->interface = optarg;
            break;

        case 'm':
            options->mgroup = libnet_name2addr4(NULL, optarg, LIBNET_DONT_RESOLVE);
            network = libnet_name2addr4(NULL, "224.0.0.0", LIBNET_DONT_RESOLVE);
            if (options->mgroup == -1 || network == -1 || (options->mgroup & network) != network) {
                fprintf(stderr, "Error: Invalid multicast group '%s'\n", optarg);
                return -1;
            }
            break;

        case 's':
            errno = 0;
            options->interval = strtol(optarg, &endptr, 10);
            if (*endptr != '\0' || options->interval <= 0 ||
                (errno == ERANGE && (options->interval == LONG_MAX || options->interval == LONG_MIN)) ||
                (errno != 0 && options->interval == 0)) {
                fprintf(stderr, "Error: Invalid interval '%s'\n", optarg);
                return -1;
            }
            break;

        case 'u':
            errno = 0;
            options->username = optarg;
            passwd = getpwnam(optarg);
            if (passwd == NULL) {
                if (errno) {
                    fprintf(stderr, "Error: Could not get GID for user '%s': %s\n", optarg, strerror(errno));
                } else {
                    fprintf(stderr, "Error: Can not drop privileges to nonexistent user '%s'\n", optarg);
                }
                return -1;
            }
            options->uid = passwd->pw_uid;
            break;

        case 'v':
            options->version = 1;
            break;

        default:
            usage(argv[0]);
            return -1;
            break;
        }
    }

    /* Ensure no extra command line parameters were given */
    if (argc != optind) {
        usage(argv[0]);
        return -1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    char *dst_mgroup = "224.0.0.1";
    char *dst_mac = "01:00:5e:00:00:01";

    igmpqd_options_t *options;
    libnet_t *l = NULL;
    libnet_ptag_t igmp, ipv4, ethernet;
    uint32_t src_ipv4, dst_ipv4;
    uint8_t *dst_ether;
    int len;
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* Parse command line options */
    options = malloc(sizeof(igmpqd_options_t));
    if (options == NULL) {
        fprintf(stderr, "Error: Could not allocate memory for options: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(options, 0, sizeof(options));
    options->interval = 60; /* seconds */
    options->daemonize = 1;
    if (parse_command_line(argc, argv, options) != 0) {
        exit(EXIT_FAILURE);
    }

    /* Check for special options */
    if (options->help) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }
    if (options->version) {
        printf("%s\n", VERSION);
        exit(EXIT_SUCCESS);
    }

    /* Initialize libnet */
    l = libnet_init(LIBNET_LINK, options->interface, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error: Could not initialize libnet: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (options->debug) {
        printf("Using interface '%s'\n", libnet_getdevice(l));
    }

    /* Drop privileges */
    if (drop_privileges(options->username, options->uid,
            options->groupname, options->gid) != 0) {
        goto fail;
    }

    /* Build IGMP membership query (layer 4) */
    igmp = libnet_build_igmp(IGMP_MEMBERSHIP_QUERY, 0, 0, options->mgroup, NULL, 0, l, 0);
    if (igmp == -1) {
        fprintf(stderr, "Error: Could not build IGMP packet: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Source IP address */
    src_ipv4 = libnet_get_ipaddr4(l);
    if (src_ipv4 == -1) {
        fprintf(stderr, "Error: Could not get source IPv4 address: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Resolve destination multicast group (All Hosts) */
    dst_ipv4 = libnet_name2addr4(l, dst_mgroup, LIBNET_DONT_RESOLVE);
    if (dst_ipv4 == -1) {
        fprintf(stderr, "Error: Could not resolve multicast group (%s)\n", dst_mgroup);
        goto fail;
    }

    /* Build IPv4 header (layer 3) */
    ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_IGMP_H,
        0, 0, 0, 1, IPPROTO_IGMP, 0, src_ipv4, dst_ipv4, NULL, 0, l, 0);
    if (ipv4 == -1) {
        fprintf(stderr, "Error: Could not build IPv4 header: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Destination MAC address */
    dst_ether = libnet_hex_aton(dst_mac, &len);
    if (dst_ether == NULL) {
        fprintf(stderr, "Error: Could not construct destination MAC address (%s)\n", dst_mac);
        goto fail;
    }

    /* Build ethernet header (layer 2) */
    ethernet = libnet_autobuild_ethernet(dst_ether, ETHERTYPE_IP, l);
    if (ethernet == -1) {
        fprintf(stderr, "Error: Could not build ethernet header: %s\n", libnet_geterror(l));
        goto fail;
    }
    free(dst_ether);

    /* Daemonize */
    if (options->daemonize) {
        if (daemonize(options->debug) != 0) {
            goto fail;
        }
    }

    /* Transmit loop */
    while (1) {
        if (options->debug) {
            libnet_diag_dump_pblock(l);
        }
        if (libnet_write(l) == -1) {
            fprintf(stderr, "Error: Could not transmit IGMP packet: %s", libnet_geterror(l));
            /* TODO: Just log and carry on here? */
            goto fail;
        }

        sleep(options->interval);
    }

    free(options);
    libnet_destroy(l);
    exit(EXIT_SUCCESS);

fail:
    free(options);
    libnet_destroy(l);
    exit(EXIT_FAILURE);
}
