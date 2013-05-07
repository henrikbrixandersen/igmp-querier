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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libnet.h>

#define VERSION "0.1.0"

void
usage(char *command)
{
    printf("usage: %s [-dfhv] [-m MGROUP] [-u USER] [-g GROUP] [-i INTERVAL]\n",
        command);
}

int
main(int argc, char **argv)
{
    int debug = 0, daemonize = 1;
    long interval = 60;

    char *endptr = NULL, *username = NULL, *groupname = NULL;
    struct passwd *passwd = NULL;
    struct group *group = NULL;
    uid_t uid;
    gid_t gid;

    libnet_t *l = NULL;
    libnet_ptag_t igmp, ipv4;
    uint32_t mgroup = 0, network, dst;
    char errbuf[LIBNET_ERRBUF_SIZE];

    pid_t pid;
    int c, i, exitstatus;

    while ((c = getopt(argc, argv, "dfg:hi:m:u:v")) != -1) {
        switch (c) {
        case 'd':
            debug = 1;
            break;

        case 'f':
            daemonize = 0;
            break;

        case 'g':
            errno = 0;
            groupname = optarg;
            group = getgrnam(groupname);
            if (group == NULL) {
                if (errno) {
                    fprintf(stderr, "Error: Could not get GID for group '%s': %s\n", groupname, strerror(errno));
                } else {
                    fprintf(stderr, "Error: Can not drop privileges to nonexistent group '%s'\n", groupname);
                }
                exit(EXIT_FAILURE);
            }
            gid = group->gr_gid;
            break;

        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;

        case 'i':
            errno = 0;
            interval = strtol(optarg, &endptr, 10);
            if (*endptr != '\0' || interval <= 0 ||
                (errno == ERANGE && (interval == LONG_MAX || interval == LONG_MIN)) ||
                (errno != 0 && interval == 0)) {
                fprintf(stderr, "Error: Invalid interval '%s'\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;

        case 'm':
            mgroup = libnet_name2addr4(l, optarg, LIBNET_DONT_RESOLVE);
            network = libnet_name2addr4(l, "224.0.0.0", LIBNET_DONT_RESOLVE);
            if (mgroup == -1 || network == -1 || (mgroup & network) != network) {
                fprintf(stderr, "Error: Invalid multicast group '%s'\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;

        case 'u':
            errno = 0;
            username = optarg;
            passwd = getpwnam(username);
            if (passwd == NULL) {
                if (errno) {
                    fprintf(stderr, "Error: Could not get GID for user '%s': %s\n", username, strerror(errno));
                } else {
                    fprintf(stderr, "Error: Can not drop privileges to nonexistent user '%s'\n", username);
                }
                exit(EXIT_FAILURE);
            }
            uid = passwd->pw_uid;
            break;

        case 'v':
            printf("%s\n", VERSION);
            exit(EXIT_SUCCESS);
            break;

        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }

    /* Ensure no extra command line parameters were given */
    if (argc != optind) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize libnet */
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error: Could not initialize libnet: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Drop privileges */
    if (groupname != NULL) {
        if (setgid(gid) != 0) {
            fprintf(stderr, "Error: Could not drop privileges to group '%s' (GID %d): %s\n",
                groupname, gid, strerror(errno));
            goto fail;
        }
    }
    if (username != NULL) {
        if (setuid(uid) != 0) {
            fprintf(stderr, "Error: Could not drop priveleges to user '%s' (UID %d): %s\n",
                username, uid, strerror(errno));
            goto fail;
        }
    }

    /* Build IGMP membership query (layer 4) */
    igmp = libnet_build_igmp(IGMP_MEMBERSHIP_QUERY, 0, 0, mgroup, NULL, 0, l, 0);
    if (igmp == -1) {
        fprintf(stderr, "Error: Could not build IGMP packet: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Resolve destination multicast group (All Hosts) */
    dst = libnet_name2addr4(l, "224.0.0.1", LIBNET_DONT_RESOLVE);
    if (dst == -1) {
        fprintf(stderr, "Error: Could not resolve multicast group 224.0.0.1\n");
        goto fail;
    }

    /* Build IPv4 header (layer 3) */
    ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_IGMP_H,
        0, 0, 0, 1, IPPROTO_IGMP, 0, (uint32_t)0, dst, NULL, 0, l, 0);
    if (ipv4 == -1) {
        fprintf(stderr, "Error: Could not build IPv4 header: %s\n", libnet_geterror(l));
        goto fail;
    }

    /* Daemonize */
    if (daemonize) {
        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "Error: Could not create child process: %s\n", strerror(errno));
            goto fail;
        } else if (pid > 0) {
            if (debug) {
                printf("Waiting for child process with PID %d to exit...\n", pid);
            }
            if (waitpid(pid, &exitstatus, 0) == pid) {
                if (exitstatus == EXIT_SUCCESS) {
                    /* TODO: wait for grandchild */
                    _exit(EXIT_SUCCESS);
                } else {
                    fprintf(stderr, "Error: Child process failed\n");
                    goto fail;
                }
            } else {
                fprintf(stderr, "Error: Could not wait for child process with PID %d: %s\n", pid, strerror(errno));
                goto fail;
            }
        }

        if (setsid() < 0) {
            fprintf(stderr, "Error: Could not create new session: %s\n", strerror(errno));
            goto fail;
        }

        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "Error: Could not create grandchild process: %s", strerror(errno));
            goto fail;
        } else if (pid > 0) {
            if (debug) {
                printf("Created grandchild process with PID %d\n", pid);
            }
            exit(EXIT_SUCCESS);
        }

        if (chdir("/") != 0) {
            fprintf(stderr, "Error: Could not change directory to '/': %s\n", strerror(errno));
            goto fail;
        }

        umask(027);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        i = open("/dev/null", O_RDWR);
        dup(i);
        dup(i);
    }

    while (1) {
        /* Transmit */
        if (debug) {
            libnet_diag_dump_pblock(l);
        }
        if (libnet_write(l) == -1) {
            fprintf(stderr, "Error: Could not transmit IGMP packet: %s", libnet_geterror(l));
            /* TODO: Just log and carry on here? */
            goto fail;
        }

        sleep(interval);
    }

    libnet_destroy(l);
    exit(EXIT_SUCCESS);

fail:
    libnet_destroy(l);
    exit(EXIT_FAILURE);
}
