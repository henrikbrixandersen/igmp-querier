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
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int
drop_privileges(char* username, char *groupname)
{
    struct passwd *passwd = NULL;
    struct group *group = NULL;

    if (groupname != NULL) {
        errno = 0;
        group = getgrnam(groupname);
        if (group == NULL) {
            if (errno) {
                fprintf(stderr, "Error: Could not get GID for group '%s': %s\n", groupname, strerror(errno));
            } else {
                fprintf(stderr, "Error: Can not drop privileges to nonexistent group '%s'\n", groupname);
            }
            return -1;
        }

        if (setgid(group->gr_gid) != 0) {
            fprintf(stderr, "Error: Could not drop privileges to group '%s' (GID %d): %s\n",
                groupname, group->gr_gid, strerror(errno));
            return -1;
        }
    }

    if (username != NULL) {
        errno = 0;
        passwd = getpwnam(username);
        if (passwd == NULL) {
            if (errno) {
                fprintf(stderr, "Error: Could not get GID for user '%s': %s\n", username, strerror(errno));
            } else {
                fprintf(stderr, "Error: Can not drop privileges to nonexistent user '%s'\n", username);
            }
            return -1;
        }

        if (setuid(passwd->pw_uid) != 0) {
            fprintf(stderr, "Error: Could not drop priveleges to user '%s' (UID %d): %s\n",
                username, passwd->pw_uid, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int
daemonize(int debug)
{
    pid_t pid;
    int exitstatus;

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Error: Could not create child process: %s\n", strerror(errno));
        return -1;
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
                return -1;
            }
        } else {
            fprintf(stderr, "Error: Could not wait for child process with PID %d: %s\n", pid, strerror(errno));
            return -1;
        }
    }

    if (setsid() < 0) {
        fprintf(stderr, "Error: Could not create new session: %s\n", strerror(errno));
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Error: Could not create grandchild process: %s", strerror(errno));
        return -1;
    } else if (pid > 0) {
        if (debug) {
            printf("Created grandchild process with PID %d\n", pid);
        }
        exit(EXIT_SUCCESS);
    }

    if (chdir("/") != 0) {
        fprintf(stderr, "Error: Could not change directory to '/': %s\n", strerror(errno));
        return -1;
    }

    umask(027);

    /* TODO: Handle errors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    return 0;
}
