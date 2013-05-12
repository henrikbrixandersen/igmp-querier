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

typedef enum daemon_error {
        DAEMON_ERROR_NONE,
        DAEMON_ERROR_PIDFILE_CREATE,
        DAEMON_ERROR_PIDFILE_LOCK,
        DAEMON_ERROR_CHDIR,
        DAEMON_ERROR_STDIN_CLOSE,
        DAEMON_ERROR_STDOUT_CLOSE,
        DAEMON_ERROR_STDERR_CLOSE,
        DAEMON_ERROR_STDIN_OPEN,
        DAEMON_ERROR_STDOUT_OPEN,
        DAEMON_ERROR_STDERR_OPEN,
} daemon_error_t;

typedef struct daemon_status {
    daemon_error_t error;
    pid_t          pid;
    int            errnum;
} daemon_status_t;

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
                fprintf(stderr, "Error: Nonexistent group '%s'\n", groupname);
            }
            return -1;
        }

        if (setgid(group->gr_gid) < 0) {
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
                fprintf(stderr, "Error: Nonexistent user '%s'\n", username);
            }
            return -1;
        }

        if (setuid(passwd->pw_uid) < 0) {
            fprintf(stderr, "Error: Could not drop privileges to user '%s' (UID %d): %s\n",
                username, passwd->pw_uid, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int
daemonize(char *pidfile)
{
    daemon_status_t status;
    int len, pidfd;
    pid_t pid;
    int exitstatus;
    int statusfds[2];

    if (pipe(statusfds) < 0) {
        perror("Error: Could not create status pipe");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("Error: Could not create child process");
        return -1;
    } else if (pid > 0) {
        close(statusfds[1]);
        if (waitpid(pid, &exitstatus, 0) == pid) {
            if (exitstatus == EXIT_SUCCESS) {
                do {
                    errno = 0;
                    len = read(statusfds[0], &status, sizeof(status));
                } while(len == -1 && errno == EINTR);
                close(statusfds[0]);

                if (len == 0) {
                    fprintf(stderr, "Error: Could not read daemon status, pipe broken\n");
                    return -1;
                } else if (len == -1) {
                    perror("Error: Could not read daemon status");
                    return -1;
                }

                switch (status.error) {
                case DAEMON_ERROR_NONE:
                    /* Successfully created grandchild, exit parent */
                    _exit(EXIT_SUCCESS);
                    break;

                case DAEMON_ERROR_PIDFILE_CREATE:
                    fprintf(stderr, "Error: Could not create pid file '%s': %s\n",
                        pidfile, strerror(status.errnum));
                    break;

                case DAEMON_ERROR_PIDFILE_LOCK:
                    fprintf(stderr, "Error: Could not lock pidfile '%s': %s\n",
                        pidfile, strerror(status.errnum));
                    break;

                case DAEMON_ERROR_CHDIR:
                    fprintf(stderr, "Error: Could not change directory to '/': %s\n",
                        strerror(status.errnum));
                    break;

                case DAEMON_ERROR_STDIN_CLOSE:
                    fprintf(stderr, "Error: Could not close standard input: %s\n",
                        strerror(status.errnum));
                    break;

                case DAEMON_ERROR_STDOUT_CLOSE:
                    fprintf(stderr, "Error: Could not close standard output: %s\n",
                        strerror(status.errnum));
                    break;

                case DAEMON_ERROR_STDERR_CLOSE:
                    fprintf(stderr, "Error: Could not close standard error: %s\n",
                        strerror(status.errnum));
                    break;

                case DAEMON_ERROR_STDIN_OPEN:
                    fprintf(stderr, "Error: Could not open '/dev/null' as standard input: %s\n",
                        strerror(status.errnum));
                    break;

                case DAEMON_ERROR_STDOUT_OPEN:
                    fprintf(stderr, "Error: Could not open '/dev/null' as standard output: %s\n",
                        strerror(status.errnum));
                    break;

                case DAEMON_ERROR_STDERR_OPEN:
                    fprintf(stderr, "Error: Could not open '/dev/null' as standard error: %s\n",
                        strerror(status.errnum));
                    break;

                default:
                    fprintf(stderr, "Error: Unknown error while launching daemon\n");
                    break;
                }

                return -1;
            } else {
                fprintf(stderr, "Error: Could not create a new process group and fork daemon\n");
                return -1;
            }
        } else {
            fprintf(stderr, "Error: Could not wait for child process with PID %d: %s\n",
                pid, strerror(errno));
            return -1;
        }
    }

    /* Child process starts here */

    if (setsid() < 0) {
        perror("Error: Could not create new session");
        /* Signal parent by exiting with failure */
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        perror("Error: Could not create grandchild process");
        /* Signal parent by exiting with failure */
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        /* Succesfully created grandchild, exit child */
        exit(EXIT_SUCCESS);
    }

    /* Grandchild process starts here */

    close(statusfds[0]);
    umask(0133);

    status.error = DAEMON_ERROR_NONE;
    status.pid = getpid();
    errno = 0;

    if (pidfile != NULL) {
        pidfd = open(pidfile, O_WRONLY|O_CREAT, 0644);
        if (pidfd < 0) {
            status.error = DAEMON_ERROR_PIDFILE_CREATE;
            goto out;
        }

        if (lockf(pidfd, F_TLOCK, 0) < 0) {
            status.error = DAEMON_ERROR_PIDFILE_LOCK;
            goto out;
        }

        dprintf(pidfd, "%d\n", getpid());
    }

    if (chdir("/") < 0) {
        status.error = DAEMON_ERROR_CHDIR;
        goto out;
    }

    if (close(STDIN_FILENO) < 0) {
        status.error = DAEMON_ERROR_STDIN_CLOSE;
        goto out;
    }

    if (close(STDOUT_FILENO) < 0) {
        status.error = DAEMON_ERROR_STDOUT_CLOSE;
        goto out;
    }

    if (close(STDERR_FILENO) < 0) {
        status.error = DAEMON_ERROR_STDERR_CLOSE;
        goto out;
    }

    if (open("/dev/null", O_RDONLY) < 0) {
        status.error = DAEMON_ERROR_STDIN_OPEN;
        goto out;
    }

    if (open("/dev/null", O_WRONLY) < 0) {
        status.error = DAEMON_ERROR_STDOUT_OPEN;
        goto out;
    }

    if (open("/dev/null", O_WRONLY) < 0) {
        status.error = DAEMON_ERROR_STDERR_OPEN;
        goto out;
    }

out:
    status.errnum = errno;
    write(statusfds[1], &status, sizeof(status));
    close(statusfds[1]);

    return (status.error == DAEMON_ERROR_NONE ? 0 : -1);
}
