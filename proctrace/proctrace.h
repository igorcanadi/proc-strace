#ifndef _PROCTRACE_H
#define _PROCTRACE_H

#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/user.h>
#include <errno.h>
#include <signal.h>

#define REGSSIZE sizeof(struct user_regs_struct)

/**
 * There are a lot of semantical differences between real ptrace
 * and emulated ptrace through /proc file system. It should work
 * on simple use cases, but may fail on advanced.
 *
 * Some of the differences are:
 * 1) proctrace starts tracing only on wait. It does not capture
 *    events that happen between registering (attach, setoptions...)
 *    and wait(). Assuming child is stopped in that period, this should
 *    not be a problem.
 * 2) proctrace can only trace one process at a time.
 * 3) proctrace does not send signals to the tracer at all.
 * 4) There are some differences between ptrace and proctrace in
 *    signal numbers for different events (fork, vfork, exec...)
 * 5) Wait doesn't wait for any stop of the child. It waits for
 *    stops because of interesting events (signal delievery, etc.)
 */

long proctrace(enum __ptrace_request __request, pid_t pid, void *addr, void *data);

// substitute for wait4() system call
pid_t proctrace_wait(pid_t pid, int *status, int options, struct rusage *rusage);

#endif
