#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>

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
 */

unsigned long long proctrace_wait_mask = 0;
int singlestep = 0;
pid_t attached_pid = 0;

void setoptions(int data) {
	switch (data) {
	case PTRACE_O_TRACEFORK:
		proctrace_wait_mask |= (1 << 34);
		break;
	case PTRACE_O_TRACEVFORK:
		proctrace_wait_mask |= (1 << 35);
		break;
	case PTRACE_O_TRACECLONE:
		proctrace_wait_mask |= (1 << 36);
		break;
	case PTRACE_O_TRACEEXEC:
		proctrace_wait_mask |= (1 << 37);
		break;
	case PTRACE_O_TRACEVFORKDONE:
		proctrace_wait_mask |= (1 << 38);
		break;
	case PTRACE_O_TRACEEXIT:
		proctrace_wait_mask |= (1 << 39);
	}
}

long proctrace(enum __ptrace_request __request, pid_t pid, void *addr, void *data) {
	long retval = 0;

	if (attached_pid != 0 && attached_pid != pid) {
		fprintf(stderr, "i can only trace one guy\n");
		exit(1);
	}

	switch (request) {
	case PTRACE_TRACEME:
		retval = traceme();
		break;
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		retval = readfile("mem", addr);
		break;
	case PTRACE_PEEKUSER:
		fprintf(stderr, "not supported yet\n");
		exit(1);
		break;
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		retval = writefile("mem", addr, data);
		break;
	case PTRACE_POKEUSER:
		fprintf(stderr, "not supported yet\n");
		exit(1);
		break;
	case PTRACE_CONT:
		if (data) 
			retval = kill(attached_pid, data);
		if (!retval)
			retval = ctl("start");
		break;
	case PTRACE_KILL:
		retval = kill(attached_pid, SIGKILL);
		break;
	case PTRACE_SINGLESTEP:
		singlestep = 0;
		retval = 0;
		break;
	case PTRACE_GETREGS:
		fprintf(stderr, "not supported yet\n");
		/* Read all the bytes from "regs"; same as calling ptrace with
		 * GETREGS */
		exit(1);
		break;
	case PTRACE_SETREGS:
		fprintf(stderr, "not supported yet\n");
		/* Same as GETREGS except use write to write the entire struct
		 * to the file */
		exit(1);
		break;
	case PTRACE_GETFPREGS:
		fprintf(stderr, "not supported yet\n");
		exit(1);
		break;
	case PTRACE_SETFPREGS:
		fprintf(stderr, "not supported yet\n");
		exit(1);
		break;
	case PTRACE_ATTACH:
		attached_pid = pid;
		proctrace_wait_mask = ((1ULL << 31) - 1) << 1;
		break;
	case PTRACE_DETACH:
		attached_pid = proctrace_wait_mask = singlestep = 0;
		break;
	case PTRACE_SYSCALL:
		proctrace_wait_mask |= (1 << 33);
		break;
	case PTRACE_SETOPTIONS:
		setoptions((int) data);
		break;
	case PTRACE_GETEVENTMSG:
	case PTRACE_GETSIGINFO:
	case PTRACE_SETSIGINFO:
	}

	return retval;
}

