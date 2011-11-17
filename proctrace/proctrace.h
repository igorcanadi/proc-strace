#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/user.h>

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
 */

unsigned long long proctrace_wait_mask = 0;
int singlestep = 0;
pid_t attached_pid = 0;

static void setoptions(int data) {
	switch (data) {
	case PTRACE_O_TRACEFORK:
		proctrace_wait_mask |= (1ULL << 34);
		break;
	case PTRACE_O_TRACEVFORK:
		proctrace_wait_mask |= (1ULL << 35);
		break;
	case PTRACE_O_TRACECLONE:
		proctrace_wait_mask |= (1ULL << 36);
		break;
	case PTRACE_O_TRACEEXEC:
		proctrace_wait_mask |= (1ULL << 37);
		break;
	case PTRACE_O_TRACEVFORKDONE:
		proctrace_wait_mask |= (1ULL << 38);
		break;
	case PTRACE_O_TRACEEXIT:
		proctrace_wait_mask |= (1ULL << 39);
	}
}

// read a word from a file on address addr and return it
static long readfile(const char *filename, long addr) {
	char buf[35];
	sprintf(buf, "/proc/%d/%s", attached_pid, filename);

	int fd = open(buf, O_RDONLY);
	lseek(fd, addr, SEEK_SET);
	long retvalue;
	if (read(fd, &retvalue, sizeof(retvalue)) < 0) {
		printf("read failed\n");
		exit(1);
	}
	close(fd);

	return retvalue;
}

// put data to address addr in filename
static long writefile(const char *filename, long addr, long data) {
	char buf[35];
	sprintf(buf, "/proc/%d/%s", attached_pid, filename);

	int fd = open(buf, O_WRONLY);
	lseek(fd, addr, SEEK_SET);
	long retvalue;
	if (write(fd, &data, sizeof(data)) < 0) {
		printf("write failed\n");
		exit(1);
	}
	close(fd);

	return retvalue;
}

static long copyfromfile(const char *filename, char* buf, int size) {
	char filenamebuf[35];
	sprintf(filenamebuf, "/proc/%d/%s", attached_pid, filename);

	int fd = open(filenamebuf, O_RDONLY);
	long retvalue;
	retvalue = write(fd, buf, size);
	close(fd);

	return retvalue;
}

static int traceme() {
	sleep(100000);
	return 0;
}

static int ctl(const char *command) {
	char buf[35];
	sprintf(buf, "/proc/%d/ctl", attached_pid);

	int fd = open(buf, O_WRONLY);
	long retvalue;
	retvalue = write(fd, command, strlen(command));
	close(fd);

	return retvalue;
}

// substitute for wait4() system call
long proctrace_wait() {
	long retval;
	if (singlestep) {
		retval = ctl("step");
		singlestep = 0;
	} else {
		char buf[35];
		sprintf(buf, "/proc/%d/wait", attached_pid);

		int fd = open(buf, O_WRONLY);
		long retvalue;
		retvalue = write(fd, &proctrace_wait_mask, 
				sizeof(proctrace_wait_mask));
		close(fd);
	}

	return retval;
}

long proctrace(enum __ptrace_request __request, pid_t pid, void *addr, void *data) {
	long retval = 0;

	if (attached_pid != 0 && attached_pid != pid) {
		fprintf(stderr, "i can only trace one guy\n");
		exit(1);
	}

	switch (__request) {
	case PTRACE_TRACEME:
		retval = traceme();
		break;
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		retval = readfile("mem", (long)addr);
		break;
	case PTRACE_PEEKUSER:
		// TODO
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		retval = ptrace(PTRACE_PEEKUSER, pid, addr, data);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		retval = writefile("mem", (long) addr, (long) data);
		break;
	case PTRACE_POKEUSER:
		// TODO
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		retval = ptrace(PTRACE_POKEUSER, pid, addr, data);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		break;
	case PTRACE_CONT:
		if (data) 
			retval = kill(attached_pid, (int) data);
		if (!retval)
			retval = ctl("start");
		break;
	case PTRACE_KILL:
		retval = kill(attached_pid, SIGKILL);
		break;
	case PTRACE_SINGLESTEP:
		singlestep = 1;
		retval = 0;
		break;
	case PTRACE_GETREGS:
		// TODO
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		retval = ptrace(PTRACE_GETREGS, pid, addr, data);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		/* Read all the bytes from "regs"; same as calling ptrace with
		 * GETREGS */
		break;
	case PTRACE_SETREGS:
		// TODO
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		retval = ptrace(PTRACE_SETREGS, pid, addr, data);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		/* Same as GETREGS except use write to write the entire struct
		 * to the file */
		break;
	case PTRACE_GETFPREGS:
		// TODO
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		retval = ptrace(PTRACE_GETFPREGS, pid, addr, data);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		break;
	case PTRACE_SETFPREGS:
		// TODO
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		retval = ptrace(PTRACE_SETFPREGS, pid, addr, data);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		break;
	case PTRACE_ATTACH:
		attached_pid = pid;
		proctrace_wait_mask = ((1ULL << 31) - 1) << 1;
		break;
	case PTRACE_DETACH:
		attached_pid = proctrace_wait_mask = singlestep = 0;
		break;
	case PTRACE_SYSCALL:
		proctrace_wait_mask |= (1ULL << 33);
		break;
	case PTRACE_SETOPTIONS:
		setoptions((int) data);
		break;
	case PTRACE_GETEVENTMSG:
		copyfromfile("evetmessage", (char *) data, REGSSIZE);
		break;
	case PTRACE_GETSIGINFO:
		copyfromfile("last_siginfo", (char *) data, REGSSIZE);
		break;
	case PTRACE_SETSIGINFO:
		fprintf(stderr, "not supported yet\n");
		exit(1);
		break;
	}

	return retval;
}

