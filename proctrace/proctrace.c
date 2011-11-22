#include "proctrace.h"

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
	retvalue = read(fd, buf, size);
	close(fd);

	return retvalue;
}

static int traceme() {
	// may not work!
	kill(getpid(), SIGSTOP);
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
pid_t proctrace_wait(pid_t pid, int *status, int options, struct rusage *rusage) {
	return wait4(pid, status, options, rusage);

	pid_t retval;
	if (singlestep) {
		retval = ctl("step");
		singlestep = 0;
	} else {
		char buf[35];
		sprintf(buf, "/proc/%d/wait", attached_pid);
		printf("%s\n", buf);

		int fd = open(buf, O_WRONLY);
		long retvalue;
		proctrace_wait_mask |= (1ULL << 40);
		printf("waiting on: %llX\n", proctrace_wait_mask);
		unsigned long long big_endian = 0;
		int i;
		for (i = 0; i < 8; ++i) {
			big_endian |= ((proctrace_wait_mask >> (8*i)) & ((1 << 8)-1)) << (8-i-1)*8;
		}

		retvalue = write(fd, &big_endian, sizeof(big_endian));
		if (retval < 0) {
			printf("write to wait failed\n");
		}
		close(fd);
	}

	siginfo_t a;
	if (proctrace(PTRACE_GETSIGINFO, attached_pid, NULL, (void *)&a) == -1) {
		*status = 0;
	} else {
		*status = a.si_signo;
		printf("proctrace... got %d\n", a.si_signo);
	}


	proctrace_wait_mask = ((1ULL << 31) - 1) << 1;

	return retval;
}

long proctrace(enum __ptrace_request __request, pid_t pid, void *addr, void *data) {
	return ptrace(__request, pid, addr, data);

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
		break;
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
		// next time someboy calls proctrace_wait, start the child
		if (!retval)
			proctrace_wait_mask |= 1;
		break;
	case PTRACE_KILL:
		retval = kill(attached_pid, (int) data);
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
		kill(pid, SIGSTOP);
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
		copyfromfile("evetmessage", (char *) data, sizeof(unsigned long int));
		break;
	case PTRACE_GETSIGINFO:
		copyfromfile("last_siginfo", (char *) data, sizeof(siginfo_t));
		break;
	case PTRACE_SETSIGINFO:
		fprintf(stderr, "not supported yet\n");
		exit(1);
		break;
	}

	return retval;
}

