#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "../proctrace.h"

int pid;


void print_signal() {
	siginfo_t sig;
	proctrace(PTRACE_GETSIGINFO, pid, NULL, &sig);
	printf("I quit because of the signal %d\n", sig.si_signo);
}

int main(int argc, char *argv[]) {
	if (argc != 2) return 0;

	sscanf(argv[1], "%d", &pid);

	printf("attaching\n");
	proctrace(PTRACE_ATTACH, pid, NULL, NULL);
	printf("waiting for child to stop\n");
	proctrace_wait();
	print_signal();
	printf("waited. child should be stopped\n");
	proctrace(PTRACE_SYSCALL, pid, NULL, NULL);
	proctrace(PTRACE_CONT, pid, NULL, NULL);
	printf("waiting for the system call\n");
	proctrace_wait();
	print_signal();
	printf("child did it's thing. continuing and waiting for child to quit...\n");
	proctrace(PTRACE_CONT, pid, NULL, NULL);
	proctrace_wait();

	return 0;
}
