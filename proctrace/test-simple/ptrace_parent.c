#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/reg.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int pid;

int main(int argc, char *argv[]) {
	if (argc != 2) return 0;

	sscanf(argv[1], "%d", &pid);

	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	wait4(-1, NULL, 0, NULL);
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait4(-1, NULL, 0, NULL);

	long sc = ptrace(PTRACE_PEEKUSER, pid, (void*) (4 * ORIG_EAX), NULL);
	printf("not minus 1: %ld\n", sc);

	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait4(-1, NULL, 0, NULL);

	return 0;
}
