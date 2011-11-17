#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "../proctrace.h"

int main(int argc, char *argv[]) {
	if (argc != 2) return 0;

	int pid;
	sscanf(argv[1], "%d", &pid);

	printf("attaching\n");
	proctrace(PTRACE_ATTACH, pid, NULL, NULL);
	printf("waiting\n");
	proctrace_wait();
	printf("waited. child should be stopped\n");
	proctrace(PTRACE_SYSCALL, pid, NULL, NULL);
	proctrace(PTRACE_CONT, pid, NULL, NULL);
	printf("waiting again\n");
	proctrace_wait();
	printf("child did it's thing\n");

	return 0;
}
