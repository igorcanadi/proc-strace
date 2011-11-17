#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
	printf("%d\n", getpid());
	printf("start sleep\n");
	sleep(10);
	printf("end sleep\n");
	execl("/bin/ls", "ls", NULL);

	return 0;
}
