#include <cstdio>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
	int t = 0;
	printf("%d\n", getpid());
	do {
		t++;
		printf("%d\n", t);
		kill(1, SIGCONT);
		sleep(1);
	} while(1);

	return 0;
}
