#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
	long long i;
	printf("%d\n", getpid());

	for (i = 0; ; ++i) {
		if (i % 100000000 == 0) {
			printf("%lld\n", i);
		}
	}

	return 0;
}
