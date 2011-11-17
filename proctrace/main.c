#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include "proctrace.h"

int main()
{   pid_t child;
    long orig_eax;
    child = fork();
    if(child == 0) {
        proctrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }
    else {
        wait(NULL);
        orig_eax = proctrace(PTRACE_PEEKUSER,
                          child, (void *) (4 * ORIG_EAX),
                          NULL);
        printf("The child made a "
               "system call %ld\n", orig_eax);
        proctrace(PTRACE_CONT, child, NULL, NULL);
    }
    return 0;
}
 
