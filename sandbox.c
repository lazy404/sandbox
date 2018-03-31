#include <stdio.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <seccomp.h>


int setseccomp() {
     scmp_filter_ctx ctx;
     int rc;
     
     ctx = seccomp_init(SCMP_ACT_ALLOW);

     // only allow PR_SET_DUMPABLE reset
     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 1, SCMP_A0(SCMP_CMP_NE, PR_SET_DUMPABLE))) < 0)
         goto out;

     // this is already blocked by setting PR_SET_DUMPABLE but block just in case
     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0)) < 0)
         goto out;

     // this is already blocked by setting PR_SET_DUMPABLE but block just in case
     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0)) < 0)
         goto out;

     // this is already blocked by setting PR_SET_DUMPABLE but block just in case
     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0)) < 0)
         goto out;

     // block all non local socket creation
     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_NE, AF_LOCAL))) < 0)
         goto out;


     rc = seccomp_load(ctx);

out:
     seccomp_release(ctx);
     return rc;
}

void handle_signal(int signal) {
    printf("handle_signal(), got signal %d\n", signal);
    
    printf("resetting PR_SET_DUMPABLE, prctl(PR_SET_DUMPABLE, 1) = %d\n", prctl(PR_SET_DUMPABLE, 1));

    abort();
}

int main(int argc, char* argv[]) {
    int* oops = NULL;
    int nodump=0, redump=0, seccomp=0, tcp=0, set_signal=0;
    char c;
    
    while((c = getopt(argc, argv, "anrst")) != -1)
        switch(c) {
            case 'n':
                nodump=1;
                break;
            case 't':
                tcp=1;
                break;
            case 'r':
                redump=1;
                break;
            case 's':
                seccomp=1;
                break;
            case 'a':
                set_signal=1;
                break;
            default:
                printf("Usage:\n%s -a reset PR_SET_DUMPABLE in signal handler -n set PR_SET_DUMPABLE, -r reset PR_SET_DUMPABLE -s seccomp -t try tcp socket\n", argv[0]);
                exit(1);
        }

    struct rlimit core_limit;
    core_limit.rlim_cur = RLIM_INFINITY;
    core_limit.rlim_max = RLIM_INFINITY;

    if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
        perror("setrlimit failed");

    printf("getpid() = %d\n", getpid());

    if(nodump)
        printf("prctl(PR_SET_DUMPABLE, 0) = %d\n", prctl(PR_SET_DUMPABLE, 0));

    printf("prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = %d\n", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

    system("sudo localhost");


    struct sigaction sa;

    if(set_signal) {

        sa.sa_handler = &handle_signal;

        // Restart the system call, if at all possible
        sa.sa_flags = SA_RESTART;

        // Block every signal during the handler
        sigfillset(&sa.sa_mask);

        if (sigaction(SIGSEGV, &sa, NULL) == -1) {
            perror("Error: cannot handle SIGSEGV");
        }
    }


    if(seccomp)
        printf("setseccomp() = %d\n", setseccomp());


    printf("socket(AF_UNIX, SOCK_STREAM, 0) = %d\n", socket(AF_UNIX, SOCK_STREAM, 0));

    if(tcp)
        printf("socket(AF_INET, SOCK_STREAM, 0) = %d\n", socket(AF_INET, SOCK_STREAM, 0));

    if(redump)
        printf("prctl(PR_SET_DUMPABLE, 1) = %d\n", prctl(PR_SET_DUMPABLE, 1));

    printf("\npress enter for segfault\n");

    getchar();
    *oops=42;
}