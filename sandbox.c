#include <stdio.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <time.h>
#include <stdlib.h>

#include <seccomp.h> /* libseccomp */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int setseccomp() {
     scmp_filter_ctx ctx;
     int rc;
     
     ctx = seccomp_init(SCMP_ACT_ALLOW);


     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 0)) < 0)
         goto out;


     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0)) < 0)
         goto out;


     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0)) < 0)
         goto out;


     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0)) < 0)
         goto out;


     if((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_NE, AF_LOCAL))) < 0)
         goto out;


     rc = seccomp_load(ctx);

out:
     seccomp_release(ctx);
     return rc;
}

int main(int argc, char* argv[]) {
    int* oops = NULL;
    int nodump=0, redump=0, seccomp=0, tcp=0;
    char c;
    
    while((c = getopt(argc, argv, "nrst")) != -1)
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
            default:
                printf("Usage:\n%s -n set PR_SET_DUMPABLE, -r reset PR_SET_DUMPABLE -s seccomp -t try tcp socket\n", argv[0]);
                exit(1);
        }

    printf("getpid() = %d\n", getpid());
    
    if(nodump)
        printf("prctl(PR_SET_DUMPABLE, 0) = %d\n", prctl(PR_SET_DUMPABLE, 0));

    if(seccomp)
        printf("setseccomp() = %d\n", setseccomp());

    printf("socket(AF_UNIX, SOCK_STREAM, 0) = %d\n", socket(AF_UNIX, SOCK_STREAM, 0));

    if(tcp)
        printf("socket(AF_INET, SOCK_STREAM, 0) = %d\n", socket(AF_INET, SOCK_STREAM, 0));

    if(redump)
        printf("prctl(PR_SET_DUMPABLE, 1) = %d\n", prctl(PR_SET_DUMPABLE, 1));

    printf("press enter for segfault\n");

    getchar();
    *oops=42;
}