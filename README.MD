To build `docker-compose build`


## Options:
* `-a` reset PR_SET_DUMPABLE to 1 in signal handler
* `-n` set PR_SET_DUMPABLE to 0
* `-r` reset PR_SET_DUMPABLE to 1 in main
* `-s` enable seccomp
* `-t` try to create tcp socket


### Happy patch:
`docker-compose run --rm sandbox -asn`

### Unhappy:
`docker-compose run --rm sandbox -asnt`

What do we do:
* set PR_SET_DUMPABLE to 0, disables same user memory access, strace, disables coredumps
* set PR_SET_NO_NEW_PRIVS to 1, to prevent process gaining more priv ie. by execing suid binary
* set seccomp-bpf blacklist filter to deny PR_SET_NO_NEW_PRIVS changes, non AF_LOCAL socket creation, ptrace, vm access syscalls
* optionally set PR_SET_DUMPABLE to 1 in segfault handler to be able to produce coredumps, this may require some tweaks as it may allow some cross process memory access using coredumps, maybe using a custom script as a coredump file handler
* optionally we can block execveat and execve if seccomp will be set inside the process

