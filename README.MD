To build `docker-compose up --build`


## Options:
* `-a` reset PR_SET_DUMPABLE in signal handler
* `-n` set PR_SET_DUMPABLE
* `-r` reset PR_SET_DUMPABLE in main
* `-s` enable seccomp
* `-t` try to create tcp socket


### Happy patch:
`docker-compose run --rm sandbox -asn`

### Unhappy:
`docker-compose run --rm sandbox -asnt`
