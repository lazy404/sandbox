FROM amazonlinux

RUN yum update && yum install -y gcc make strace psutils shadow-utils procps
RUN yum install -y psmisc libseccomp libseccomp-devel
WORKDIR /code
#RUN make sandbox
RUN adduser test
ENTRYPOINT /code/init.sh