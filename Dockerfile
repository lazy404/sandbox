FROM amazonlinux

RUN yum update && yum install -y gcc make strace psutils shadow-utils procps
RUN yum install -y psmisc libseccomp libseccomp-devel sudo
WORKDIR /code
ADD . /code
RUN make
RUN adduser test
USER test
ENTRYPOINT ["/code/init.sh"]
CMD [-nsa]