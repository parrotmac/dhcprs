FROM ubuntu:jammy

RUN apt-get update && apt-get install -y \
  iproute2 vim lsof strace tcpdump iputils-ping netcat bridge-utils

WORKDIR /opt

COPY setup.sh /opt/

CMD ["/opt/setup.sh"]
