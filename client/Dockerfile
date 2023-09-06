FROM rust:latest as builder

WORKDIR /app/

COPY . ./

RUN cargo build --release

FROM ubuntu:jammy

RUN apt-get update && apt-get install -y \
    iproute2 vim lsof strace tcpdump iputils-ping netcat

COPY --from=builder /app/target/release/dhcprs_cli /opt/dhcprs-client

CMD ["/opt/dhcprs-client"]
