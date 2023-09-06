FROM golang:alpine3.18 as builder

WORKDIR /app/

COPY go.mod go.sum main.go ./

RUN go build -o dhcprs-server .

FROM alpine:3.18

WORKDIR /opt

COPY --from=builder /app/dhcprs-server /opt/dhcprs-server
COPY config.yml /opt/config.yml

RUN touch /opt/leases.txt

CMD ["/opt/dhcprs-server"]
