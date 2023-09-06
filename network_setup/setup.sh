#!/usr/bin/env bash

CLIENT_CONTAINER_PID=${CLIENT_CONTAINER_PID}
SERVER_CONTAINER_PID=${SERVER_CONTAINER_PID}

set -euo pipefail

set -x

if [ -z "${CLIENT_CONTAINER_PID}" ]; then
  echo "CLIENT_CONTAINER_PID is not set"
  exit 1
fi

if [ -z "${SERVER_CONTAINER_PID}" ]; then
  echo "SERVER_CONTAINER_PID is not set"
  exit 1
fi

# Delete any existing network resources from previous runs
ip netns del client || true
ip netns del server || true
ip link del veth990 || true
ip link del veth991 || true
ip link del br999 || true

# Configure netns handles
mkdir -p /var/run/netns
ln -sfT /proc/${CLIENT_CONTAINER_PID}/ns/net /var/run/netns/client
ln -sfT /proc/${SERVER_CONTAINER_PID}/ns/net /var/run/netns/server

# Create a veth pair
ip link add dev veth990 type veth peer name veth991

brctl addbr br999
brctl addif br999 veth990
brctl addif br999 veth991

ip link set dev veth990 netns client
ip link set dev veth991 netns server

ip netns exec client ip link set dev veth990 up
ip netns exec server ip link set dev veth991 up
