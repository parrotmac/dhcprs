#!/usr/bin/env bash

set -euo pipefail

docker compose down || true
trap "docker compose down" EXIT

docker compose up --build -d

# Wait for 'docker compose up' to finish

# Server
while true; do
  if [ "$( docker compose logs server | grep 'Listen 0.0.0.0:67' )" ]; then
    echo "[INFO] Server container is ready"
    break
  fi
  sleep 1
done

# Client
# Check command: docker compose exec client true
while true; do
  if docker compose exec client true; then
    echo "[INFO] Client container is ready"
    break
  fi
  sleep 1
done

# Start a temporary privileged container to configure the network


CLIENT_CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' $( docker compose ps -q client ))
SERVER_CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' $( docker compose ps -q server ))

docker build -t network_setup network_setup

docker run --rm \
  --name network_cfg \
  --network host \
  --pid host \
  --privileged \
  --env CLIENT_CONTAINER_PID=${CLIENT_CONTAINER_PID} \
  --env SERVER_CONTAINER_PID=${SERVER_CONTAINER_PID} \
  network_setup

# Run DHCP client in the client container
docker compose exec client /opt/dhcprs-client veth990

# Pull sever assigned IP address from server logs
CLIENT_MAC="$(docker compose exec client ip link show veth990 | grep 'link/ether' | awk '{print $2}')"
echo "[INFO] Client MAC address: ${CLIENT_MAC}"
ASSIGNED_IP=$(docker compose logs server | grep "for MAC ${CLIENT_MAC}" | tail -1 | sed 's/.*found IP address //' | awk '{print $1}')
echo "[INFO] Assigned IP address: ${ASSIGNED_IP}"

# Check that the client has the correct IP address
if [ "$(docker compose exec client ip addr show veth990 | grep ${ASSIGNED_IP})" ]; then
  echo "[SUCCESS] Client has the correct IP address"
else
  echo "[FAIL] Client does not have the correct IP address"
  exit 1
fi
