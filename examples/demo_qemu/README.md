# ESP WireGuard Demo Example

This demo showcases the use of ESP WireGuard on QEMU with emulated OpenCores Ethernet, running in a Docker environment.
The setup includes 1 container running `esp_wireguard` and 2 containers running native WireGuard.
All services are managed and spun up with Docker Compose.

**⚠ WARNING:**

Note: The private and public keys used in this example are intended for testing purposes only and should never be used in a real environment.

## Overview

- **Platform**: ESP-IDF
- **Virtualization**: QEMU
- **Network Interface**: (OpenCores Ethernet emulated)[https://github.com/espressif/esp-toolchain-docs/blob/main/qemu/esp32/README.md#ethernet-support] via QEMU
- **Dockerized**: Using Docker Compose for container orchestration
- **Containers**:
  - `esp_wireguard`: ESP WireGuard peer running in a QEMU emulator
  - `wireguard_peer1`: First native WireGuard peer
  - `wireguard_peer2`: Second native WireGuard peer

Connection between peers looks as below:

                wireguard_peer1
               /
              /
esp_wireguard
              \
               \
                wireguard_peer2

Esp_wireguard peer establishes the connections to both wireguard peers.

## Prerequisites

- [Docker](https://www.docker.com/) installed on your machine.
- [Docker Compose](https://docs.docker.com/compose/) for orchestrating the setup.


## How to build and run

### WireGuard Configuration

There is no need to set-up Wireguard configuration details as they defined already in the demo project.

### Docker Compose
In the root directory of the repository run following command:

`docker compose up --build -d`

To check the logs of esp_wireguard container:

`docker logs esp_wireguard`

1st Wireguard peer:

`docker logs wireguard_peer1`

2nd Wireguard peer:

`docker logs wireguard_peer2`

To stop and remove the containers:

`docker compose down`
