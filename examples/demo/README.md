# demo example

## What the example does

The example connects to a WireGuard server. When the link is up, the device
sends ICMP echo requests, shows ping statistics, and loops forever.

## Requirements

* An ESP32 development board
* WiFi network
* [`wireguard-tools`](https://github.com/WireGuard/wireguard-tools)
* A WireGuard server

## Generate keys

```console
wg genkey | tee private.key | wg pubkey > public.key
```
