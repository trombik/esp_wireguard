# `esp_wireguard`, WireGuard Implementation for ESP-IDF

This is an implementation of the [WireGuard&reg;](https://www.wireguard.com/)
for ESP-IDF, based on
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).

[![Build examples](https://github.com/trombik/esp_wireguard/actions/workflows/build.yml/badge.svg)](https://github.com/trombik/esp_wireguard/actions/workflows/build.yml)

## Status

The code is alpha.

A single tunnel to a WireGuard peer has been working.

## Supported ESP-IDF versions and targets

The following ESP-IDF versions are supported:

* `esp-idf` `master`
* `esp-idf` `v4.2.x`
* `esp-idf` `v4.3.x`
* ESP8266 RTOS SDK `v3.4`

The following targets are supported:

* `esp32`
* `esp32s2`
* `esp8266`

## Usage

In `menuconfig` under `WireGuard`, choose a TCP/IP adapter. The default is
`ESP-NETIF`. SDKs older than `esp-idf` `v4.1`, including ESP8266 RTOS SDK v3.4
requires `TCP/IP Adapter`.

Both peers must have synced time. The library does not sync time.

## Known issues

The implementation uses `LwIP` as TCP/IP protocol stack.

IPv6 support is not tested.

## License

BSD 3-Clause "New" or "Revised" License (SPDX ID: BSD-3-Clause).
See [LICENSE](LICENSE) for details.

## Authors

* Daniel Hope (daniel.hope@smartalock.com)
* Kenta Ida (fuga@fugafuga.org)
