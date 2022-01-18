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
* `esp32c3`
* `esp8266`

## Usage

In `menuconfig` under `WireGuard`, choose a TCP/IP adapter. The default is
`ESP-NETIF`. SDKs older than `esp-idf` `v4.1`, including ESP8266 RTOS SDK v3.4
requires `TCP/IP Adapter`.

Both peers must have synced time. The library does not sync time.

A working network interface is required.

Create WireGuard configuration, `wireguard_config_t`, and `wireguard_ctx_t`.
Pass the variables to `esp_wireguard_init()`. Then, call
`esp_wireguard_connect()`. Call `esp_wireguard_disconnect()` to disconnect
from the peer (and destroy the WireGuard interface).

```c
#include <esp_wireguard.h>

esp_err_t err = ESP_FAIL;

wireguard_config_t wg_config = {
    .private_key = CONFIG_WG_PRIVATE_KEY,
    .listen_port = CONFIG_WG_LOCAL_PORT,
    .fw_mark = 0,
    .public_key = CONFIG_WG_PEER_PUBLIC_KEY,
    .preshared_key = NULL,
    .allowed_ip = CONFIG_WG_LOCAL_IP_ADDRESS,
    .allowed_ip_mask = CONFIG_WG_LOCAL_IP_NETMASK,
    .endpoint = CONFIG_WG_PEER_ADDRESS,
    .port = CONFIG_WG_PEER_PORT,
    .persistent_keepalive = 0,
};
wireguard_ctx_t ctx = {0};
err = esp_wireguard_init(&wg_config, &ctx);
err = esp_wireguard_connect(ctx);

/* do something */

err = esp_wireguard_disconnect(&ctx);
```

See examples at [examples](examples).

## Known issues

The implementation uses `LwIP` as TCP/IP protocol stack.

IPv6 support is not tested.

The library assumes the interface is WiFi interface. Ethernet is not
supported.

Older `esp-idf` versions with `TCP/IP Adapter`, such as v4.1.x, should work,
but there are others issues, not directly related to the library.

## License

BSD 3-Clause "New" or "Revised" License (SPDX ID: BSD-3-Clause).
See [LICENSE](LICENSE) for details.

## Authors

* Daniel Hope (daniel.hope@smartalock.com)
* Kenta Ida (fuga@fugafuga.org)
