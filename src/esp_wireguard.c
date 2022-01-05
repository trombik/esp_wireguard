/*
 * Copyright (c) 2022 Tomoyuki Sakurai <y@trombik.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <lwip/ip.h>
#include <lwip/netdb.h>
#include <lwip/err.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_wireguard.h>

#include "wireguard-platform.h"
#include "wireguardif.h"

#define TAG "esp_wireguard"

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static struct wireguardif_peer peer;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

esp_err_t esp_wireguard_init(wireguard_config_t *config, wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;
    err_t lwip_err = -1;
    char addr_str[INET_ADDRSTRLEN];
    ip_addr_t ip_addr;
    ip_addr_t netmask;
    ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    struct wireguardif_init_data wg;

    memset(&peer, 0, sizeof(peer));
    memset(&wg, 0, sizeof(wg));

    if (ipaddr_aton(config->allowed_ip, &ip_addr) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip: `%s`", config->allowed_ip);
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }
    if (ipaddr_aton(config->allowed_ip_mask, &netmask) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip_mask: `%s`", config->allowed_ip_mask);
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* Setup the WireGuard device structure */
    wg.private_key = config->private_key;
    wg.listen_port = config->listen_port;
    wg.bind_netif = NULL;

    err = wireguard_platform_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard_platform_init: %s", esp_err_to_name(err));
        goto fail;
    }

    /* Register the new WireGuard network interface with lwIP */
    wg_netif = netif_add(
            &wg_netif_struct,
            ip_2_ip4(&ip_addr),
            ip_2_ip4(&netmask),
            ip_2_ip4(&gateway),
            &wg, &wireguardif_init,
            &ip_input);
    if (wg_netif == NULL) {
        ESP_LOGE(TAG, "netif_add: failed");
        err = ESP_FAIL;
        goto fail;
    }

    /* Mark the interface as administratively up, link up flag is set
     * automatically when peer connects */
    netif_set_up(wg_netif);

    /* Initialize the first WireGuard peer structure */
    wireguardif_peer_init(&peer);

    peer.public_key = config->public_key;
    peer.preshared_key = (uint8_t*)config->preshared_key;

    /* Allow all IPs through tunnel */
    {
        ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_mask = allowed_mask;
    }

    /* resolve peer name or IP address */
    {
        ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        struct addrinfo *res = NULL;
        struct addrinfo hint;
        memset(&hint, 0, sizeof(hint));
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));
        if (lwip_getaddrinfo(config->endpoint, NULL, &hint, &res) != 0) {
            lwip_freeaddrinfo(res);
            ESP_LOGE(TAG, "lwip_getaddrinfo: unable to resolve %s", config->endpoint);
            err = ESP_FAIL;
            goto fail;
        }

        ESP_ERROR_CHECK(lwip_getaddrinfo(CONFIG_WG_PEER_ADDRESS, NULL, &hint, &res) == 0 ? ESP_OK : ESP_FAIL);
        struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
        inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        lwip_freeaddrinfo(res);
        peer.endpoint_ip = endpoint_ip;

    }

    inet_ntop(AF_INET, &(peer.endpoint_ip), addr_str, INET_ADDRSTRLEN);
    if (addr_str == NULL) {
        ESP_LOGW(TAG, "inet_ntop: %d", errno);
    } else {
        ESP_LOGI(TAG, "Peer: %s (%s:%d)", config->endpoint, addr_str, config->port);
    }
    peer.endport_port = config->port;

    /* Register the new WireGuard peer with the network interface */
    lwip_err = wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);
    if (lwip_err != ERR_OK || wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
        ESP_LOGE(TAG, "wireguardif_add_peer: %d", lwip_err);
        goto fail;
    }
    if (ip_addr_isany(&peer.endpoint_ip)) {
        err = ESP_FAIL;
        goto fail;
    }
    ctx->config = config;
    ctx->netif = wg_netif;
    ctx->netif_default = netif_default;

    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_connect(wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;
    err_t lwip_err = -1;

    ESP_LOGI(TAG, "Connecting to %s:%d", ctx->config->endpoint, ctx->config->port);
    lwip_err = wireguardif_connect(wg_netif, wireguard_peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGE(TAG, "wireguardif_connect: %d", lwip_err);
        err = ESP_FAIL;
        goto fail;
    }
    err = ESP_OK;
fail:
    return err;
}

void esp_wireguard_set_default(wireguard_ctx_t *ctx)
{
    netif_set_default(ctx->netif);
}

void esp_wireguard_disconnect(wireguard_ctx_t *ctx)
{
    err_t lwip_err;

    netif_set_default(ctx->netif_default);

    lwip_err = wireguardif_disconnect(ctx->netif, wireguard_peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_disconnect: peer_index: %d err: %d", wireguard_peer_index, lwip_err);
    }

    lwip_err = wireguardif_remove_peer(ctx->netif, wireguard_peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_remove_peer: peer_index: %d err: %d", wireguard_peer_index, lwip_err);
    }

    wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    wireguardif_shutdown(ctx->netif);
    netif_remove(ctx->netif);
    ctx->netif = NULL;
}

esp_err_t esp_wireguardif_peer_is_up(wireguard_ctx_t *ctx)
{
    err_t lwip_err;

    lwip_err = wireguardif_peer_is_up(
            ctx->netif,
            wireguard_peer_index,
            &peer.endpoint_ip,
            &peer.endport_port);
    return lwip_err == ERR_OK ? ESP_OK : ESP_FAIL;
}
