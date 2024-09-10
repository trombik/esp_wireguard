/* WireGuard demo example
   This example code is in the Public Domain (or CC0 licensed, at your option.)
   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <lwip/netdb.h>
#include <ping/ping_sock.h>
#include <esp_eth.h>
#include <esp_netif.h>
#include <driver/gpio.h>
#include <esp_wireguard.h>
#include "sync_time.h"


static const char *TAG = "demo_qemu";
static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
static wireguard_peer_config_t peer_one_config = ESP_WIREGUARD_PEER_CONFIG_DEFAULT();
static wireguard_peer_config_t peer_two_config = ESP_WIREGUARD_PEER_CONFIG_DEFAULT();



static void print_initialized_netifs(void) {
    esp_netif_t *netif = NULL;
    esp_netif_ip_info_t ip_info;

    ESP_LOGI(TAG, "Printing initialized network interfaces:");

    for (netif = esp_netif_next(netif); netif != NULL; netif = esp_netif_next(netif)) {
        ESP_LOGI(TAG, "Interface: %s, ID: %s", esp_netif_get_desc(netif), esp_netif_get_ifkey(netif));

        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            ESP_LOGI(TAG, "IP: " IPSTR ", Netmask: " IPSTR ", Gateway: " IPSTR,
                     IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask), IP2STR(&ip_info.gw));
        } else {
            ESP_LOGI(TAG, "IP information not available");
        }
    }
}

static esp_err_t wireguard_setup(wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;

    ESP_LOGI(TAG, "Initializing WireGuard.");
    wg_config.private_key = CONFIG_WG_PRIVATE_KEY;
    wg_config.listen_port = CONFIG_WG_LOCAL_PORT;

    wg_config.base_ip = CONFIG_WG_LOCAL_IP_ADDRESS;
    wg_config.net_mask = CONFIG_WG_LOCAL_IP_NETMASK;

    peer_one_config.public_key = CONFIG_WG_PEER_ONE_PUBLIC_KEY;
    peer_one_config.preshared_key = NULL;
    peer_one_config.allowed_ip[0] = CONFIG_WG_PEER_ONE_ADDRESS;
    peer_one_config.allowed_ip_mask[0] = CONFIG_WG_PEER_ONE_MASK;
    peer_one_config.endpoint = CONFIG_WG_PEER_ONE_ENDPOINT;
    peer_one_config.port = CONFIG_WG_PEER_ONE_PORT;
    peer_one_config.persistent_keepalive = CONFIG_WG_PERSISTENT_KEEP_ALIVE;

    peer_two_config.public_key = CONFIG_WG_PEER_TWO_PUBLIC_KEY;
    peer_two_config.preshared_key = NULL;
    peer_two_config.allowed_ip[0] = CONFIG_WG_PEER_TWO_ADDRESS;
    peer_two_config.allowed_ip_mask[0] = CONFIG_WG_PEER_TWO_MASK;
    peer_two_config.endpoint = CONFIG_WG_PEER_TWO_ENDPOINT;
    peer_two_config.port = CONFIG_WG_PEER_TWO_PORT;
    peer_two_config.persistent_keepalive = CONFIG_WG_PERSISTENT_KEEP_ALIVE;



    err = esp_wireguard_init(&wg_config, ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init: %s", esp_err_to_name(err));
        goto fail;
    }

    vTaskDelay(10000 / portTICK_PERIOD_MS);

    ESP_LOGI(TAG, "Connecting to the peer.");
    err = esp_wireguard_connect(ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect: %s", esp_err_to_name(err));
        goto fail;
    } else {
        ESP_LOGI(TAG, "WireGuard connection initiated successfully.");
    }

    err = esp_wireguard_add_peer(ctx, &peer_one_config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_wireguard_add_peer: %s", esp_err_to_name(err));
        goto fail;
    }

    err = esp_wireguard_add_peer(ctx, &peer_two_config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_wireguard_add_peer: %s", esp_err_to_name(err));
        goto fail;
    }

    err = ESP_OK;
fail:
    return err;
}

static esp_err_t ethernet_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&cfg);

    if (!eth_netif) {
        ESP_LOGE(TAG, "Failed to create default Ethernet netif");
        return ESP_FAIL;
    }

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.autonego_timeout_ms = 100;

    esp_eth_mac_t *mac = esp_eth_mac_new_openeth(&mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_dp83848(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    ESP_LOGI(TAG, "Waiting for 5 seconds...");
    vTaskDelay(5000 / portTICK_PERIOD_MS);

    print_initialized_netifs();

    ESP_LOGI(TAG, "Ethernet started");

    return ESP_OK;
}

static void test_on_ping_success(esp_ping_handle_t hdl, void *args)
{
    uint8_t ttl;
    uint16_t seqno;
    uint32_t elapsed_time, recv_len;
    ip_addr_t target_addr;

    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TTL, &ttl, sizeof(ttl));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_SIZE, &recv_len, sizeof(recv_len));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_time, sizeof(elapsed_time));

    ESP_LOGI(TAG, "%" PRIu32 " bytes from %s icmp_seq=%" PRIu16 " ttl=%" PRIi8 " time=%" PRIu32 " ms",
           recv_len, ipaddr_ntoa(&target_addr), seqno, ttl, elapsed_time);
}

static void test_on_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    uint16_t seqno;
    ip_addr_t target_addr;

    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));

    ESP_LOGI(TAG, "From %s icmp_seq=%" PRIu16 " timeout", ipaddr_ntoa(&target_addr), seqno);
}

static void test_on_ping_end(esp_ping_handle_t hdl, void *args)
{
    uint32_t transmitted, received, total_time_ms;

    esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST, &transmitted, sizeof(transmitted));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &received, sizeof(received));
    esp_ping_get_profile(hdl, ESP_PING_PROF_DURATION, &total_time_ms, sizeof(total_time_ms));

    ESP_LOGI(TAG, "%" PRIu32 " packets transmitted, %" PRIu32 " received, time %" PRIu32 "ms", transmitted, received, total_time_ms);
}

void start_ping(const char* ip_addr)
{
    ESP_LOGI(TAG, "Initializing ping...");

    ip_addr_t target_addr;
    struct addrinfo *res = NULL;
    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    memset(&target_addr, 0, sizeof(target_addr));

    ESP_ERROR_CHECK(lwip_getaddrinfo(ip_addr, NULL, &hint, &res) == 0 ? ESP_OK : ESP_FAIL);

    struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
    inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
    lwip_freeaddrinfo(res);

    ESP_LOGI(TAG, "ICMP echo target: %s", ip_addr);

    esp_ping_config_t ping_config = ESP_PING_DEFAULT_CONFIG();
    ping_config.target_addr = target_addr;
    ping_config.count = ESP_PING_COUNT_INFINITE;

    esp_ping_callbacks_t cbs = {
        .on_ping_success = test_on_ping_success,
        .on_ping_timeout = test_on_ping_timeout,
        .on_ping_end = test_on_ping_end,
        .cb_args = NULL
    };

    esp_ping_handle_t ping;
    ESP_ERROR_CHECK(esp_ping_new_session(&ping_config, &cbs, &ping));
    esp_ping_start(ping);
}

void app_main(void)
{
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];
    wireguard_ctx_t ctx = {0};
    esp_err_t err;

    esp_log_level_set("esp_wireguard", ESP_LOG_DEBUG);
    esp_log_level_set("wireguardif", ESP_LOG_DEBUG);
    esp_log_level_set("wireguard", ESP_LOG_DEBUG);

    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    err = ethernet_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ethernet_init: %s", esp_err_to_name(err));
        goto fail;
    }

    obtain_time();
    time(&now);

    setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time in Warsaw is: %s", strftime_buf);

    err = wireguard_setup(&ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard_setup: %s", esp_err_to_name(err));
        goto fail;
    }

    while (1) {
        vTaskDelay(10000 / portTICK_PERIOD_MS);
        err = esp_wireguardif_peer_is_up(&ctx, peer_one_config.public_key);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Peer 1 is up and connection established.");
            break;
        } else {
            ESP_LOGW(TAG, "Peer 1 is down or handshake not completed. Retrying...");
        }
    }

    start_ping(CONFIG_WG_PEER_ONE_ADDRESS);

    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        err = esp_wireguardif_peer_is_up(&ctx, peer_two_config.public_key);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Peer 2 is up and connection established.");
            break;
        } else {
            ESP_LOGI(TAG, "Peer 2 is down or handshake not completed. Retrying...");
        }
    }
    start_ping(CONFIG_WG_PEER_TWO_ADDRESS);

    vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);
    ESP_LOGI(TAG, "Disconnecting peer 1");
    esp_wireguard_remove_peer(&ctx, peer_one_config.public_key);
    ESP_LOGI(TAG, "Disconnected peer 1");

    vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);
    ESP_LOGI(TAG, "Connecting peer 1");
    err = esp_wireguard_add_peer(&ctx, &peer_one_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect: %s", esp_err_to_name(err));
        goto fail;
    }
    ESP_LOGI(TAG, "Peer 1 is up");
    vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);

    ESP_LOGI(TAG, "Disconnecting peer 2");
    esp_wireguard_remove_peer(&ctx, peer_two_config.public_key);
    ESP_LOGI(TAG, "Disconnected peer 2");

    vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);
    peer_one_config.allowed_ip[0] = CONFIG_EXAMPLE_FALSE_ADDRESS;
    esp_wireguard_update_peer(&ctx, &peer_one_config);
    ESP_LOGI(TAG, "Peer 1 updated!");
    vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);

    ESP_LOGI(TAG, "Everything works well");
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
fail:
    ESP_LOGE(TAG, "Halting due to error");
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
