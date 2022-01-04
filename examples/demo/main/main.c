/* WiFi station Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <lwip/err.h>
#include <lwip/sys.h>
#include <lwip/ip.h>
#include <lwip/netdb.h>

#include <wireguardif.h>
#include <wireguard-platform.h>
#include "sync_time.h"

#define EXAMPLE_ESP_WIFI_SSID	   CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS	   CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

#if defined(CONFIG_IDF_TARGET_ESP8266)
#define EXAMPLE_TCPIP_ADAPTER
#else
#define EXAMPLE_NETIF
#endif

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT	   BIT1

static const char *TAG = "demo";
static int s_retry_num = 0;

// Wireguard instance
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

static esp_err_t wireguard_setup(struct wireguardif_peer *peer)
{
	esp_err_t err = ESP_FAIL;
	err_t result = ERR_OK;

	struct wireguardif_init_data wg;
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);

	ESP_ERROR_CHECK(ipaddr_aton(CONFIG_WG_LOCAL_IP_ADDRESS, &ipaddr) != 0 ? ESP_OK : ESP_FAIL);
	ESP_ERROR_CHECK(ipaddr_aton(CONFIG_WG_LOCAL_IP_NETMASK, &netmask) != 0 ? ESP_OK : ESP_FAIL);
	if (peer == NULL) {
		err = ESP_ERR_INVALID_ARG;
		goto fail;
	}

	// Setup the WireGuard device structure
	wg.private_key = CONFIG_WG_PRIVATE_KEY;
	wg.listen_port = CONFIG_WG_LOCAL_PORT;

	wg.bind_netif = NULL;

	// Initialize the platform
	wireguard_platform_init();

	// Register the new WireGuard network interface with lwIP
	wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);
	assert(wg_netif);

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	netif_set_up(wg_netif);

	// Initialise the first WireGuard peer structure
	wireguardif_peer_init(peer);
	peer->public_key = CONFIG_WG_PEER_PUBLIC_KEY;
	peer->preshared_key = NULL;
	// Allow all IPs through tunnel
	{
		ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		peer->allowed_ip = allowed_ip;
		ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		peer->allowed_mask = allowed_mask;
	}
	// If we know the endpoint's address can add here
	{
		ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		struct addrinfo *res = NULL;
		struct addrinfo hint;
		memset(&hint, 0, sizeof(hint));
		memset(&endpoint_ip, 0, sizeof(endpoint_ip));
		ESP_ERROR_CHECK(lwip_getaddrinfo(CONFIG_WG_PEER_ADDRESS, NULL, &hint, &res) == 0 ? ESP_OK : ESP_FAIL);
		struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
		inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
		lwip_freeaddrinfo(res);

		peer->endpoint_ip = endpoint_ip;
		ESP_LOGI(TAG, "Peer: %s (%d.%d.%d.%d:%d)"
			, CONFIG_WG_PEER_ADDRESS
			, (endpoint_ip.u_addr.ip4.addr >>  0) & 0xff
			, (endpoint_ip.u_addr.ip4.addr >>  8) & 0xff
			, (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff
			, (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff
			, CONFIG_WG_PEER_PORT
			);
	}
	peer->endport_port = CONFIG_WG_PEER_PORT;

	// Register the new WireGuard peer with the netwok interface
	result = wireguardif_add_peer(wg_netif, peer, &wireguard_peer_index);
	if (result != ERR_OK) {
		ESP_LOGE(TAG, "wireguardif_add_peer: %d", result);
		goto fail;
	}
	if (wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
		ESP_LOGE(TAG, "wireguard_peer_index is invalid");
		err = ESP_FAIL;
		goto fail;
	}
	if (ip_addr_isany(&peer->endpoint_ip)) {
		ESP_LOGE(TAG, "peer->endpoint_ip is invalid");
		err = ESP_FAIL;
		goto fail;
	}
	// Start outbound connection to peer
	ESP_LOGI(TAG, "connecting wireguard...");
	result = wireguardif_connect(wg_netif, wireguard_peer_index);
	if (result != ERR_OK) {
		ESP_LOGE(TAG, "netif_set_default: %d", result);
		err = ESP_FAIL;
		goto fail;
	}
	netif_set_default(wg_netif);
	err = ESP_OK;
fail:
	return err;
}

static void event_handler(void* arg, esp_event_base_t event_base,
								int32_t event_id, void* event_data)
{
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
		esp_wifi_connect();
	} else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
			esp_wifi_connect();
			s_retry_num++;
			ESP_LOGI(TAG, "retry to connect to the AP");
		} else {
			xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
		}
		ESP_LOGI(TAG,"connect to the AP fail");
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		s_retry_num = 0;
		xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	}
}

#ifdef EXAMPLE_TCPIP_ADAPTER
static esp_err_t wifi_init_tcpip_adaptor(void)
{
	esp_err_t err = ESP_FAIL;
	s_wifi_event_group = xEventGroupCreate();

	tcpip_adapter_init();

	ESP_ERROR_CHECK(esp_event_loop_create_default());

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

	wifi_config_t wifi_config = {
		.sta = {
			.ssid = EXAMPLE_ESP_WIFI_SSID,
			.password = EXAMPLE_ESP_WIFI_PASS
		},
	};

	/* Setting a password implies station will connect to all security modes including WEP/WPA.
		* However these modes are deprecated and not advisable to be used. Incase your Access point
		* doesn't support WPA2, these mode can be enabled by commenting below line */

	if (strlen((char *)wifi_config.sta.password)) {
		wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
	}

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
	ESP_ERROR_CHECK(esp_wifi_start() );

	ESP_LOGI(TAG, "wifi_init_sta finished.");

	/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
	 * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
	EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
			WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
			pdFALSE,
			pdFALSE,
			portMAX_DELAY);

	/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
	 * happened. */
	if (bits & WIFI_CONNECTED_BIT) {
		ESP_LOGI(TAG, "connected to ap SSID:%s", EXAMPLE_ESP_WIFI_SSID);
	} else if (bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s", EXAMPLE_ESP_WIFI_SSID);
		err = ESP_FAIL;
		goto fail;
	} else {
		ESP_LOGE(TAG, "Unknown event");
		err = ESP_FAIL;
		goto fail;
	}

	ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler));
	ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler));
	vEventGroupDelete(s_wifi_event_group);

	err = ESP_OK;
fail:
	return err;
}
#endif // EXAMPLE_TCPIP_ADAPTER

#ifdef EXAMPLE_NETIF
static esp_err_t wifi_init_netif(void)
{
	esp_err_t err = ESP_FAIL;
	esp_netif_t *sta_netif;

	s_wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_netif_init());

	ESP_ERROR_CHECK(esp_event_loop_create_default());
	sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif);

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id;
	esp_event_handler_instance_t instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
														ESP_EVENT_ANY_ID,
														&event_handler,
														NULL,
														&instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
														IP_EVENT_STA_GOT_IP,
														&event_handler,
														NULL,
														&instance_got_ip));

	wifi_config_t wifi_config = {
		.sta = {
			.ssid = EXAMPLE_ESP_WIFI_SSID,
			.password = EXAMPLE_ESP_WIFI_PASS,
			/* Setting a password implies station will connect to all security modes including WEP/WPA.
			 * However these modes are deprecated and not advisable to be used. Incase your Access point
			 * doesn't support WPA2, these mode can be enabled by commenting below line */
		 .threshold.authmode = WIFI_AUTH_WPA2_PSK,

			.pmf_cfg = {
				.capable = true,
				.required = false
			},
		},
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
	ESP_ERROR_CHECK(esp_wifi_start() );

	/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
	 * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
	EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
			WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
			pdFALSE,
			pdFALSE,
			portMAX_DELAY);

	/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
	 * happened. */
	if (bits & WIFI_CONNECTED_BIT) {
		ESP_LOGI(TAG, "Connected to ap SSID:%s", EXAMPLE_ESP_WIFI_SSID);
	} else if (bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s", EXAMPLE_ESP_WIFI_SSID);
		err = ESP_FAIL;
		goto fail;
	} else {
		ESP_LOGE(TAG, "Unknown event");
		err = ESP_FAIL;
		goto fail;
	}

	err = esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_event_handler_instance_unregister: %s", esp_err_to_name(err));
		goto fail;
	}
	err = esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_event_handler_instance_unregister: %s", esp_err_to_name(err));
		goto fail;
	}
	vEventGroupDelete(s_wifi_event_group);

	err = ESP_OK;
fail:
	return err;
}
#endif // EXAMPLE_NETIF

static esp_err_t wifi_init_sta(void)
{
#ifdef EXAMPLE_TCPIP_ADAPTER
	return wifi_init_tcpip_adaptor();
#endif
#if defined(EXAMPLE_NETIF)
	return wifi_init_netif();
#endif
}

void app_main(void)
{
	esp_err_t err;
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];

	struct wireguardif_peer peer;
	memset(&peer, 0, sizeof(peer));

	err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
	  ESP_ERROR_CHECK(nvs_flash_erase());
	  err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);

	err = wifi_init_sta();
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "wifi_init_sta: %s", esp_err_to_name(err));
		goto fail;
	}

    obtain_time();
    time(&now);

    setenv("TZ", "EST5EDT,M3.2.0/2,M11.1.0", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time in New York is: %s", strftime_buf);

	err = wireguard_setup(&peer);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "wireguard_setup: %s", esp_err_to_name(err));
		goto fail;
	}

	while (1) {
		vTaskDelay(1000 / portTICK_RATE_MS);
		err = wireguardif_peer_is_up(wg_netif, wireguard_peer_index, &peer.endpoint_ip, &peer.endport_port);
		ESP_LOGI(TAG, "Peer is %s", err == ERR_OK ? "up" : "down");
	}

fail:
	ESP_LOGE(TAG, "Halting due to error");
	while (1) {
		vTaskDelay(1000 / portTICK_RATE_MS);
	}
}
