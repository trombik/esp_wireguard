#include "derp.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lwip/netif.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/mem.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <sys/socket.h>
#include <esp_log.h>
#include <esp_err.h>
#include "esp_tls.h"
#include "crypto.h"
#include "sodium.h"

#define WIREGUARDIF_TIMER_MSECS 400
#define DERP_CONNECTION_TIMEOUT_TICKS 20

#define TAG "derp" // TODO: fix log levels, as now only errors are printed

// Certificate:
const char *cacert =
"-----BEGIN CERTIFICATE-----\n"
"MIIEijCCA3KgAwIBAgIQfU1CqStDHX5kU+fBmo1YdzANBgkqhkiG9w0BAQsFADBX\n"
"MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE\n"
"CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIyMTAx\n"
"MjAzNDk0M1oXDTI3MTAxMjAwMDAwMFowTDELMAkGA1UEBhMCQkUxGTAXBgNVBAoT\n"
"EEdsb2JhbFNpZ24gbnYtc2ExIjAgBgNVBAMTGUFscGhhU1NMIENBIC0gU0hBMjU2\n"
"IC0gRzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtJCmVZhWIPzOH\n"
"A3jP1QwkuDFT8/+DImyZlSt85UpZwq7G0Sqd+n8gLlHIZypQkad5VkT7OLU+MI78\n"
"lC7LVwxpU19ExlaWL67ANyWG8XHx3AJFQoZhuDbvUeNzRQyQs6XS5wN6uDlF0Bf1\n"
"AtCUQWrGGLGYwyC1xTrzgrFKpESsIXMqklUGTsh8i7DKZhRUVfgrPLJUkbbLUrLY\n"
"42+KRCiwfSvBloC5PgDYnj3oMZ1aTe3Wfk3l1I4D3RKaJ4PU1qHXhHJOge2bjGIG\n"
"l6MsaBN+BB2sr6EnxX0xnMIbew2oIfOFoLqs47vh/GH4JN0qql2WBHfDPVDm3b+G\n"
"QxY6N/LXAgMBAAGjggFbMIIBVzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYI\n"
"KwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE\n"
"FE/LrKjC76vdg29rv86YPVxYJXYVMB8GA1UdIwQYMBaAFGB7ZhpFDZfKiVAvfQTN\n"
"NKj//P1LMHoGCCsGAQUFBwEBBG4wbDAtBggrBgEFBQcwAYYhaHR0cDovL29jc3Au\n"
"Z2xvYmFsc2lnbi5jb20vcm9vdHIxMDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJl\n"
"Lmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXIxLmNydDAzBgNVHR8ELDAqMCig\n"
"JqAkhiJodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QuY3JsMCEGA1UdIAQa\n"
"MBgwCAYGZ4EMAQIBMAwGCisGAQQBoDIKAQMwDQYJKoZIhvcNAQELBQADggEBABol\n"
"9nNkiECpWQenQ7oVP1FhvRX/LWTdzXpdMmp/SELnEJhoOe+366E0dt8tWGg+ezAc\n"
"DPeGYPmp83nAVLeDpji7Nqu8ldB8+G/B6U9GB8i2DDIAqSsFEvcMbWb5gZ2/DmRN\n"
"cifGi9FKAuFu2wyft4s4DHwzL2CJ2zjMlUOM3RaE1cxuOs+Om6MCD9G7vnkAtSiC\n"
"/OOfHO902f4yI2a48K+gKaAf3lISFXjd32pwQ21LpM3ueIGydaJ+1/z8nv+C7SUT\n"
"5bHoz7cYU27LUvh1n2WSNnC6/QwFSoP6gNKa4POO/oO13xjhrLRHJ/04cKMbRALt\n"
"JWQkPacJ8SJVhB2R7BI=\n"
"-----END CERTIFICATE-----";

void derp_tick(struct wireguard_device *dev) {
	err_t err = ESP_FAIL;

	bool is_any_peer_active = false;
	for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
		is_any_peer_active |= dev->peers[i].active;
	}

	if (is_any_peer_active && dev->derp.tls == NULL) {
		ESP_LOGE(TAG, "No DERP connection, but active peers exists -> initializing DERP connection");
		err = derp_initiate_new_connection(dev);
		ESP_LOGE(TAG, "New DERP connection initiation status, %d", err);
	} else if (!is_any_peer_active && dev->derp.tls) {
		ESP_LOGE(TAG, "No active peer exists - Shutting down DERP connection");
		err = derp_shutdown_connection(dev);
		ESP_LOGE(TAG, "Shutdown of DERP connection status, %d", err);
	} else if (dev->derp.tls && dev->derp.ticks_connecting > DERP_CONNECTION_TIMEOUT_TICKS) {
		//ESP_LOGE(TAG, "DERP connection timeout - Shutting down");
		//err = derp_shutdown_connection(dev);
		//dev->derp.ticks_connecting = 0;
		//ESP_LOGE(TAG, "Shutdown of DERP connection status, %d", err);
	}

	if ((dev->derp.conn_state & CONN_STATE_TCP_DISCONNECTED) | (dev->derp.conn_state & CONN_STATE_DERP_READY)) {
			dev->derp.ticks_connecting = 0;
		} else {
			++dev->derp.ticks_connecting;
		}
}


static void read_from_interface_worker(void *arg) {
	int err = ESP_FAIL;
	struct wireguard_device *dev = (struct wireguard_device *)arg;
	uint32_t packet_ptr;

	ESP_LOGE(TAG, "Read from interface worker starting");

	for (;;) {
		xTaskNotifyWaitIndexed(0, ULONG_MAX, ULONG_MAX, &packet_ptr, portMAX_DELAY);
		struct derp_pkt *data_pkt = (struct derp_pkt *)packet_ptr;

		ESP_LOGE(TAG, "Data packet has attempted to send");
		err = esp_tls_conn_write(dev->derp.tls, data_pkt, BE32_TO_LE32(data_pkt->length_be) + 5);
		if (err < 0) {
			ESP_LOGE(TAG, "Failed to send data packet %d", err);
			goto end;
		}

		ESP_LOGE(TAG, "Data packet has been sent");
		mem_free(data_pkt);
	}

end:
	vTaskDelete(NULL);
}

static void read_from_network_worker(void *arg) {
	int err = ESP_FAIL;
	struct wireguard_device *dev = (struct wireguard_device *)arg;
	size_t max_data_pkt_size = 2048;
	struct derp_pkt *data_pkt = mem_malloc(max_data_pkt_size);
	if (data_pkt == NULL) {
		ESP_LOGE(TAG, "Failed to allocate memory for rx packet buf");
		goto end;
	}

	ESP_LOGE(TAG, "Read from network worker starting");

	for (;;) {
		int read_len = esp_tls_conn_read(dev->derp.tls, data_pkt, max_data_pkt_size);
		if (read_len <= 0) {
			ESP_LOGE(TAG, "Failed to receive data packet upgrade response %d", read_len);
			goto end;
		}

		if (read_len < 5 || read_len < 5 + BE32_TO_LE32(data_pkt->length_be)) {
			ESP_LOGE(TAG, "Received packet is too short %d", read_len);
			continue;
		}

		if (data_pkt->type != 0x05) {
			ESP_LOGE(TAG, "Received strange packet type %d", data_pkt->type);
			continue;
		}

		if (data_pkt->data.subtype != 0x00) {
			ESP_LOGE(TAG, "Received strange packet subtype %d", data_pkt->data.subtype);
			continue;
		}

		// Data packet:
		uint16_t offset = 0;
		struct pbuf data;
		data.payload = data_pkt->data.data;
		data.tot_len = read_len - offsetof(struct derp_pkt, data.data);
		data.len = read_len - offsetof(struct derp_pkt, data.data);

		// Always use localhost address
		struct ip_addr addr = {0};
		err = ipaddr_aton("127.0.0.1", &addr);

		// Find which peer packet is being sent,
		// we will assign port according to this
		int index = -1;
		for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
			if (!dev->peers[i].active)
				continue;

			// Compare public keys of known peers
			if (memcmp(data_pkt->data.peer_public_key, dev->peers[i].public_key, WIREGUARD_PUBLIC_KEY_LEN) == 0) {
				index = i;
				break;
			}
		}
		if (index == -1) {
			ESP_LOGE(TAG, "Received data mesage for unknown peer. Ignoring");
		}
		uint16_t port = 49152 + index;

		ESP_LOGE(TAG, "Invoking packet receiving callback for wireguard for peer on port %d", port);
		wireguardif_network_rx((void *)dev, NULL, &data, &addr, port);
	}

end:
	if (data_pkt) {
		mem_free(data_pkt);
	}

	vTaskDelete(NULL);
}

static void derp_transmit_task(void *arg) {
	struct wireguard_device *dev = (struct wireguard_device *)arg;
	uint8_t *read_buf = NULL;
	int err = ESP_FAIL;

	ESP_LOGE(TAG, "Allocating new socket");
	dev->derp.tls = esp_tls_init();

	if (dev->derp.tls == NULL) {
		ESP_LOGE(TAG, "Failed to allocate socket");
		goto ret;
	}

	// Prepare TLS configuration
	esp_tls_cfg_t tls_cfg = {0};
	tls_cfg.cacert_buf = cacert;
	tls_cfg.cacert_bytes = strlen(cacert) + 1;
	tls_cfg.skip_common_name = true;

	// Try to establish TLS connection
	const char *derp_ip = "149.88.19.146"; // TODO: make configurable
	err = esp_tls_conn_new_sync(derp_ip, strlen(derp_ip), 8765, &tls_cfg, dev->derp.tls);
	if (err == -1) {
		ESP_LOGE(TAG, "Failed to attempt TLS connection address %d", err);
		goto ret;
	}
	ESP_LOGE(TAG, "Connection Established!");

	dev->derp.conn_state = CONN_STATE_TCP_CONNECTING;

	// Prepare HTTP upgrade request
	const char * http_req =
		"GET /derp HTTP/1.1\r\n"
		"Host: 149.88.19.146\r\n"
		"Connection: Upgrade\r\n"
		"Upgrade: WebSocket\r\n"
		"User-Agent: esp32/v1.0.0 esp\r\n\r\n";
	err = esp_tls_conn_write(dev->derp.tls, http_req, strlen(http_req));
	if (err < 0) {
		ESP_LOGE(TAG, "Failed to send HTTP upgrade request %d", err);
		goto ret;
	}

	ESP_LOGE(TAG, "Request transmitted!");

	// Read HTTP response
	const int read_buf_size = 2048;
	read_buf = mem_malloc(read_buf_size);
	if (!read_buf) {
		ESP_LOGE(TAG, "Failed allocate HTTP response buffer");
		goto ret;
	}
	int read_len = esp_tls_conn_read(dev->derp.tls, read_buf, read_buf_size);
	if (read_len <= 0) {
		ESP_LOGE(TAG, "Failed to receive HTTP upgrade response %x %s", err, read_buf);
		goto ret;
	}

	// Verify that server agrees to switch protocols
	if (strstr(read_buf, "101 Switching Protocols") == NULL) {
		ESP_LOGE(TAG, "Server has not responded with success response: %s", read_buf);
		goto ret;
	}

	ESP_LOGE(TAG, "Server has switched protocols");

	// Verify length of the response
	uint8_t *http_resp_end = strstr(read_buf, "\r\n\r\n");
	if (http_resp_end == NULL) {
		ESP_LOGE(TAG, "HTTP response end not found");
		goto ret;
	}
	http_resp_end += 4;

	size_t http_resp_len = http_resp_end - (uint8_t *)read_buf;
	if (read_len - http_resp_len < 45) {
		ESP_LOGE(TAG, "Server Key packet too short %d", http_resp_len);
		goto ret;
	}

	struct derp_pkt *server_key_pkt = http_resp_end;
	ESP_LOGE(TAG, "ServerKey received");

	//TODO: Validate that the server key is in
	//      fact matching the one provided via config

	// Prepare client_key packet
	struct derp_pkt client_key_pkt;
	memset(&client_key_pkt, 0, sizeof(client_key_pkt));

	const char* plaintext = "{\"version\": 2, \"meshKey\": \"\"}";
	client_key_pkt.type = 2; // Client-Key packet
	client_key_pkt.length_be = BE32_TO_LE32(101);
	memcpy(client_key_pkt.client_key.client_public_key, dev->public_key, sizeof(client_key_pkt.client_key.client_public_key));
	randombytes_buf(client_key_pkt.client_key.nonce, sizeof(client_key_pkt.client_key.nonce));

	ESP_LOGE(TAG, "Attempting to encrypt the plaintext for client-key");
	err = crypto_box_easy(client_key_pkt.client_key.ciphertext,
			plaintext, strlen(plaintext),
			client_key_pkt.client_key.nonce,
			server_key_pkt->server_key.server_public_key,
			dev->private_key);
	if (err != 0) {
		ESP_LOGE(TAG, "Failed to encrypt plaintext for client-key packet: %d", err);
		goto ret;
	}

	ESP_LOGE(TAG, "Attempting to transmit ClientKey message");
	err = esp_tls_conn_write(dev->derp.tls, &client_key_pkt, 106);
	if (err < 0) {
		ESP_LOGE(TAG, "Failed to send HTTP upgrade request %d", err);
		goto ret;
	}

	ESP_LOGE(TAG, "Reading ServerInfo message");
	read_len = esp_tls_conn_read(dev->derp.tls, read_buf, read_buf_size);
	if (read_len < 5) {
		ESP_LOGE(TAG, "Failed to receive ServerInfo message %d", err);
		goto ret;
	}
	struct derp_pkt *serverInfo = read_buf;
	if (serverInfo->type != 3) {
		ESP_LOGE(TAG, "Unexpected packet during DERP handshake %s", serverInfo->type);
		goto ret;
	}

	mem_free(read_buf);
	read_buf = NULL;

	ESP_LOGE(TAG, "DERP connection established succesfully");

	dev->derp.conn_state = CONN_STATE_DERP_READY;

	read_from_network_worker(dev);

ret:
	if (read_buf) {
		mem_free(read_buf);
	}

	vTaskDelete(NULL);
}

err_t derp_initiate_new_connection(struct wireguard_device *dev) {
	err_t err = ESP_FAIL;
	LWIP_ASSERT("derp_tick: invalid state", dev->derp.conn_state == CONN_STATE_TCP_DISCONNECTED);
	LWIP_ASSERT("derp_initiate_new_connection: invalid state", dev->derp.tls == NULL);

	// Creating new task for http stuff
	xTaskCreate(&read_from_interface_worker, "read-from-interface", 8192, dev, 5, &dev->derp.read_interface_worker);
	xTaskCreate(&derp_transmit_task, "derp-task", 8192, dev, 5, NULL);

	return ESP_OK;
}

err_t derp_shutdown_connection(struct wireguard_device *dev) {
	if (dev->derp.tls != NULL) {
		esp_tls_conn_destroy(dev->derp.tls);
		dev->derp.tls = NULL;
	}

	dev->derp.conn_state = CONN_STATE_TCP_DISCONNECTED;

	return ESP_OK;
}


err_t derp_send_packet(struct wireguard_device *dev, struct wireguard_peer *peer, struct pbuf *payload) {
	err_t err = ESP_FAIL;

	if (dev->derp.conn_state != CONN_STATE_DERP_READY) {
		ESP_LOGE(TAG, "Requested to transmit packet while DERP is not ready. Dropping");
		return ESP_FAIL;
	}

	// Allocate buffer for packet
	int packet_len = 5 + WIREGUARD_PUBLIC_KEY_LEN + 1 + payload->tot_len;
	struct derp_pkt *packet = mem_malloc(packet_len);
	if (!packet) {
		ESP_LOGE(TAG, "Failed to allocate buffer for packet");
		return ESP_FAIL;
	}

	packet->type = 0x04; // SendPacket type
	packet->length_be = BE32_TO_LE32(WIREGUARD_PUBLIC_KEY_LEN + 1 + payload->tot_len);
	memcpy(packet->data.peer_public_key, peer->public_key, WIREGUARD_PUBLIC_KEY_LEN);
	packet->data.subtype = 0x00;
	pbuf_copy_partial(payload, packet->data.data, payload->tot_len, 0);

	if (xTaskNotify(dev->derp.read_interface_worker, (uint32_t)packet, eSetValueWithoutOverwrite) != pdPASS) {
		mem_free(packet);
		ESP_LOGE(TAG, "Worker busy -> dropping packet");
	}

cleanup:
	return ESP_OK;
}



