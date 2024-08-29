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
#include "wireguardif.h"

#define WIREGUARDIF_TIMER_MSECS 400
#define DERP_CONNECTION_TIMEOUT_TICKS 20

#define TAG "derp" // TODO: fix log levels, as now only errors are printed

// Certificate:
const char *cacert =
"-----BEGIN CERTIFICATE-----\n"
"MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0BAQwFADB7\n"
"MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD\n"
"VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE\n"
"AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4\n"
"MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5\n"
"MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO\n"
"ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0\n"
"aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sI\n"
"s9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnG\n"
"vDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQ\n"
"Ijy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfb\n"
"IWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0\n"
"tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97E\n"
"xwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNV\n"
"icQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5\n"
"D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJ\n"
"WBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ\n"
"5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzG\n"
"KAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSMEGDAWgBSg\n"
"EQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rID\n"
"ZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAG\n"
"BgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t\n"
"L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggr\n"
"BgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUA\n"
"A4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+cli3vA0p+\n"
"rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCRlv79Q2R+\n"
"/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHxW/BBC5gA\n"
"CiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w52z97GA1F\n"
"zZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEUxOipakyA\n"
"vGp4z7h/jnZymQyd/teRCBaho1+V\n"
"-----END CERTIFICATE-----";

enum ConnectionAttemptControl {
	AttemptNow,
	WaitForReconnect,
	DoNotAttempt,
};

static enum ConnectionAttemptControl connection_attempt_control = DoNotAttempt;

void derp_tick(struct wireguard_device *dev) {
	err_t err = ESP_FAIL;

	bool is_any_peer_active = false;
	for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
		is_any_peer_active |= dev->peers[i].active;
	}

	if (is_any_peer_active && dev->derp.tls == NULL && connection_attempt_control == AttemptNow) {
		ESP_LOGI(TAG, "No DERP connection, but active peers exists -> initializing DERP connection");
		connection_attempt_control = WaitForReconnect;
		err = derp_initiate_new_connection(dev);
		ESP_LOGI(TAG, "New DERP connection initiation status, %d", err);
	} else if (!is_any_peer_active && dev->derp.tls) {
		ESP_LOGE(TAG, "No active peer exists - Shutting down DERP connection");
		err = derp_shutdown_connection(dev);
		ESP_LOGE(TAG, "Shutdown of DERP connection status, %d", err);
	//! TODO: Keeping this here for now
	// } else if (dev->derp.tls && dev->derp.ticks_connecting > DERP_CONNECTION_TIMEOUT_TICKS) {
		//ESP_LOGE(TAG, "DERP connection timeout - Shutting down");
		//err = derp_shutdown_connection(dev);
		//dev->derp.ticks_connecting = 0;
		//ESP_LOGE(TAG, "Shutdown of DERP connection status, %d", err);
	} else if (dev->derp.tls && (connection_attempt_control == AttemptNow)) {
		ESP_LOGI(TAG, "Initializing new DERP connection");
		connection_attempt_control = WaitForReconnect;
		err = derp_shutdown_connection(dev);
		if (!err) {
			ESP_LOGE(TAG, "DERP shutdown failed, %d", err);
			return;
		}
		err = derp_initiate_new_connection(dev);
		ESP_LOGI(TAG, "New DERP connection initiation status, %d", err);
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
	struct wireguard_device *dev = (struct wireguard_device *)arg;
	size_t max_data_pkt_size = 2048;
	struct derp_pkt *data_pkt = mem_malloc(max_data_pkt_size);
	if (data_pkt == NULL) {
		ESP_LOGE(TAG, "Failed to allocate memory for rx packet buf");
		goto end;
	}

	ESP_LOGI(TAG, "Read from network worker starting");

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
		struct pbuf data;
		data.payload = data_pkt->data.data;
		data.tot_len = read_len - offsetof(struct derp_pkt, data.data);
		data.len = read_len - offsetof(struct derp_pkt, data.data);

		// Always use localhost address
		struct ip_addr addr = {0};
		ipaddr_aton("127.0.0.1", &addr);

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
	char *read_buf = NULL;
	int err = ESP_FAIL;

	if (!dev->derp.endpoint.addr_len) {
		ESP_LOGE(TAG, "No DERP server set");
		goto ret;
	}

	ESP_LOGI(TAG, "Allocating new socket");
	dev->derp.tls = esp_tls_init();

	if (dev->derp.tls == NULL) {
		ESP_LOGE(TAG, "Failed to allocate socket");
		goto ret;
	}

	// Prepare TLS configuration
	esp_tls_cfg_t tls_cfg = {0};
	tls_cfg.cacert_buf = (unsigned char*) cacert;
	tls_cfg.cacert_bytes = strlen(cacert) + 1;
	tls_cfg.skip_common_name = true;

	// Try to establish TLS connection
	err = esp_tls_conn_new_sync(dev->derp.endpoint.addr, dev->derp.endpoint.addr_len, dev->derp.endpoint.port, &tls_cfg, dev->derp.tls);
	if (err == -1) {
		ESP_LOGE(TAG, "Failed to attempt TLS connection address %d", err);
		goto ret;
	}
	ESP_LOGI(TAG, "Connection Established!");

	dev->derp.conn_state = CONN_STATE_TCP_CONNECTING;
	char http_req[128];
	// Prepare HTTP upgrade request
    snprintf(http_req, 128,
        "GET /derp HTTP/1.1\r\n"
	    "Host: %s\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: WebSocket\r\n"
        "User-Agent: esp32/v1.0.0 esp\r\n\r\n",
        dev->derp.endpoint.addr);
	err = esp_tls_conn_write(dev->derp.tls, http_req, strlen(http_req));
	if (err < 0) {
		ESP_LOGE(TAG, "Failed to send HTTP upgrade request %d", err);
		goto ret;
	}

	ESP_LOGI(TAG, "Request transmitted!");

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

	ESP_LOGI(TAG, "Server has switched protocols");

	// Verify length of the response
	char *http_resp_end = strstr(read_buf, "\r\n\r\n");
	if (http_resp_end == NULL) {
		ESP_LOGE(TAG, "HTTP response end not found");
		goto ret;
	}
	http_resp_end += 4;

	size_t http_resp_len = http_resp_end - read_buf;
	if (read_len - http_resp_len < 45) {
		ESP_LOGE(TAG, "Server Key packet too short %d", http_resp_len);
		goto ret;
	}

	struct derp_pkt *server_key_pkt = (struct derp_pkt*) http_resp_end;
	ESP_LOGI(TAG, "ServerKey received");

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

	ESP_LOGI(TAG, "Attempting to encrypt the plaintext for client-key");
	err = crypto_box_easy(client_key_pkt.client_key.ciphertext,
			(const unsigned char*) plaintext, strlen(plaintext),
			client_key_pkt.client_key.nonce,
			server_key_pkt->server_key.server_public_key,
			dev->private_key);
	if (err != 0) {
		ESP_LOGE(TAG, "Failed to encrypt plaintext for client-key packet: %d", err);
		goto ret;
	}

	ESP_LOGI(TAG, "Attempting to transmit ClientKey message");
	err = esp_tls_conn_write(dev->derp.tls, &client_key_pkt, 106);
	if (err < 0) {
		ESP_LOGE(TAG, "Failed to send HTTP upgrade request %d", err);
		goto ret;
	}

	ESP_LOGI(TAG, "Reading ServerInfo message");
	read_len = esp_tls_conn_read(dev->derp.tls, read_buf, read_buf_size);
	if (read_len < 5) {
		ESP_LOGE(TAG, "Failed to receive ServerInfo message %d", err);
		goto ret;
	}
	struct derp_pkt *serverInfo = (struct derp_pkt*)read_buf;
	if (serverInfo->type != 3) {
		ESP_LOGE(TAG, "Unexpected packet during DERP handshake %d", serverInfo->type);
		goto ret;
	}

	mem_free(read_buf);
	read_buf = NULL;

	ESP_LOGI(TAG, "DERP connection established succesfully");

	dev->derp.conn_state = CONN_STATE_DERP_READY;

	read_from_network_worker(dev);

ret:
	if (read_buf) {
		mem_free(read_buf);
	}

	if (dev->derp.conn_state == CONN_STATE_DERP_READY) {
		connection_attempt_control = DoNotAttempt;
	} else {
		connection_attempt_control = AttemptNow;
	}

	vTaskDelete(NULL);
}

void set_derp_endpoint(struct wireguard_device *dev, const char* ip, int port) {
	ESP_LOGI(TAG, "Updating derp with %s", ip);
	dev->derp.endpoint.addr_len = strlen(ip);
	memcpy(dev->derp.endpoint.addr, ip, dev->derp.endpoint.addr_len);
	dev->derp.endpoint.addr[dev->derp.endpoint.addr_len] = '\0';
	dev->derp.endpoint.port = port;
	connection_attempt_control = AttemptNow;
}

err_t derp_initiate_new_connection(struct wireguard_device *dev) {
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
	packet->length_be = BE32_TO_LE32((WIREGUARD_PUBLIC_KEY_LEN + 1 + payload->tot_len));
	memcpy(packet->data.peer_public_key, peer->public_key, WIREGUARD_PUBLIC_KEY_LEN);
	packet->data.subtype = 0x00;
	pbuf_copy_partial(payload, packet->data.data, payload->tot_len, 0);

	if (xTaskNotify(dev->derp.read_interface_worker, (uint32_t)packet, eSetValueWithoutOverwrite) != pdPASS) {
		mem_free(packet);
		ESP_LOGE(TAG, "Worker busy -> dropping packet");
	}

	return ESP_OK;
}
