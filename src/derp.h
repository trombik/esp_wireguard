#ifndef _DERP_H_
#define _DERP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "wireguard.h"

#define BE32_TO_LE32(num) ((num & 0xFF) << 24) | ((num & 0xFF00) << 8) | ((num >> 8) & 0xFF00) | (num >> 24)

struct __attribute__((packed)) derp_pkt {
    uint8_t type;
    uint32_t length_be; // In Big Endian
    union {
        struct {
            uint8_t magic[8];
            uint8_t server_public_key[32];
        } server_key;
        struct {
            uint8_t client_public_key[32];
            uint8_t nonce[24];
            uint8_t ciphertext[45];
        } client_key;
    };
};

// A function called periodically to manage
// state for DERP connection
void derp_tick(struct wireguard_device *dev);

err_t derp_initiate_new_connection(struct wireguard_device *dev);
err_t derp_shutdown_connection(struct wireguard_device *dev);

// State transition functions
err_t derp_send_http_upgrade_request(struct wireguard_device *dev);
err_t derp_key_exchange(struct wireguard_device *dev, struct pbuf *buf);
err_t derp_data_message(struct wireguard_device *dev, struct derp_pkt *packet);

#ifdef __cplusplus
}
#endif


#endif /* _DERP_H_ */
