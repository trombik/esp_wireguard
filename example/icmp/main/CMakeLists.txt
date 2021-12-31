idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES wireguard-lwip-esp32 nvs_flash)
