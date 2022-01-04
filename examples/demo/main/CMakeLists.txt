idf_component_register(SRCS "main.c" "sync_time.c"
                    INCLUDE_DIRS "."
                    REQUIRES wireguard-lwip-esp-idf nvs_flash)
