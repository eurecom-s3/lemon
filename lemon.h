#define PAGE_SIZE               4 * 1024                // The majority of CPU archs support this as little granule
#define HUGE_PAGE_SIZE          2 * 1024 * 1024         // Same for huge pages
#define TCP_PAYLOAD_SIZE        1024                    // Payload size using in network dump
#define MAX_TCP_PAYLOAD_SIZE    1440                    // Maxium TCP payload size in IPv6 (less than IPv4)

enum CMD_CODE {
    SEND_PKT,       // Send packet without altering it
    MODIFY_PKT,     // Replace the content of the packet with memory content
};

struct ram_range {
    uintptr_t start;
    uintptr_t end;
};

struct ram_regions {
    struct ram_range *regions;
    size_t num_regions;
};

typedef struct __attribute__((packed)) {
    unsigned int magic;
    unsigned int version;
    unsigned long long s_addr;
    unsigned long long e_addr;
    unsigned char reserved[8];
} lime_header;

struct read_mem_result {
    int ret_code;
    uint8_t buf[HUGE_PAGE_SIZE];
};