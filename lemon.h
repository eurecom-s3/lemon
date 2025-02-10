#define PAGE_SIZE 4 * 1024              // The majority of CPU archs support this as little granule
#define HUGE_PAGE_SIZE 2 * 1024 * 1024  // Same for huge pages

struct ram_range {
    uintptr_t start;
    uintptr_t end;
};

typedef struct __attribute__((packed)) {
    unsigned int magic;
    unsigned int version;
    unsigned long long s_addr;
    unsigned long long e_addr;
    unsigned char reserved[8];
} lime_header;

struct ebpf_buf {
    int ret_code;
    uint8_t buf[HUGE_PAGE_SIZE];
};