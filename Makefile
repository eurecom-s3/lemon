STATIC ?=
CORE ?=

ARCH := $(shell uname -m)

# For now supports only x86-64 and ARM64
ifeq ($(ARCH), x86_64)
    TARGET_ARCH := __TARGET_ARCH_x86
else ifeq ($(ARCH), aarch64)
    TARGET_ARCH := __TARGET_ARCH_arm64
endif

all: CORE=-D CORE 
all: ebpf loader

static: CORE=1 
static: STATIC=-static 
static: all

loader:
	clang $(CORE) -D $(TARGET_ARCH) -Wall -O2 lemon.c mem.c disk.c -o lemon -lbpf -lelf -lz -lzstd $(STATIC)

ebpf:
	clang -target bpf $(CORE) -D $(TARGET_ARCH) -I/usr/include/linux -I/usr/include/$(ARCH)-linux-gnu \
	      -Wall -O2 -g -c lemon.ebpf.c -o lemon.ebpf.o
	llvm-strip -g lemon.ebpf.o
	bpftool gen skeleton lemon.ebpf.o > lemon.ebpf.skel.h

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f *.o *.bc vmlinux.h lemon.ebpf.skel.h lemon
