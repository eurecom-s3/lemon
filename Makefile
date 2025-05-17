# Optional build flags (can be overridden via command line)
STATIC ?=  # Default is not static
CORE ?= 1  # Default to CORE=1, can be disabled via CORE=0

# System and architecture detection
ARCH := $(shell uname -m)
BPFTOOL := bpftool

# Detect architecture for eBPF
ifeq ($(ARCH), x86_64)
    TARGET_ARCH := __TARGET_ARCH_x86
else ifeq ($(ARCH), aarch64)
    TARGET_ARCH := __TARGET_ARCH_arm64
else
    $(error Unsupported architecture: $(ARCH))
endif

# Define compiler and flags
CLANG   := clang
CFLAGS  := -Wall -O2 -D$(TARGET_ARCH)
LDFLAGS := -lbpf -lelf -lz -lzstd -lcap

# Conditional flags
ifeq ($(CORE), 1)
    CFLAGS  += -DCORE
    BPF_CORE_FLAG := -DCORE
endif

ifeq ($(STATIC), 1)
    LDFLAGS += -static
endif

# Files
LOADER_SRCS := lemon.c cpu_stealer.c mem.c dump.c disk.c net.c capabilities.c
LOADER_BIN  := lemon.$(ARCH)
BPF_SRC     := ebpf/mem.ebpf.c
BPF_OBJ     := ebpf/mem.ebpf.o
BPF_SKEL    := ebpf/mem.ebpf.skel.h

# Default target: If CORE is enabled, make vmlinux first, then compile eBPF and loader
all: clean $(if $(filter 1,$(CORE)), vmlinux) $(BPF_OBJ) $(LOADER_BIN)

# Build eBPF object and generate skeleton
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -target bpf -D$(TARGET_ARCH) $(BPF_CORE_FLAG) -I/usr/include/linux -I/usr/include/$(ARCH)-linux-gnu \
	        -Wall -O2 -g -c $< -o $@
	llvm-strip -g $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Build the loader (compiled before eBPF program)
$(LOADER_BIN): $(LOADER_SRCS)
	$(CLANG) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	objcopy --strip-all --keep-symbol=read_kernel_memory $@ $@_strip
	mv $@_strip $@

# Dump vmlinux BTF as C header (only if CORE is enabled)
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Static target for convenience
static:
	$(MAKE) STATIC=1

# Clean
clean:
	rm -f $(LOADER_BIN) $(BPF_OBJ) $(BPF_SKEL) vmlinux.h

.PHONY: all static clean vmlinux
