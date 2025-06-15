# Optional build flags (can be overridden via command line)
STATIC ?=
MODE ?= core

# Validate MODE value
VALID_MODES := core nocore nocoreuni
ifeq ($(filter $(MODE),$(VALID_MODES)),)
	$(error Invalid MODE value: $(MODE). Valid values are: $(VALID_MODES))
endif

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
CLANG := clang
CFLAGS := -Wall -O2 -D$(TARGET_ARCH)
LDFLAGS := -lbpf -lelf -lz -lzstd -lcap

# MODE-based flags
ifeq ($(MODE), core)
	CFLAGS += -DCORE
	BPF_FLAGS := -DCORE
	NEEDS_VMLINUX := 1 
else ifeq ($(MODE), nocore)
	CFLAGS += -DNOCORE
	BPF_FLAGS := -DNOCORE
	NEEDS_VMLINUX := 0
else ifeq ($(MODE), nocoreuni)
	CFLAGS += -DNOCOREUNI
	BPF_FLAGS := -DNOCOREUNI
	NEEDS_VMLINUX := 0
endif

# Static linking flag
ifeq ($(STATIC), 1)
	LDFLAGS += -static
endif

# Files
LOADER_SRCS := lemon.c cpu_stealer.c mem.c dump.c disk.c net.c capabilities.c
LOADER_BIN := lemon.$(MODE).$(ARCH)
BPF_SRC := ebpf/mem.ebpf.c
BPF_OBJ := ebpf/mem.ebpf.o
BPF_SKEL := ebpf/mem.ebpf.skel.h

# Default target: If core mode is enabled, make vmlinux first, then compile eBPF and loader
all: clean $(if $(filter 1,$(NEEDS_VMLINUX)), vmlinux) $(BPF_OBJ) $(LOADER_BIN)

# Build eBPF object and generate skeleton
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -target bpf -D$(TARGET_ARCH) $(BPF_FLAGS) -I/usr/include/linux -I/usr/include/$(ARCH)-linux-gnu \
		-Wall -O2 -g -c $< -o $@
	llvm-strip -g $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Build the loader (compiled before eBPF program)
$(LOADER_BIN): $(LOADER_SRCS)
	$(CLANG) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	objcopy --strip-all --keep-symbol=read_kernel_memory $@ $@_strip
	mv $@_strip $@

# Dump vmlinux BTF as C header (only if core mode is enabled)
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Clean
clean:
	rm -f $(LOADER_BIN) $(BPF_OBJ) $(BPF_SKEL) vmlinux.h

# Help target
help:
	@echo "Available targets:"
	@echo "  all     - Build the project (default, core, dynamic linked)"
	@echo "  static  - Build with static linking"
	@echo "  clean   - Clean build artifacts"
	@echo "  vmlinux - Generate vmlinux.h (for core mode)"
	@echo "  help    - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  MODE    - Build mode (default: core)"
	@echo "            core: Use eBPF CO-RE with vmlinux.h"
	@echo "            nocore: Compile in legacy no CO-RE mode using installed Linux headers"
	@echo "            nocoreuni: Compile in no CO-RE mode using universal header included"
	@echo "  STATIC  - Enable static linking (default: disabled)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                   # Build with core mode"
	@echo "  make MODE=nocore       # Build in legacy no CO-RE mode using installed Linux headers"
	@echo "  make MODE=nocoreuni    # Build in no CO-RE mode using universal header included"
	@echo "  make STATIC=1 MODE=nocore  # Static build legacy NO CO-RE"

# Show current configuration
config:
	@echo "Current configuration:"
	@echo "  MODE: $(MODE)"
	@echo "  STATIC: $(if $(STATIC),enabled,disabled)"
	@echo "  ARCH: $(ARCH)"
	@echo "  TARGET_ARCH: $(TARGET_ARCH)"
	@echo "  NEEDS_VMLINUX: $(NEEDS_VMLINUX)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  BPF_FLAGS: $(BPF_FLAGS)"
	@echo "  LDFLAGS: $(LDFLAGS)"

.PHONY: all static clean vmlinux help config