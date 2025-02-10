# LEMON - An eBPF Memory Dump Tool for x64 and ARM64 Linux

LEMON is a Linux memory dump tool that utilizes eBPF to capture the entire physical memory of a system and save it in LiME format, compatible with forensic tools such as Volatility 3.

LEMON is available as a precompiled static binary for x64 and ARM64, leveraging a CO-RE (Compile Once, Run Everywhere) eBPF program. This allows analysts to dump system memory without compiling anything on the target machine, checking for specific compatibility with installed libraries and kernel versions, and without requiring kernel headers. It is particularly useful in scenarios where loading kernel modules is not possible (e.g., due to Secure Boot) or when `{/proc, /dev}/kcore` is unavailable.

## Usage

Copy the `lemon` binary to the target machine and initiate the memory dump with:

```sh
./lemon memory.dump
```

This generates a `memory.dump` file in LiME format, containing all physical memory pages. Since running eBPF programs typically requires root privileges, LEMON must be executed as `root` or with an appropriate `sudo` configuration.

## Build

Precompiled static binaries (`static_bins/lemon.x64` and `static_bins/lemon.arm64`) are available in this repository. Analysts can also compile LEMON themselves, either dynamically or statically. The dynamic version requires the presence of `libbpf`, `libz`, `libelf`, and `libzstd` on the target machine, whereas the static version has no external dependencies. Note that the build machine **MUST** have the same CPU architecture as the target.

### Dependencies

To build LEMON, install the necessary dependencies on the analyst's machine. The following command sets up all required packages on an Ubuntu 24.04 system:

```sh
sudo apt install -y git make clang llvm libbpf-dev linux-tools-generic
```

Other distributions provide equivalent packages, which at minimum allow compiling the dynamic version via the system package manager.

### Build Procedure

1. **Clone the repository:**

   ```sh
   git clone git@github.com:eurecom-s3/lemon.git && cd lemon
   ```

2. **Generate a valid **``** file:**

   Copy a valid `vmlinux.h` file into `lemon/` or generate one with:

   ```sh
   make vmlinux
   ```

3. **Compile:**

   - Dynamic binary:
     ```sh
     make
     ```
   - Static binary:
     ```sh
     make static
     ```

## Limitations

- The kernel must support eBPF (obviously!).
- Kernel lockdown must not be in confidentiality mode (or must allow `bpf_probe_read_kernel()`).
- Currently, LEMON supports only CO-RE kernels and on-disk memory dumps.

## TODO

- [ ] Support non CO-RE kernels
- [ ] Insert checks on kernel versions and ```CONFIG_``` kernel options to extend support
- [ ] Implement network dump
- [ ] Support other CPU architectures (x32, ARM32, MIPS, PowerPC, POWER, RISC-V)