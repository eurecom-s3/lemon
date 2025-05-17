# LEMON - An eBPF Memory Dump Tool for x64 and ARM64 Linux and Android

LEMON is a Linux and Android memory dump tool that utilizes eBPF to capture the entire physical memory of a system and save it in LiME format, compatible with forensic tools such as Volatility 3.

LEMON is available as a precompiled static binary for x64 and ARM64, leveraging a CO-RE (Compile Once, Run Everywhere) eBPF program. This allows analysts to dump system memory without compiling anything on the target machine, checking for specific compatibility with installed libraries and kernel versions, and without requiring kernel headers. It is particularly useful in scenarios where loading kernel modules is not possible (e.g., due to Secure Boot) or when `{/proc, /dev}/kcore` is unavailable.

## Usage

Copy the `lemon` binary to the target machine and initiate a memory dump on disk with:

```sh
./lemon.ARCH -d memory_on_disk.dump
```

For a network dump instead use:

```sh
./lemon.ARCH -n TARGET_IP -p TARGET_PORT
```
while on the target machine
```sh
nc -l -p TARGET_PORT >  memory_by_net.dump
```

This generates a `memory.dump` file in LiME format, containing all physical memory pages. Since running eBPF programs typically requires root privileges, LEMON must be executed as `root` or with an appropriate `sudo` configuration.

## Build

Precompiled static binaries are available in this repository (check the Github actions tab). Analysts can also compile LEMON themselves, either dynamically or statically. The dynamic version requires the presence of `libbpf`, `libz`, `libelf`, and `libzstd` on the target machine, whereas the static version has no external dependencies. Note that the build machine **MUST** have the same CPU architecture as the target.

### Dependencies

To build LEMON, install the necessary dependencies on the analyst's machine. The following command sets up all required packages on an Ubuntu 24.04 system:

```sh
sudo apt install -y git make clang llvm libbpf-dev libcap-dev linux-tools-generic
```

Other distributions provide equivalent packages, which at minimum allow compiling the dynamic version via the system package manager.

### Build Procedure

1. **Clone the repository:**

   ```sh
   git clone git@github.com:eurecom-s3/lemon.git && cd lemon
   ```

2. **Generate a valid **`vmlinux.h`** file (only for CO-RE builds):**

   Copy a valid `vmlinux.h` file into `lemon/` or generate one with:

   ```sh
   make vmlinux
   ```

3. **Compile:**

   - Dynamic binary (set CORE=0 for non CO-RE binaries):
     ```sh
     make CORE=1
     ```
   - Static binary:
     ```sh
     make CORE=1 static
     ```

## Limitations

- The kernel must support eBPF (obviously!).
- Kernel lockdown must not be in confidentiality mode (or must allow `bpf_probe_read_kernel()`).

## TODO

- [X] Support non CO-RE kernels ([this library](https://github.com/eunomia-bpf/bpf-compatible) might help)
- [X] Insert checks on kernel versions and ```CONFIG_``` kernel options to extend support
- [X] Implement network dump (TCP)
- [X] Implement dump with reduced granule if page fail to be read
- [X] Introduce support for kernels that do not have uprobes
- [ ] Support other CPU architectures (x32, ARM32, MIPS, PowerPC, POWER, RISC-V)
- [ ] Use of `_stext` in x64 to bypass missing `CONFIG_KALLSYMS_ALL`
- [ ] Bruteforce scanning (?) for page containing same data of  `_stext` page in ARM64 to bypass missing `CONFIG_KALLSYMS_ALL`
- [ ] Implement network dump (UDP)

## Notes

### eBPF cronology
- Introduction of eBPF: 3.15
- Introduction of Array maps 3.19
- Introduction of kProbe/uProbe support 4.1
- Introduction of tracepoint support (syscalls tracing) 4.7
- Introduction of XDP 4.8
- Android 9 support eBPF: 4.9
- Introduction of BTF 4.18
- Introduction mmap() support for array maps 5.5
- !!! Introduction of read_kernel() 5.5 <==== Minimum Lemon target version
- Introduction of ring_buffer 5.8
- Android 13 support BTF 5.15
- Introduction of SYSCALL program type 5.15
- Introduction of kallsyms() in ebpf 5.16
