## About Lemon

LEMON is a research-oriented tool for Linux memory acquisition using eBPF. Please keep in mind:
- Support is provided on a best-effort basis
- Be precise, technical, and respectful when reporting issues


## Prerequisites

Please confirm the following before submitting:

- [ ] I am running the latest version of LEMON
- [ ] I have read the README and setup instructions carefully
- [ ] I checked existing issues to ensure this has not already been reported
- [ ] I verified my configuration (kernel version, ebpf, privileges, permissions, etc.)

## Expected Behavior

Describe clearly what you expected LEMON to do.

Example:
- Successful build
- Correct dump of process memory

## Current Behavior

What actually happens?

Include:
- Errors
- Unexpected output
- Partial or failed memory dumps


## Failure Information

### Context

Provide detailed environment information.

| Question                  | Answer |
|---------------------------|--------|
| Linux distribution       | (e.g., Ubuntu 22.04, Android 16) |
| Kernel version           | (`uname -r`) |
| Architecture             | (e.g., x86_64, ARM) |
| LEMON version      | (`lemon_bin --version`) |


### Steps to Reproduce

Provide a minimal, reproducible sequence when possible:

1. Setup environment (device specs, dependencies)
2. Compile/build LEMON - optional
3. Run command(s)
4. Observe failure


### Failure Logs

Please include when possible inside code blocks:

- Full terminal output of lemon run with the `--debug` option
- When available, `last_kmesg` logs (or dumpstate file located under `/data/log` if samsung)
- Build/compile logs
- Any stack traces or error messages
