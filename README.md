# sysinfo.sh - Linux System Configuration Info

`sysinfo.sh` is a comprehensive Bash script that gathers and displays a wide range of system configuration information for Linux environments. It is designed to be a powerful tool for system administrators, developers, and power users who need a quick and detailed overview of a system's setup.

The script is optimized for various init systems, including `systemd`, `SysVinit`, and `OpenRC`, and provides enhanced metrics and debugging capabilities.

## Features

- **Comprehensive System Analysis**: Gathers information across multiple system areas, including hardware, memory, storage, network, core system components, and virtualization.
- **Multi-Init System Support**: Compatible with modern and legacy init systems like `systemd`, `SysVinit`, and `OpenRC`.
- **Extensive Package Manager Detection**: Identifies multiple package managers and counts installed packages, similar to tools like `neofetch`. This includes native managers (`pacman`, `dpkg`, `dnf`, etc.), universal managers (`flatpak`, `snap`), and language-specific managers (`pip`, `npm`, `cargo`).
- **Advanced Debugging Tools**: Includes multiple debug levels (`--debug`, `--verbose`, `--trace`) for troubleshooting and script development.
- **Color-Coded Output**: Presents information in a clear, human-readable format with optional color coding for better readability.
- **Rootless Execution**: Designed to run without root privileges for most of its functions.
- **Section-Specific Output**: Allows users to display specific sections of information (e.g., `--system`, `--net`, `--hardware`).

## Requirements

- **Operating System**: Linux
- **Shell**: Bash
- **Core Utilities**: Standard Linux command-line utilities (e.g., `grep`, `awk`, `sed`, `ip`).

## Installation

To use the script, simply make it executable:

```bash
chmod +x sysinfo.sh
```

## Usage

You can run the script without any arguments to get a full system report:

```bash
./sysinfo.sh
```

### Options

The script supports several command-line options to customize its behavior:

| Option             | Description                                                 |
| ------------------ | ----------------------------------------------------------- |
| `-n`, `--no-color` | Disable colored output.                                     |
| `-d`, `--debug`    | Enable debug mode to show function calls and logic flow.    |
| `-v`, `--verbose`  | Enable verbose mode to show detailed command outputs.       |
| `-t`, `--trace`    | Enable command tracing (implies debug and verbose).         |
| `-h`, `--help`     | Show the help message.                                      |
| `--version`        | Show the script version.                                    |

### Sections

You can choose to display only specific sections of the system report:

| Section            | Description                                                 |
| ------------------ | ----------------------------------------------------------- |
| `--full`           | (Default) Show all sections.                                |
| `--system`         | Show the System Overview section.                           |
| `--hardware`       | Show the Hardware section.                                  |
| `--mem`            | Show the Memory & Storage section.                          |
| `--core`           | Show the Core System Components section.                    |
| `--net`            | Show the Network Interfaces section.                        |
| `--packages`       | Show the Package Managers section.                          |
| `--alternatives`   | Show the Alternative Components section.                    |
| `--virt`           | Show the Virtualization & Containers section.               |

### Examples

**Run with default options (full report with colors):**
```bash
./sysinfo.sh
```

**Run without colors (useful for piping to files):**
```bash
./sysinfo.sh --no-color
```

**Show only the system and hardware sections:**
```bash
./sysinfo.sh --system --hardware
```

**Enable full debug, verbose, and trace modes:**
```bash
./sysinfo.sh -d -v -t
```

## Output Sections

The script organizes system information into the following sections:

- **SYSTEM OVERVIEW**: General information like hostname, distribution, kernel version, architecture, uptime, and default shell.
- **HARDWARE**: CPU and GPU details.
- **MEMORY & STORAGE**: RAM and swap usage, along with a summary of disk usage and key partitions.
- **CORE SYSTEM COMPONENTS**: Information about the init system, network manager, time synchronization service, firewall, DNS resolver, and other core services.
- **NETWORK INTERFACES**: Lists LAN, WLAN, and virtual network interfaces with their IP addresses and status.
- **PACKAGE MANAGERS**: The primary package manager and a summary of all detected package managers with package counts.
- **ALTERNATIVE COMPONENTS**: A list of installed (but not necessarily active) alternatives for network management, firewalls, and time sync.
- **VIRTUALIZATION & CONTAINERS**: KVM status, detected container runtimes (Docker, Podman, LXC), and a list of running containers.

## Contributing

Contributions are welcome! If you have suggestions for improvements or find any issues, please open an issue or submit a pull request on the project's repository.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
