# tuxwall

A Linux firewall configuration tool/script for managing and applying firewall rules on Linux systems.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

tuxwall is a Linux firewall management tool that simplifies the setup, configuration, and management of firewall rules. It provides a straightforward interface for defining and applying network filtering policies on Linux systems.

---

## Requirements

- Linux (kernel 2.4+ recommended)
- `iptables` or `nftables` (depending on configuration)
- Root / sudo privileges
- `bash` 4.0 or newer

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/tuxwall.git
cd tuxwall
```

### 2. Make the script executable

```bash
chmod +x tuxwall.sh
```

### 3. Install system-wide (optional)

```bash
sudo cp tuxwall.sh /usr/local/bin/tuxwall
sudo chmod +x /usr/local/bin/tuxwall
```

### 4. Install the configuration file

```bash
sudo mkdir -p /etc/tuxwall
sudo cp tuxwall.conf /etc/tuxwall/tuxwall.conf
```

---

## Configuration

The main configuration file is located at `/etc/tuxwall/tuxwall.conf` (or `./tuxwall.conf` for local use).

### Configuration Options

| Option             | Description                                      | Default         |
|--------------------|--------------------------------------------------|-----------------|
| `ALLOWED_PORTS`    | Comma-separated list of allowed inbound ports    | `22,80,443`     |
| `BLOCKED_IPS`      | Comma-separated list of IPs to block             | (empty)         |
| `DEFAULT_POLICY`   | Default policy for incoming traffic (`ACCEPT` / `DROP`) | `DROP`   |
| `ENABLE_LOGGING`   | Enable firewall event logging (`yes` / `no`)     | `yes`           |
| `LOG_FILE`         | Path to the log file                             | `/var/log/tuxwall.log` |
| `INTERFACE`        | Network interface to apply rules to              | `eth0`          |

### Example `tuxwall.conf`

```ini
# tuxwall Configuration File

INTERFACE=eth0
DEFAULT_POLICY=DROP
ALLOWED_PORTS=22,80,443
BLOCKED_IPS=
ENABLE_LOGGING=yes
LOG_FILE=/var/log/tuxwall.log
```

---

## Usage

```
Usage: tuxwall [COMMAND] [OPTIONS]

Commands:
  start       Apply firewall rules from configuration
  stop        Flush all rules and set policies to ACCEPT
  restart     Stop and re-apply all rules
  status      Show current firewall rules
  reload      Reload configuration without full restart
  help        Show this help message

Options:
  -c <file>   Specify a custom configuration file
  -v          Verbose output
```

### Starting the firewall

```bash
sudo tuxwall start
```

### Stopping the firewall

```bash
sudo tuxwall stop
```

### Checking status

```bash
sudo tuxwall status
```

### Using a custom config file

```bash
sudo tuxwall start -c /path/to/custom.conf
```

---

## Examples

### Allow only SSH and HTTPS

```ini
ALLOWED_PORTS=22,443
DEFAULT_POLICY=DROP
```

### Block a specific IP address

```ini
BLOCKED_IPS=192.168.1.100,10.0.0.5
```

### Apply rules to a specific interface

```ini
INTERFACE=ens3
```

---

## Troubleshooting

### Rules not applying

- Ensure you are running with `sudo` or as root.
- Verify `iptables` or `nftables` is installed: `which iptables` or `which nft`.
- Check the configuration file path and syntax.

### Locked out of SSH

If you accidentally block SSH access:
1. Access the machine via console or out-of-band management.
2. Run `sudo tuxwall stop` to flush all rules.
3. Update your config to include port `22` in `ALLOWED_PORTS`.
4. Run `sudo tuxwall start` to re-apply rules.

### Viewing logs

```bash
sudo tail -f /var/log/tuxwall.log
```

### Checking current iptables rules

```bash
sudo iptables -L -n -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
