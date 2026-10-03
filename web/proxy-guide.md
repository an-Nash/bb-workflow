# MITM Proxy Guide for Linux

A comprehensive guide for setting up and running Man-in-the-Middle (MITM) proxies on Linux, written for AI agents and security practitioners.

---

## What is a MITM Proxy?

A MITM (Man-in-the-Middle) proxy intercepts and logs traffic between a client and a server. For HTTPS traffic, the proxy generates forged certificates signed by its own root Certificate Authority (CA) and presents them to the client. If the client trusts that root CA, it accepts the forged certificate and establishes TLS with the proxy, allowing the proxy to decrypt, inspect, and modify the plaintext data.

**Use cases**: Debugging APIs, mobile app reverse-engineering, security testing (with permission), and network analysis.

**⚠️ Legal Note**: Intercepting traffic without explicit permission is unethical and often illegal. Only use these tools on systems you own or have written authorization to test.

---

## Popular MITM Proxy Tools for Linux

| Tool | Description | Best For |
|------|-------------|----------|
| **mitmproxy** | Open-source, CLI + web UI, Python-scriptable | General-purpose, automation, CLI enthusiasts |
| **Burp Suite** | Security-focused GUI tool | Web application security testing |
| **Charles Proxy** | Paid GUI app | Beginners, easy setup |
| **InterceptSuite** | TCP/TLS/DTLS/UDP MITM | Multi-protocol interception |
| **SSLsplit** | Transparent SSL/TLS interception | Penetration testing, red teaming |
| **warcprox** | WARC-writing HTTP/S proxy | Web archiving |

**mitmproxy** is the most widely used and will be the primary focus of this guide.

---

## Installing mitmproxy on Linux

### Method 1: Standalone Binaries (Recommended)

The recommended way to install mitmproxy on Linux is to download the standalone binaries from mitmproxy.org:

```bash
# Download and extract (replace X.X.X with version)
wget https://snapshots.mitmproxy.org/X.X.X/mitmproxy-X.X.X-linux-x86_64.tar.gz
tar -xzf mitmproxy-*-linux-x86_64.tar.gz

# Move to PATH
sudo mv mitmproxy mitmdump mitmweb /usr/local/bin/

# Verify installation
mitmproxy --version
```

The standalone binaries include a self-contained Python environment and all dependencies, so Python is not required.

### Method 2: Distribution Packages

Community-maintained packages are available for major distributions:

```bash
# Debian/Ubuntu/Kali
sudo apt install mitmproxy

# Arch Linux
sudo pacman -S mitmproxy

# Fedora
sudo dnf install mitmproxy
```

> **Note**: Distribution packages may lag behind official releases.

### Method 3: pip/pipx (PyPI)

For custom addons and Python integration:

```bash
pip install mitmproxy
# or
pipx install mitmproxy
```

> **⚠️ Local Mode Requirement**: mitmproxy's local capture mode on Linux requires **kernel ≥ 6.8**. Check your kernel with `uname -r`.

---

## Basic mitmproxy Usage

mitmproxy provides three main commands:

| Command | Description |
|---------|-------------|
| `mitmproxy` | Interactive console UI |
| `mitmdump` | Command-line only (non-interactive) |
| `mitmweb` | Web-based UI |

### Start the Proxy

```bash
# Default port 8080 with console UI
mitmproxy

# Custom port
mitmproxy --listen-port 9000

# Web UI
mitmweb

# Command-line only (useful for automation)
mitmdump
```

### Set Proxy Environment Variables

For applications that respect standard proxy variables:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export ALL_PROXY=http://localhost:8080
```

For Python applications using `requests`:

```bash
export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

### Install the CA Certificate

The mitmproxy CA certificate is automatically generated on first run at `~/.mitmproxy/mitmproxy-ca-cert.pem`.

To install it system-wide:

```bash
# For Debian/Ubuntu
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

For browser-based interception, import the certificate manually in your browser's certificate settings.

---

## Advanced MITM Modes

### 1. Local Capture Mode (Process-Specific)

mitmproxy 11.1+ supports eBPF-based local capture on Linux, allowing interception of specific applications without system-wide proxy settings:

```bash
# Capture all local traffic (requires sudo, kernel 6.8+)
mitmproxy --mode local

# Capture only cURL traffic
mitmproxy --mode local:curl

# Capture specific process by name
mitmproxy --mode local:firefox
```

**How it works**: mitmproxy spawns an eBPF redirector as a privileged subprocess with `sudo` to redirect traffic at the kernel level. The redirection is process-scoped—it only intercepts traffic from the specified process, not your browser, curl, or other apps.

> **Troubleshooting**: If you see "eBPF program failed to load", check your kernel version with `uname -r`—you need ≥ 6.8.

### 2. Transparent Proxy Mode

Transparent proxying intercepts network traffic at the network layer without client configuration—ideal for analyzing mobile apps, embedded devices, or clients that cannot be configured to use a proxy.

#### Step 1: Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make persistent
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf
```

#### Step 2: Disable ICMP Redirects

```bash
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
```

#### Step 3: Configure iptables

Replace `eth0` with your network interface:

```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
sudo ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

**Persist rules**:

```bash
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

#### Step 4: Start mitmproxy in Transparent Mode

```bash
mitmproxy --mode transparent --showhost
```

The `--showhost` flag uses the Host header for URL display.

#### Step 5: Configure Client Device

Set the client device's gateway to the machine running mitmproxy and install the mitmproxy CA certificate on the client.

### 3. ARP Spoofing + Transparent Proxy (Network-Wide)

For intercepting traffic from all clients on a local network, tools like `arp-mitm-proxy` combine ARP spoofing with mitmproxy:

```bash
# Install dependencies
sudo apt update
sudo apt install arp-scan dsniff mitmproxy net-tools

# Clone and run
git clone https://github.com/tonilkumar/arp-mitm-proxy.git
cd arp-mitm-proxy
chmod +x advanced_arp_spoof.sh
sudo ./advanced_arp_spoof.sh
```

This auto-detects the network interface, scans all devices, performs ARP spoofing, and sets up transparent proxying via mitmproxy.

---

## Other MITM Proxy Tools

### Burp Suite (Security Focus)

Burp Suite's proxy listens on `127.0.0.1:8080` by default:

1. Download the Linux installer from PortSwigger
2. Make executable: `chmod +x burpsuite_community_linux_v*.sh`
3. Run the installer
4. Open Burp Suite → Proxy → Options → confirm listener on `127.0.0.1:8080`

### InterceptSuite (Multi-Protocol)

For TCP/TLS/DTLS/UDP traffic with TLS upgrade support (STARTTLS, PostgreSQL, etc.):

- Linux: Use ProxyCap, tsocks, Proxychains, or iptables for system-wide SOCKS5 support

---

## Automation & Scripting

### Python Scripting with mitmproxy

mitmproxy can be extended with Python addons. Example addon structure:

```python
# ~/.mitmproxy/addons/my_addon.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Modify request
    flow.request.headers["X-Custom"] = "value"

def response(flow: http.HTTPFlow) -> None:
    # Modify response
    flow.response.content = flow.response.content.replace(b"old", b"new")
```

Run with addon:

```bash
mitmproxy -s ~/.mitmproxy/addons/my_addon.py
```

### Automation with mitmdump

For non-interactive use:

```bash
# Save traffic to file
mitmdump --set view_filter="~u example.com" --save-stream-file output.mitm

# Run script and exit
mitmdump -s script.py --set flow_detail=0
```

### Environment Variable Automation

For seamless shell integration:

```bash
# Source a script that starts proxy and sets env vars
source mitm-start.sh
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "eBPF program failed to load" | Kernel ≥ 6.8 required for local mode |
| Certificate not trusted | Install CA certificate system-wide or in browser |
| Port already in use | Use `--listen-port` to change port |
| No traffic captured | Verify proxy settings in client application |
| iptables rules not persisting | Use iptables-persistent or netfilter-persistent |

---

## Security Best Practices

1. **Remove CA certificate** when done with interception
2. **Be careful with credentials**—they may appear in cleartext in proxy logs
3. **Never use on production systems** without explicit authorization
4. **Use only on networks you own** or have permission to test

---

## Quick Reference

```bash
# Start mitmproxy (default port 8080)
mitmproxy

# Start with web UI
mitmweb

# Custom port
mitmproxy --listen-port 9000

# Local capture mode (kernel 6.8+)
mitmproxy --mode local

# Transparent mode
mitmproxy --mode transparent --showhost

# Set proxy environment variables
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Install CA certificate (Debian/Ubuntu)
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

---
