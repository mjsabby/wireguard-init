# WireGuard Init

This guide shows how to use the example init program for a minimal WireGuard-based system.

## Quick Start

### 1. Build the Static Init Binary

```bash
cd src
make wireguard-init
```

This creates a fully static binary (~1.2MB) with zero runtime dependencies.

### 2. Create Your WireGuard Config

Create `wireguard.conf`:

```ini
[Interface]
PrivateKey = <your-private-key>
ListenPort = 51820

[Peer]
PublicKey = <peer-public-key>
AllowedIPs = 10.100.0.2/32
```

Generate keys:
```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

### 3. Build Minimal Initramfs

```bash
#!/bin/bash

INITRAMFS_DIR="initramfs"
rm -rf $INITRAMFS_DIR
mkdir -p $INITRAMFS_DIR/{bin,dev,proc,sys}
cp src/wireguard-init $INITRAMFS_DIR/init
cp wireguard.conf $INITRAMFS_DIR/
cd $INITRAMFS_DIR
find . | cpio -H newc -o | gzip > ../initramfs.cpio.gz
cd ..
```

### 4. Boot Your System

Add to kernel command line:
```
init=/init console=ttyS0
```

Or configure your bootloader:

**GRUB (`/boot/grub/grub.cfg`):**
```
menuentry 'WireGuard System' {
    linux /vmlinuz init=/init console=ttyS0
    initrd /initramfs.cpio.gz
}
```

**Syslinux (`syslinux.cfg`):**
```
LABEL wireguard
    KERNEL vmlinuz
    APPEND init=/init console=ttyS0
    INITRD initramfs.cpio.gz
```

### 5. Access Statistics

Once booted:
```bash
curl http://<your-server-ip>:8080
```

## Architecture Overview

```
┌─────────────────────────────────────┐
│   Kernel (with WireGuard support)   │
│         CONFIG_WIREGUARD=y          │
└──────────────┬──────────────────────┘
               │
               ├─ Netlink/IPC
               │
┌──────────────▼──────────────────────┐
│     wireguard-init (PID 1)          │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  1. Network Setup             │ │
│  │     - eth0 up                 │ │
│  │     - Assign static IP        │ │
│  └───────────────────────────────┘ │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  2. WireGuard Setup           │ │
│  │     - Create wg0 interface    │ │
│  │     - Parse config file       │ │
│  │     - Apply via ipc_set_device│ │
│  └───────────────────────────────┘ │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  3. HTTP Stats Server         │ │
│  │     - Listen on port 8080     │ │
│  │     - Query via ipc_get_device│ │
│  │     - Return formatted stats  │ │
│  └───────────────────────────────┘ │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  4. Zombie Reaper             │ │
│  │     - Handle SIGCHLD          │ │
│  │     - waitpid(-1, ..., WNOHANG)│ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
```

## Minimal Kernel Config

Required kernel options:

```
CONFIG_WIREGUARD=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_NETDEVICES=y
CONFIG_ETHERNET=y
CONFIG_E1000=y  # Or your ethernet driver
CONFIG_CRYPTO=y
CONFIG_CRYPTO_CHACHA20POLY1305=y
CONFIG_CRYPTO_CURVE25519=y
```

## Testing in QEMU

```bash
#!/bin/bash

# Build everything
make clean
make

# Create minimal initramfs
./build-initramfs.sh

# Run in QEMU, says rl3819 but the kernel config in this repo is for rl3619
qemu-system-x86_64 \
    -kernel /boot/vmlinuz-$(uname -r) \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 init=/init" \
    -nographic \
    -m 512M \
    -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -device rl3819,netdev=net0

# Test from host
curl http://localhost:8080
```

## REMAINING TO DO

### 1. Security Hardening

- Run HTTP server on localhost only (bind to 127.0.0.1)
- Add iptables rules to restrict access
- Consider adding authentication

### 2. Logging

Add to init:
```c
// Open kernel log
int kmsg = open("/dev/kmsg", O_WRONLY);
dprintf(kmsg, "<6>wireguard-init: Starting\n");
```

### 3. Health Monitoring

Add endpoint:
```c
if (strstr(request, "GET /health")) {
    response = "HTTP/1.0 200 OK\r\n\r\nOK\n";
    write(client_fd, response, strlen(response));
}
```
