import sys
import ipaddress
import struct
from base64 import b64decode

def parse_wireguard_config(path):
    interface = {}
    peers = []
    current_section = None
    current_peer = None

    with open(path, 'r') as f:
        for raw_line in f:
            line = raw_line.strip()
            # Remove inline comments
            line = line.split('#', 1)[0].strip()
            if not line:
                continue

            if line.startswith('['):
                if line == '[Interface]':
                    current_section = 'interface'
                elif line == '[Peer]':
                    if current_peer:
                        peers.append(current_peer)
                    current_peer = {}
                    current_section = 'peer'
                continue

            if '=' in line:
                key, value = [x.strip() for x in line.split('=', 1)]
                if current_section == 'interface':
                    interface[key] = value
                elif current_section == 'peer':
                    current_peer[key] = value

        if current_peer:
            peers.append(current_peer)

    return interface, peers


def ip_to_bytes(ip_cidr):
    net = ipaddress.ip_interface(ip_cidr)
    ip_bytes = net.ip.packed
    cidr = net.network.prefixlen
    return ip_bytes, cidr


def encode_config_to_binary(interface, peers):
    import sys
    import struct
    import ipaddress
    from base64 import b64decode

    privkey = b64decode(interface['PrivateKey'])
    if len(privkey) != 32:
        raise ValueError("PrivateKey must decode to 32 bytes")

    ip_bytes = ipaddress.ip_interface(interface['Address']).ip.packed
    cidr = ipaddress.ip_interface(interface['Address']).network.prefixlen
    port = int(interface['ListenPort'])
    num_peers = len(peers)

    # Native-endian ("<" would be little-endian explicitly)
    binary = bytearray()
    binary += privkey
    binary += ip_bytes
    binary += struct.pack("H", cidr)
    binary += struct.pack("H", port)
    binary += struct.pack("H", num_peers)

    for peer in peers:
        pubkey = b64decode(peer['PublicKey'])
        ip_bytes = ipaddress.ip_interface(peer['AllowedIPs']).ip.packed
        cidr = ipaddress.ip_interface(peer['AllowedIPs']).network.prefixlen
        binary += pubkey
        binary += ip_bytes
        binary += struct.pack("H", cidr)

    return bytes(binary)


def print_usage():
    print("Usage:")
    print("  python3 wg2bin.py <input_config> <output_bin>")
    print("")
    print("Example:")
    print("  python3 wg2bin.py wg0.conf wg0.bin")


def main():
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(1)

    cfg_path = sys.argv[1]
    out_path = sys.argv[2]

    try:
        interface, peers = parse_wireguard_config(cfg_path)
        binary_data = encode_config_to_binary(interface, peers)
        with open(out_path, 'wb') as f:
            f.write(binary_data)
        print(f"✅ Binary configuration written to {out_path} ({len(binary_data)} bytes)")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

