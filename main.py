from scapy.all import ARP, Ether, srp
import socket
import psutil


def get_local_ip_and_subnet():
    """
    Get the local IP address and subnet mask of the current network.

    Returns:
        A tuple containing the local IP address and CIDR notation (e.g., '192.168.1.1/24').
    """
    # Get the network interfaces and their IP addresses
    interfaces = psutil.net_if_addrs()

    # Loop through interfaces to find the active one (that has an IP address)
    for interface, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET:  # IPv4
                ip_address = address.address
                netmask = address.netmask

                # Convert netmask to CIDR notation
                cidr_suffix = sum(bin(int(x)).count('1') for x in netmask.split('.'))

                # Combine IP address and CIDR suffix to form network range
                network_cidr = f"{ip_address}/{cidr_suffix}"
                return ip_address, network_cidr
    return None, None


def scan_network(target_ip):
    """
    Scans the local network for devices and retrieves their IP and MAC addresses.

    Args:
        target_ip (str): The network address to scan in CIDR format (e.g., '192.168.1.1/24').

    Returns:
        List of dictionaries containing 'ip' and 'mac' addresses of discovered devices.
    """
    # Create ARP request to the target network
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
    packet = ether / arp

    # Send the packet and capture the responses
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    # Parse the result
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def get_hostname(ip):
    """
    Attempts to resolve the hostname of a given IP address.

    Args:
        ip (str): The IP address to resolve.

    Returns:
        str: The resolved hostname, or 'Unknown' if resolution fails.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"

    return hostname


def main():
    # Automatically get the local IP and subnet
    local_ip, target_ip = get_local_ip_and_subnet()

    if not local_ip or not target_ip:
        print("Unable to determine the local network.")
        return

    print(f"Scanning network {target_ip} from local IP {local_ip}...\n")

    # Scan for devices on the network
    devices = scan_network(target_ip)

    if devices:
        print("Discovered devices:")
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            hostname = get_hostname(ip)

            print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}")
    else:
        print("No devices found.")


if __name__ == "__main__":
    main()
