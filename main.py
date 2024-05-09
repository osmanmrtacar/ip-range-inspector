from scapy.all import ARP, Ether, srp
import sys
import socket

def arp_scan(network):
    """
    Perform an ARP scan on the specified network.
    
    :param network: The network to scan, e.g., '192.168.1.0/24'
    """
    # Create an Ethernet and ARP packet to broadcast
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=network)
    
    # Combine the Ethernet and ARP packet
    packet = ether / arp
    
    # Send the packet and capture the response
    result, _ = srp(packet, timeout=2, verbose=False)
    
    # List of active IP addresses
    active_hosts = []
    
    for sent, received in result:
        # For each response, add the IP address to the active_hosts list
        active_hosts.append({'IP': received.psrc, 'MAC': received.hwsrc, 'HOSTNAME': socket.gethostbyaddr(received.psrc)[0]})
    
    return active_hosts

if __name__ == "__main__":
    # Check for command line argument
    if len(sys.argv) != 2:
        print("Usage: python arp_scan.py <network>")
        sys.exit(1)
    
    # The network to scan
    network = sys.argv[1]
    hosts = arp_scan(network)
    
    print("Occupied IP Addresses in the network:")
    for host in hosts:
        print(f"IP: {host['IP']}, MAC: {host['MAC']}, HOSTNAME: {host['HOSTNAME']}")
