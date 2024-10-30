from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import socket
from concurrent.futures import ThreadPoolExecutor
import time

def discover_device(ip):
    """
    Discover a single device using ARP
    
    Args:
        ip (str): IP address to scan
    Returns:
        dict: Device information if found, None otherwise
    """
    try:
        # Create ARP packet
        arp = ARP(pdst=ip)
        # Create Ethernet frame
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine frame and packet
        packet = ether/arp
        
        # Send packet and wait for response
        print(f"Scanning {ip}...")
        result = srp(packet, timeout=1, verbose=False)[0]
        
        if result:
            # Get the first response
            received = result[0][1]
            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': None
            }
            
            # Try to get hostname
            try:
                device_info['hostname'] = socket.gethostbyaddr(received.psrc)[0]
            except:
                pass
                
            return device_info
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
    return None

def check_ports(ip, ports=[80, 443, 8080, 8443]):
    """
    Check common ports on a discovered device
    
    Args:
        ip (str): IP address to scan
        ports (list): List of ports to check
    Returns:
        dict: Dictionary of port states
    """
    port_states = {}
    for port in ports:
        try:
            # Create TCP SYN packet
            syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
            # Send packet and wait for response
            response = sr1(syn_packet, timeout=1, verbose=False)
            
            if response and response.haslayer(TCP):
                flags = response[TCP].flags
                if flags & 0x12:  # SYN-ACK
                    port_states[port] = 'open'
                elif flags & 0x14:  # RST-ACK
                    port_states[port] = 'closed'
                else:
                    port_states[port] = 'filtered'
            else:
                port_states[port] = 'filtered'
        except:
            port_states[port] = 'error'
    return port_states

def scan_network(base_network="192.168.4"):
    """
    Scan the network for devices
    
    Args:
        base_network (str): Base network address (e.g., "192.168.4")
    """
    print(f"Starting network scan on {base_network}.0/24")
    
    discovered_devices = []
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create list of IPs to scan
        ip_list = [f"{base_network}.{i}" for i in range(1, 255)]
        
        # Submit all scan tasks
        future_to_ip = {executor.submit(discover_device, ip): ip for ip in ip_list}
        
        # Process results as they complete
        for future in future_to_ip:
            device_info = future.result()
            if device_info:
                # Check ports for discovered device
                device_info['ports'] = check_ports(device_info['ip'])
                discovered_devices.append(device_info)
                
                # Print device information
                print("\nDiscovered Device:")
                print(f"IP: {device_info['ip']}")
                print(f"MAC: {device_info['mac']}")
                if device_info['hostname']:
                    print(f"Hostname: {device_info['hostname']}")
                print("Open Ports:")
                for port, state in device_info['ports'].items():
                    print(f"  Port {port}: {state}")

    return discovered_devices

if __name__ == "__main__":
    print("Network Device Discovery Tool")
    print("-" * 30)
    
    # You can modify this base network address to match your network
    devices = scan_network("192.168.4")
    
    print("\nScan Complete!")
    print(f"Found {len(devices)} devices")
