import scapy.all as scapy

def arp_scan(ip_range):
    broadcast_mac = "FF:FF:FF:FF:FF:FF"
    
    arp_request = scapy.ARP(pdst=ip_range)
    ether_frame = scapy.Ether(dst=broadcast_mac)
    packet = ether_frame / arp_request
    
    answered, _ = scapy.srp(packet, timeout=2, verbose=0)
    
    devices_list = []
    for sent, received in answered:
        device_info = {"IP": received[scapy.ARP].psrc, "MAC": received[scapy.Ether].src}
        devices_list.append(device_info)
    
    return devices_list

def display_results(devices_list):
    print("\nIP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices_list:
        print(f"{device['IP']}\t\t{device['MAC']}")

if __name__ == "__main__":
    target_ip = "192.168.13.1/24"
    results = arp_scan(target_ip)
    display_results(results)
