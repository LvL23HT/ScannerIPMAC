from colorama import Fore, Style, init
init(autoreset=True)
import scapy.all as scapy
import socket
import nmap
import manuf




def print_header():
    header = r"""

//           __        __   ___  _____ __  ________        
//          / / _   __/ /  |__ \|__  // / / /_  __/        
//         / / | | / / /   __/ / /_ </ /_/ / / /           
//        / /__| |/ / /___/ __/___/ / __  / / /            
//     __/_____/___/_____/____/____/_/ /_/ /_/____   ______
//    / ___/_________ _____  /  _/ __ \/  |/  /   | / ____/
//    \__ \/ ___/ __ `/ __ \ / // /_/ / /|_/ / /| |/ /     
//   ___/ / /__/ /_/ / / / // // ____/ /  / / ___ / /___   
//  /____/\___/\__,_/_/ /_/___/_/   /_/  /_/_/  |_\____/   
//                                                         
""" 
    print(f"{Fore.RED}" + header)
print_header()


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = socket.getfqdn(ip)
    return hostname if not hostname == ip else "Unknown"

def get_os(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-O -T4', timeout=30)  # Increased timeout to 20 seconds
        return nm[ip]['osclass'][0]['osfamily']
    except:
        hostname = socket.getfqdn(ip)
    return hostname if not hostname == ip else "Unknown"

def get_manufacturer(mac):
    parser = manuf.MacParser()
    manufacturer = parser.get_manuf(mac)
    return manufacturer if manufacturer else "Unknown"

def arp_scan(ip_range):
    broadcast_mac = "FF:FF:FF:FF:FF:FF"
    
    arp_request = scapy.ARP(pdst=ip_range)
    ether_frame = scapy.Ether(dst=broadcast_mac)
    packet = ether_frame / arp_request
    
    answered, _ = scapy.srp(packet, timeout=2, verbose=0)
    
    devices_list = []
    for sent, received in answered:
        device_info = {
            "IP": received[scapy.ARP].psrc,
            "MAC": received[scapy.Ether].src,
            "Hostname": get_hostname(received[scapy.ARP].psrc),
            
            "Manufacturer": get_manufacturer(received[scapy.Ether].src)
        }
        devices_list.append(device_info)
    
    return devices_list

def display_results(devices_list):
    print(f"{Fore.BLUE}\nIP Address\t\tMAC Address\t\tManufacturer\t\tHostname{Style.RESET_ALL}")
    print(f"{Fore.BLUE}-------------------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    for device in devices_list:
        print(f"{device['IP']}\t\t{device['MAC']}\t\t{device['Manufacturer']}\t\t{device['Hostname']}")

if __name__ == "__main__":
    target_ip = input(f"{Fore.GREEN}Por favor, introduce el rango de IP que deseas escanear (ejemplo: 192.168.0.1/24):{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Escaneando... Por favor, espera.{Style.RESET_ALL}")
results = arp_scan(target_ip)
display_results(results)
print(f"{Fore.YELLOW}Escaneo completado.{Style.RESET_ALL}") 