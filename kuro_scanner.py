from scapy.all import ARP, Ether, srp
import sys

def scan(ip_range):
    print(f"🌑 [KuroHomura 7] Varrendo alvos em: {ip_range}...")
    
    # Criando a requisição ARP
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast / arp_request

    # Enviando e recebendo respostas
    answered_list = srp(combined_packet, timeout=2, verbose=False)[0]

    print("\nResultados da Forja:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    
    for element in answered_list:
        print(f"{element[1].psrc}\t\t{element[1].hwsrc}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 kuro_scanner.py <IP/Range>")
    else:
        scan(sys.argv[1])
