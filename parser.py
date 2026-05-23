from scapy.all import Ether, IP, IPv6, TCP, UDP, ARP
from typing import Any

PROTO_MAP = {
    2: "IGMP",
    6: "TCP",
    17: "UDP"
}

PORT_MAP = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    5353: "mDNS"
}

def parse_packet(packet):
    data:  dict[str, Any] = {}

    if Ether in packet:
        eth = packet[Ether]
        data["frame"] = {
            "MAC Origen": eth.src,
            "MAC Destino": eth.dst,
            "Tipo": hex(eth.type)
        }

    # Detectar paquetes ARP (Para los que no tienen capa IP)
    if ARP in packet:
        arp = packet[ARP]
        data["ip"] = {
            "Origen": arp.psrc,
            "Destino": arp.pdst
        }
        data["transport"] = {
            "Tipo": "ARP"
        }

    if IP in packet:
        ip = packet[IP]
        proto = PROTO_MAP.get(ip.proto, str(ip.proto))

        data["ip"] = {
            "Versión": ip.version,
            "TTL": f"{ip.ttl} (vida restante)",
            "Protocolo": proto,
            "Origen": ip.src,
            "Destino": ip.dst
        }

        if proto == "IGMP":
            data["transport"] = {
                "Tipo": "IGMP"
            }

    elif IPv6 in packet:
        ip6 = packet[IPv6]
        # En IPv6, el campo equivalente a 'proto' se llama 'nh' (Next Header)
        proto = PROTO_MAP.get(ip6.nh, str(ip6.nh))
        data["ip"] = {
            "Versión": ip6.version,
            "TTL": f"{ip6.hlim} (límite de saltos)",
            "Protocolo": proto,
            "Origen": ip6.src,
            "Destino": ip6.dst
        }

    if TCP in packet:
        tcp = packet[TCP]
        data["transport"] = {
            "Tipo": "TCP",
            "Puerto Origen": f"{tcp.sport} ({PORT_MAP.get(tcp.sport, '')})",
            "Puerto Destino": f"{tcp.dport} ({PORT_MAP.get(tcp.dport, '')})",
            "Flags": str(tcp.flags)
        }

    elif UDP in packet:
        udp = packet[UDP]
        data["transport"] = {
            "Tipo": "UDP",
            "Puerto Origen": str(udp.sport),
            "Puerto Destino": str(udp.dport)
        }

    return data