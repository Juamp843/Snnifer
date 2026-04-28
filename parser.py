from scapy.all import Ether, IP, TCP, UDP

PROTO_MAP = {
    6: "TCP",
    17: "UDP"
}

PORT_MAP = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS"
}

def parse_packet(packet):
    data = {}

    if Ether in packet:
        eth = packet[Ether]
        data["frame"] = {
            "MAC Origen": eth.src,
            "MAC Destino": eth.dst,
            "Tipo": hex(eth.type)
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