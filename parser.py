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

        # --- Extracción de Banderas (Flags) en IPv4 ---
        # ip.flags en Scapy puede ser un objeto de bits, lo convertimos a entero para formatear
        flags_int = int(ip.flags)
        flags_bin = f"{flags_int:03b}"  # Las banderas de IPv4 ocupan 3 bits

        data["ip"] = {
            "Versión": f"{ip.version} (Binario: {ip.version:04b})",  # 4 bits
            "IHL (Longitud Cabecera)": f"{ip.ihl} (Binario: {ip.ihl:04b})",  # 4 bits
            "TOS (Tipo de Servicio)": f"{ip.tos} (Binario: {ip.tos:08b})",  # 8 bits
            "Longitud Total": f"{ip.len} bytes",
            "Identificación": f"0x{ip.id:04x} ({ip.id})",
            "Flags": f"0b{flags_bin} (DF={1 if flags_int & 2 else 0}, MF={1 if flags_int & 1 else 0})",
            "Desplazamiento Fragmento": f"{ip.frag} (Binario: {ip.frag:013b})",  # 13 bits
            "TTL (Tiempo de Vida)": f"{ip.ttl}",
            "Protocolo": f"{proto} ({ip.proto})",
            "Checksum Cabecera": f"0x{ip.chksum:04x}",
            "Origen": ip.src,
            "Destino": ip.dst
        }

    elif IPv6 in packet:
        ip6 = packet[IPv6]
        proto = PROTO_MAP.get(ip6.nh, str(ip6.nh))

        data["ip"] = {
            "Versión": f"{ip6.version} (Binario: {ip6.version:04b})",  # 4 bits
            "Clase de Tráfico": f"0x{ip6.tc:02x} (Binario: {ip6.tc:08b})",  # 8 bits
            "Etiqueta de Flujo": f"{ip6.fl} (Binario: {ip6.fl:020b})",  # 20 bits
            "Longitud de Carga útil": f"{ip6.plen} bytes",
            "Siguiente Cabecera (Next Header)": f"{proto} ({ip6.nh})",
            "Límite de Saltos (Hop Limit)": f"{ip6.hlim}",
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