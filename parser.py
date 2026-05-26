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


# ==================== GENERADOR IPV4  ====================
def generate_ipv4_html(packet):
    if not packet.haslayer('IP'):
        return "<p style='color:red;'>Este paquete no contiene una cabecera IPv4 válida.</p>"

    ip = packet['IP']
    version = ip.version
    ihl = ip.ihl
    tos = ip.tos
    total_len = ip.len
    pkt_id = ip.id
    flags_int = int(ip.flags)
    flags_bin = f"{flags_int:03b}"
    frag = ip.frag
    ttl = ip.ttl
    proto = ip.proto
    chksum = ip.chksum
    src = ip.src
    dst = ip.dst

    proto_name = PROTO_MAP.get(proto, str(proto))

    css = """
    <style>
        body { font-family: sans-serif; background-color: #1e1e1e; color: #fff; margin: 5px; padding: 0; }
        .datagram {
            display: grid; grid-template-columns: repeat(32, 1fr); gap: 3px;
            background-color: #191919; padding: 6px; border: 1px solid #333; border-radius: 4px;
        }
        .cell {
            background-color: #2e3440; 
            border: 1px solid #4c566a; 
            text-align: center; 
            font-family: monospace; 
            font-size: 11px;
            padding: 10px 2px;
        }
        .cell a {
            color: inherent;
            text-decoration: none;
        }
        .cell a:hover {
            color: #85a5ff;              
            text-decoration: underline; 
        }
        .header-bit {
            grid-column: span 32; background-color: #434c5e; font-weight: bold;
            padding: 4px; text-align: center; font-family: monospace; font-size: 11px; color: #e5e9f0;
        }
        .c-ver { background-color: #bf616a; }
        .c-ihl { background-color: #d08770; }
        .c-tos { background-color: #ebcb8b; }
        .c-len { background-color: #a3be8c; }
        .c-id  { background-color: #b48ead; }
        .c-flg { background-color: #5e81ac; }
        .c-frg { background-color: #88c0d0; }
        .c-ttl { background-color: #4f5b66; }
        .c-pro { background-color: #ab7967; }
        .c-chk { background-color: #9a4b4b; color: #fff; }
        .c-ip  { background-color: #4c566a; grid-column: span 32; font-size: 12px; padding: 16px; }
    </style>
    """

    html = f"""
    {css}
    <div class="datagram">

        <div class="cell c-ver" style="grid-column: span 4;">
            <a href="ipv4_version">Ver<br><b>{version}</b></a>
        </div>
        <div class="cell c-ihl" style="grid-column: span 4;">
            <a href="ipv4_ihl">IHL<br><b>{ihl}</b></a>
        </div>
        <div class="cell c-tos" style="grid-column: span 8;">
            <a href="ipv4_tos">ToS<br><b>0x{tos:02x}</b></a>
        </div>
        <div class="cell c-len" style="grid-column: span 16;">
            <a href="ipv4_total_len">Longitud Total<br><b>{total_len} B</b></a>
        </div>

        <div class="cell c-id" style="grid-column: span 16;">
            <a href="ipv4_id">Identificación<br><b>0x{pkt_id:04x}</b></a>
        </div>
        <div class="cell c-flg" style="grid-column: span 3;">
            <a href="ipv4_flags">Flags<br><b>{flags_bin}</b></a>
        </div>
        <div class="cell c-frg" style="grid-column: span 13;">
            <a href="ipv4_fragment">Desplazamiento<br><b>{frag}</b></a>
        </div>

        <div class="cell c-ttl" style="grid-column: span 8;">
            <a href="ipv4_ttl">TTL<br><b>{ttl}</b></a>
        </div>
        <div class="cell c-pro" style="grid-column: span 8;">
            <a href="ipv4_protocol">Protocolo<br><b>{proto_name}</b></a>
        </div>
        <div class="cell c-chk" style="grid-column: span 16;">
            <a href="ipv4_checksum">Checksum<br><b>0x{chksum:04x}</b></a>
        </div>

        <div class="header-bit" style="background-color: #3b4252;">Dirección de Origen</div>
        <div class="cell c-ip">
            <a href="ipv4_src_ip">IP Origen: <b>{src}</b></a>
        </div>

        <div class="header-bit" style="background-color: #3b4252;">Dirección de Destino</div>
        <div class="cell c-ip">
            <a href="ipv4_dst_ip">IP Destino: <b>{dst}</b></a>
        </div>
    </div>
    """
    return html


# ==================== GENERADOR IPV6 ====================
def generate_ipv6_html(packet):
    if not packet.haslayer('IPv6'):
        return "<p style='color:red;'>Este paquete no contiene una cabecera IPv6 válida.</p>"

    ip6 = packet['IPv6']
    version = ip6.version
    tc = ip6.tc
    fl = ip6.fl
    plen = ip6.plen
    nh = ip6.nh
    hlim = ip6.hlim
    src = ip6.src
    dst = ip6.dst

    proto_name = PROTO_MAP.get(nh, str(nh))

    css = """
    <style>
        body { font-family: sans-serif; background-color: #1e1e1e; color: #fff; margin: 5px; padding: 0; }
        .datagram {
            display: grid; grid-template-columns: repeat(32, 1fr); gap: 3px;
            background-color: #191919; padding: 6px; border: 1px solid #333; border-radius: 4px;
        }
        .cell {
            background-color: #2e3440; 
            border: 1px solid #4c566a; 
            text-align: center; 
            font-family: monospace; 
            font-size: 11px;
            padding: 10px 2px;
        }
        .cell a {
            color: inherent !important;
            text-decoration: none;
        }
        .cell a:hover {
            color: #85a5ff;              
            text-decoration: underline; 
        }
        .header-bit {
            grid-column: span 32; background-color: #434c5e; font-weight: bold;
            padding: 4px; text-align: center; font-family: monospace; font-size: 11px; color: #e5e9f0;
        }
        .c-ver { background-color: #bf616a; }
        .c-tc  { background-color: #ebcb8b; }
        .c-fl  { background-color: #b48ead; }
        .plen { background-color: #a3be8c; }
        .c-nh  { background-color: #ab7967; }
        .c-hlim { background-color: #4f5b66; }
        .c-ip6 { background-color: #4c566a; grid-column: span 32; font-size: 11px; padding: 16px; word-break: break-all; }
    </style>
    """

    html = f"""
    {css}
    <div class="datagram">

        <div class="cell c-ver" style="grid-column: span 4;">
            <a href="ipv6_version">Ver<br><b>{version}</b></a>
        </div>
        <div class="cell c-tc" style="grid-column: span 8;">
            <a href="ipv6_traffic_class">Traffic Class<br><b>0x{tc:02x}</b></a>
        </div>
        <div class="cell c-fl" style="grid-column: span 20;">
            <a href="ipv6_flow_label">Flow Label<br><b>{fl}</b></a>
        </div>

        <div class="cell c-plen" style="grid-column: span 16;">
            <a href="ipv6_payload_len" style="color: #ffffff; text-decoration: none;">Payload Length<br><b>{plen} B</b></a>
        </div>
        <div class="cell c-nh" style="grid-column: span 8;">
            <a href="ipv6_next_header">Next Header<br><b>{proto_name}</b></a>
        </div>
        <div class="cell c-hlim" style="grid-column: span 8;">
            <a href="ipv6_hop_limit">Hop Limit<br><b>{hlim}</b></a>
        </div>

        <div class="header-bit" style="background-color: #3b4252;">Dirección de Origen (128 bits)</div>
        <div class="cell c-ip6">
            <a href="ipv6_src_ip">{src}</a>
        </div>

        <div class="header-bit" style="background-color: #3b4252;">Dirección de Destino (128 bits)</div>
        <div class="cell c-ip6">
            <a href="ipv6_dst_ip">{dst}</a>
        </div>
    </div>
    """
    return html

# ==================== GENERADOR ARP ====================
def generate_arp_html(packet):
    if not packet.haslayer('ARP'):
        return "<p style='color:red;'>Este paquete no contiene ARP válido.</p>"

    arp = packet['ARP']

    hwtype = arp.hwtype
    ptype = arp.ptype
    hwlen = arp.hwlen
    plen = arp.plen
    op = arp.op

    op_name = "Request" if op == 1 else "Reply" if op == 2 else str(op)

    css = """
    <style>
        body {
            font-family: sans-serif;
            background-color: #1e1e1e;
            color: #fff;
            margin: 5px;
            padding: 0;
        }

        .datagram {
            display: grid;
            grid-template-columns: repeat(32, 1fr);
            gap: 3px;
            background-color: #191919;
            padding: 6px;
            border: 1px solid #333;
            border-radius: 4px;
        }

        .cell {
            border: 1px solid #4c566a;
            text-align: center;
            font-family: monospace;
            font-size: 11px;
            padding: 10px 2px;
        }

        .cell a {
            color: white;
            text-decoration: none;
        }

        .cell a:hover {
            color: #88c0d0;
            text-decoration: underline;
        }

        .header {
            grid-column: span 32;
            background-color: #434c5e;
            font-weight: bold;
            padding: 5px;
            text-align: center;
        }

        .c1 { background-color: #bf616a; }
        .c2 { background-color: #d08770; }
        .c3 { background-color: #ebcb8b; }
        .c4 { background-color: #a3be8c; }
        .c5 { background-color: #5e81ac; }
        .c6 { background-color: #b48ead; }
        .c7 { background-color: #88c0d0; }

        .full {
            grid-column: span 32;
            background-color: #4c566a;
            padding: 12px;
            font-size: 12px;
        }
    </style>
    """

    html = f"""
    {css}

    <div class="datagram">

        <div class="cell c1" style="grid-column: span 8;">
            <a href="arp_hwtype">
                Hardware Type<br>
                <b>{hwtype}</b>
            </a>
        </div>

        <div class="cell c2" style="grid-column: span 8;">
            <a href="arp_ptype">
                Protocol Type<br>
                <b>0x{ptype:04x}</b>
            </a>
        </div>

        <div class="cell c3" style="grid-column: span 8;">
            <a href="arp_hwlen">
                HW Size<br>
                <b>{hwlen}</b>
            </a>
        </div>

        <div class="cell c4" style="grid-column: span 8;">
            <a href="arp_plen">
                Proto Size<br>
                <b>{plen}</b>
            </a>
        </div>

        <div class="cell c5" style="grid-column: span 32;">
            <a href="arp_op">
                Operación ARP<br>
                <b>{op} ({op_name})</b>
            </a>
        </div>

        <div class="header">MAC Origen</div>
        <div class="cell full">
            <a href="arp_hwsrc">{arp.hwsrc}</a>
        </div>

        <div class="header">IP Origen</div>
        <div class="cell full">
            <a href="arp_psrc">{arp.psrc}</a>
        </div>

        <div class="header">MAC Destino</div>
        <div class="cell full">
            <a href="arp_hwdst">{arp.hwdst}</a>
        </div>

        <div class="header">IP Destino</div>
        <div class="cell full">
            <a href="arp_pdst">{arp.pdst}</a>
        </div>

    </div>
    """

    return html