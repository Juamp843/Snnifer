from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal, QUrl
from PyQt5.QtGui import QColor
import threading

from parser import parse_packet, generate_ipv4_html
from capture import Sniffer
from analyzer import Analyzer
from exporter import export_csv


class GUI(QMainWindow):
    packet_signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sniffer PRO")
        self.setGeometry(100, 100, 1200, 700)

        self.packets = []
        self.raw_packets = []
        self.analyzer = Analyzer()
        self.current_row_packet = None  # Almacena el paquete seleccionado actualmente para la inspección dinámica

        # Señal segura para threads
        self.packet_signal.connect(self.process_packet_gui)

        # ====== COMPONENTES ======

        # Filtro
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filtrar por IP, TCP, UDP...")
        self.filter.textChanged.connect(self.apply_filter)

        # Tabla
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["#", "Origen", "Destino", "Protocolo", "Información"])
        self.table.cellClicked.connect(self.show_details)

        # UX mejora
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)

        # Botones
        self.btn_start = QPushButton(" Iniciar")
        self.btn_stop = QPushButton(" Detener")
        self.btn_export = QPushButton(" Exportar CSV")

        self.btn_stop.setEnabled(False)

        self.btn_start.clicked.connect(self.start_sniffing)
        self.btn_stop.clicked.connect(self.stop_sniffing)
        self.btn_export.clicked.connect(self.export_data)

        # Stats Label
        self.lbl_stats = QLabel("Estadísticas: Esperando captura...")
        self.lbl_stats.setAlignment(Qt.AlignRight)

        # ====== LAYOUTS CON SPLITTER FLEXIBLE ======
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # El layout raíz solo contiene al Splitter
        layout_raiz = QVBoxLayout(main_widget)

        # Splitter Horizontal (Barra deslizable)
        self.splitter = QSplitter(Qt.Horizontal)

        # Contenedor Izquierdo (Filtro + Tabla + Botones)
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)  # Estética limpia
        left_layout.addWidget(QLabel("Filtro de Tráfico:"))
        left_layout.addWidget(self.filter)
        left_layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(self.btn_export)
        left_layout.addLayout(btn_layout)

        # Panel Derecho (Visor HTML + Inspector Dedicado + Stats)
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(QLabel("Estructura de Red Visual (Datagrama):"))


        self.detail_viewer = QTextBrowser()
        self.detail_viewer.setOpenLinks(False)
        self.detail_viewer.anchorClicked.connect(self.handle_html_click)
        self.detail_viewer.setHtml(
            "<h3 style='color: #888; text-align: center; margin-top: 50px;'>Selecciona un paquete...</h3>")
        right_layout.addWidget(self.detail_viewer, 3)  # Proporción alta para el datagrama

        # ====== INSPECTOR NATIVO INFERIOR  ======
        self.inspector_box = QGroupBox("Inspector de Campos Seleccionado")
        inspector_layout = QVBoxLayout(self.inspector_box)

        self.lbl_ins_title = QLabel("Ningún campo seleccionado")
        self.lbl_ins_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #3b82f6;")

        self.lbl_ins_desc = QLabel(
            "Haz clic en cualquier celda del datagrama superior para inspeccionar sus datos a detalle.")
        self.lbl_ins_desc.setWordWrap(True)  # Para que el texto largo no se corte
        self.lbl_ins_desc.setStyleSheet("font-size: 12px; color: #e5e9f0;")

        inspector_layout.addWidget(self.lbl_ins_title)
        inspector_layout.addWidget(self.lbl_ins_desc)

        right_layout.addWidget(self.inspector_box, 1)  # Proporción más baja para el cuadro de texto
        right_layout.addWidget(self.lbl_stats)


        self.splitter.addWidget(left_container)
        self.splitter.addWidget(right_container)

        # Proporción inicial (650 píxeles izquierda, 450 píxeles derecha)
        self.splitter.setSizes([650, 450])

        # Añadimos el splitter al layout de la ventana
        layout_raiz.addWidget(self.splitter)

        # Sniffer Backend
        self.sniffer = Sniffer(self.packet_signal.emit)

        # DICCIONARIO TÉCNICO DE DEFINICIONES
        self.DEFINICIONES_CAMPOS = {
            # ---- CAMPOS IPV4 ----
            "ipv4_version": (
                "Versión de Protocolo (4 bits)",
                "Identifica la versión del protocolo IP utilizada en el paquete. Para redes IPv4 convencionales este valor siempre es 4."
            ),
            "ipv4_ihl": (
                "IHL - Internet Header Length (4 bits)",
                "Indica el tamaño exacto de la cabecera IP medido en bloques/palabras de 32 bits. El valor base estándar de 5 significa que la cabecera mide 20 bytes."
            ),
            "ipv4_tos": (
                "ToS - Type of Service / DSCP (8 bits)",
                "Utilizado para priorización de paquetes y Calidad de Servicio (QoS). Permite marcar flujos de datos críticos (como voz o video) para que los routers los procesen antes."
            ),
            "ipv4_total_len": (
                "Longitud Total (16 bits)",
                "Especifica el tamaño total en bytes de todo el datagrama combinado, incluyendo el tamaño de la cabecera fija y la carga de datos (Payload) transportada."
            ),
            "ipv4_id": (
                "Identificación (16 bits)",
                "Un token identificador correlativo asignado por el emisor. Es crítico durante los procesos de fragmentación, permitiendo al receptor saber a qué paquete original pertenecen las partes."
            ),
            "ipv4_flags": (
                "Banderas / Flags (3 bits)",
                "Tres bits de control para la fragmentación: el primer bit está reservado (siempre 0); el segundo es DF (Don't Fragment) que prohíbe fragmentar el paquete; el tercero es MF (More Fragments) que avisa si vienen más bloques en camino."
            ),
            "ipv4_fragment": (
                "Desplazamiento de Fragmentación (13 bits)",
                "Si un datagrama fue dividido debido al tamaño máximo de la red (MTU), este campo indica la posición exacta que ocupa el fragmento actual con respecto al mensaje original completo."
            ),
            "ipv4_ttl": (
                "TTL - Time to Live (8 bits)",
                "Contador preventivo diseñado para evitar bucles infinitos en internet. Cada router que el paquete cruza disminuye este valor en 1. Si llega a 0, el paquete se destruye."
            ),
            "ipv4_protocol": (
                "Protocolo (8 bits)",
                "Informa al sistema operativo receptor a qué protocolo específico de la capa de transporte debe entregar los datos encapsulados (como TCP [6], UDP [17] o ICMP [1])."
            ),
            "ipv4_checksum": (
                "Checksum de Cabecera (16 bits)",
                "Un código matemático de redundancia cíclica exclusivo de la cabecera IP. Sirve para comprobar que ningún bit de control se haya alterado o corrompido durante el viaje."
            ),
            "ipv4_src_ip": (
                "Dirección IP de Origen (32 bits)",
                "Dirección lógica de red del nodo emisor que generó el datagrama en su origen."
            ),
            "ipv4_dst_ip": (
                "Dirección IP de Destino (32 bits)",
                "Dirección lógica de red del receptor asignado para procesar este paquete."
            ),

            # ---- CAMPOS IPV6 ----
            "ipv6_version": (
                "Versión de Protocolo IPv6 (4 bits)",
                "Identifica la estructura de red del paquete actual. Para la arquitectura de nueva generación IPv6, este campo siempre contiene de forma fija el valor numérico 6."
            ),
            "ipv6_traffic_class": (
                "Clase de Tráfico (8 bits)",
                "El equivalente directo al ToS/DSCP de IPv4. Se encarga de clasificar los paquetes para darles tratamiento preferencial o manejar congestiones de red en tiempo real."
            ),
            "ipv6_flow_label": (
                "Etiqueta de Flujo / Flow Label (20 bits)",
                "Nueva tecnología de IPv6 que ayuda a identificar paquetes que pertenecen a un mismo flujo de comunicación (ej. streaming de audio), solicitando que los routers usen la misma ruta exacta sin reordenar datos."
            ),
            "ipv6_payload_len": (
                "Longitud de Carga Útil (16 bits)",
                "A diferencia de IPv4, este campo mide EXCLUSIVAMENTE los bytes del contenido útil y las extensiones adicionales del paquete. No incluye los 40 bytes fijos de la cabecera IPv6."
            ),
            "ipv6_next_header": (
                "Siguiente Cabecera / Next Header (8 bits)",
                "Determina el tipo de datos que continúa inmediatamente después de la cabecera fija de IPv6. Reemplaza el campo de Protocolo de IPv4 apuntando a TCP, UDP o extensiones de IPv6."
            ),
            "ipv6_hop_limit": (
                "Límite de Saltos / Hop Limit (8 bits)",
                "El equivalente directo al TTL de IPv4. Indica cuántos routers máximos puede saltar el datagrama en internet antes de ser considerado inválido y descartado automáticamente."
            ),
            "ipv6_src_ip": (
                "Dirección IPv6 de Origen (128 bits)",
                "Dirección lógica masiva del host originador del paquete en la red global."
            ),
            "ipv6_dst_ip": (
                "Dirección IPv6 de Destino (128 bits)",
                "Dirección lógica de 128 bits correspondiente a la terminal destino final."
            ),
            
            # ---- CAMPOS ARP ----
            "arp_hwtype": (
                "Hardware Type",
                "Indica el tipo de red física utilizada. El valor 1 corresponde a Ethernet."
            ),

            "arp_ptype": (
                "Protocol Type",
                "Define el protocolo de capa de red que ARP está resolviendo. 0x0800 corresponde a IPv4."
            ),

            "arp_hwlen": (
                "Hardware Address Length",
                "Tamaño en bytes de la dirección MAC. En Ethernet normalmente son 6 bytes."
            ),

            "arp_plen": (
                "Protocol Address Length",
                "Tamaño en bytes de la dirección IP utilizada. IPv4 usa 4 bytes."
            ),

            "arp_op": (
                "ARP Operation",
                "Indica si el paquete es una solicitud ARP (Request) o una respuesta ARP (Reply)."
            ),

            "arp_hwsrc": (
                "MAC Origen (Sender Hardware Address)",
                "Dirección MAC del dispositivo que envía la solicitud o respuesta ARP."
            ),

            "arp_psrc": (
                "IP Origen (Sender Protocol Address)",
                "Dirección IP del emisor del paquete ARP."
            ),

            "arp_hwdst": (
                "MAC Destino (Target Hardware Address)",
                "Dirección MAC del equipo destino. En solicitudes suele ser 00:00:00:00:00:00."
            ),

            "arp_pdst": (
                "IP Destino (Target Protocol Address)",
                "Dirección IP cuya MAC se desea conocer."
            ),
                    }

    # ====== LÓGICA CAPTURA ======

    def start_sniffing(self):
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        threading.Thread(target=self.sniffer.start, daemon=True).start()

    def stop_sniffing(self):
        self.sniffer.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def export_data(self):
        export_csv(self.packets)
        QMessageBox.information(self, "Éxito", "Datos exportados a captura.csv")

    def process_packet_gui(self, packet):
        # Guardamos el paquete original de Scapy en la nueva lista antes de parsearlo
        self.raw_packets.append(packet)

        parsed = parse_packet(packet)
        self.packets.append(parsed)
        self.analyzer.process(parsed)

        row = self.table.rowCount()
        self.table.insertRow(row)

        ip = parsed.get("ip", {})
        tr = parsed.get("transport", {})
        proto = tr.get("Tipo", "OTRO")

        self.table.setItem(row, 0, QTableWidgetItem(str(row)))
        self.table.setItem(row, 1, QTableWidgetItem(ip.get("Origen", "-")))
        self.table.setItem(row, 2, QTableWidgetItem(ip.get("Destino", "-")))
        self.table.setItem(row, 3, QTableWidgetItem(proto))
        self.table.setItem(row, 4, QTableWidgetItem("Capturado"))

        # Colores suaves
        if proto == "TCP":
            self.table.item(row, 3).setBackground(QColor("#3b82f6"))
        elif proto == "UDP":
            self.table.item(row, 3).setBackground(QColor("#22c55e"))

        # Evalúa si el paquete nuevo debe nacer oculto o visible basado en el filtro actual
        self.check_row_visibility(row, parsed)

        self.update_stats()

    # ====== FILTRO INSTANTÁNEO ======

    def apply_filter(self):
        for row in range(self.table.rowCount()):
            if row < len(self.packets):
                parsed_packet = self.packets[row]
                self.check_row_visibility(row, parsed_packet)

    def check_row_visibility(self, row, parsed_packet):
        query = self.filter.text().lower().strip()
        if not query:
            self.table.setRowHidden(row, False)
            return

        ip = parsed_packet.get("ip", {})
        tr = parsed_packet.get("transport", {})

        origen = ip.get("Origen", "-").lower()
        destino = ip.get("Destino", "-").lower()
        proto = tr.get("Tipo", "OTRO").lower()

        if query in origen or query in destino or query in proto:
            self.table.setRowHidden(row, False)
        else:
            self.table.setRowHidden(row, True)

    # ====== DETALLES INTERACTIVOS ======

    def show_details(self, row, col):
        self.detail_viewer.clear()

        # Guardamos el paquete actual seleccionado para extraer datos dinámicos en los clics
        self.current_row_packet = self.raw_packets[row]
        packet_crudo = self.current_row_packet

        # Restablecemos el recuadro inferior informativo
        self.lbl_ins_title.setText("Ningún campo seleccionado")
        self.lbl_ins_desc.setText(
            "Haz clic en cualquier celda del datagrama superior para inspeccionar sus datos a detalle.")
        self.inspector_box.setStyleSheet("QGroupBox { border: 1px solid #333; font-weight: normal; }")

        # Evaluamos dinámicamente qué capa visual renderizar
        if packet_crudo.haslayer('IP'):
            html_content = generate_ipv4_html(packet_crudo)

        elif packet_crudo.haslayer('IPv6'):
            from parser import generate_ipv6_html  # Importación rápida de seguridad
            html_content = generate_ipv6_html(packet_crudo)

        elif packet_crudo.haslayer('ARP'):
            from parser import generate_arp_html
            html_content = generate_arp_html(packet_crudo)

        self.detail_viewer.setHtml(html_content)

    def handle_html_click(self, url):
        # Si no hay un paquete seleccionado en la tabla, ignoramos el clic
        if not self.current_row_packet:
            return

        # Obtenemos el identificador limpio (ej: "ipv4_version")
        key = url.toString()

        if key in self.DEFINICIONES_CAMPOS:
            titulo_base, descripcion_tecnica = self.DEFINICIONES_CAMPOS[key]
            valor_dinamico = "Desconocido"

            # Extraemos el valor en tiempo real directamente desde Scapy
            try:
                if "ipv4" in key and self.current_row_packet.haslayer('IP'):
                    ip = self.current_row_packet['IP']
                    if key == "ipv4_version":
                        valor_dinamico = f"{ip.version}"
                    elif key == "ipv4_ihl":
                        valor_dinamico = f"{ip.ihl} ({ip.ihl * 4} Bytes)"
                    elif key == "ipv4_tos":
                        valor_dinamico = f"0x{ip.tos:02x}"
                    elif key == "ipv4_total_len":
                        valor_dinamico = f"{ip.len} Bytes"
                    elif key == "ipv4_id":
                        valor_dinamico = f"0x{ip.id:04x} ({ip.id})"
                    elif key == "ipv4_flags":
                        valor_dinamico = f"0b{int(ip.flags):03b}"
                    elif key == "ipv4_fragment":
                        valor_dinamico = f"{ip.frag}"
                    elif key == "ipv4_ttl":
                        valor_dinamico = f"{ip.ttl}"
                    elif key == "ipv4_protocol":
                        valor_dinamico = f"{ip.proto}"
                    elif key == "ipv4_checksum":
                        valor_dinamico = f"0x{ip.chksum:04x}"
                    elif key == "ipv4_src_ip":
                        valor_dinamico = f"{ip.src}"
                    elif key == "ipv4_dst_ip":
                        valor_dinamico = f"{ip.dst}"

                elif "ipv6" in key and self.current_row_packet.haslayer('IPv6'):
                    ip6 = self.current_row_packet['IPv6']
                    if key == "ipv6_version":
                        valor_dinamico = f"{ip6.version}"
                    elif key == "ipv6_traffic_class":
                        valor_dinamico = f"0x{ip6.tc:02x}"
                    elif key == "ipv6_flow_label":
                        valor_dinamico = f"{ip6.fl}"
                    elif key == "ipv6_payload_len":
                        valor_dinamico = f"{ip6.plen} Bytes"
                    elif key == "ipv6_next_header":
                        valor_dinamico = f"{ip6.nh}"
                    elif key == "ipv6_hop_limit":
                        valor_dinamico = f"{ip6.hlim}"
                    elif key == "ipv6_src_ip":
                        valor_dinamico = f"{ip6.src}"
                    elif key == "ipv6_dst_ip":
                        valor_dinamico = f"{ip6.dst}"


                elif "arp" in key and self.current_row_packet.haslayer('ARP'):
                    arp_pkt = self.current_row_packet['ARP']
                    if key == "arp_hwtype":
                        valor_dinamico = f"{arp_pkt.hwtype}"
                    elif key == "arp_ptype":
                        valor_dinamico = f"0x{arp_pkt.ptype:04x}"
                    elif key == "arp_hwlen":
                        valor_dinamico = f"{arp_pkt.hwlen} Bytes"
                    elif key == "arp_plen":
                        valor_dinamico = f"{arp_pkt.plen} Bytes"
                    elif key == "arp_op":
                        op_names = {1: "1 (who-has / Solicitud)", 2: "2 (is-at / Respuesta)"}
                        valor_dinamico = op_names.get(arp_pkt.op, f"{arp_pkt.op} (Desconocido)")
                    elif key == "arp_hwsrc":
                        valor_dinamico = f"{arp_pkt.hwsrc}"
                    elif key == "arp_psrc":
                        valor_dinamico = f"{arp_pkt.psrc}"
                    elif key == "arp_hwdst":
                        valor_dinamico = f"{arp_pkt.hwdst}"
                    elif key == "arp_pdst":
                        valor_dinamico = f"{arp_pkt.pdst}"

            except Exception as e:
                valor_dinamico = f"Error al leer valor ({str(e)})"

            # Armamos la visualización en el Inspector de texto
            titulo_completo = f"{titulo_base}"
            descripcion_completa = f"<b>Valor en este paquete:</b> <span style='color:#a3be8c;'>{valor_dinamico}</span><br><br>{descripcion_tecnica}"

            self.lbl_ins_title.setText(titulo_completo)
            self.lbl_ins_desc.setText(descripcion_completa)

            # Ajustamos bordes estéticos según el tipo de protocolo analizado
            if "ipv6" in key:
                self.inspector_box.setStyleSheet(
                    "QGroupBox { border: 2px solid #b48ead; border-radius: 5px; font-weight: bold; }")
            elif "arp" in key:
                self.inspector_box.setStyleSheet(
                    "QGroupBox { border: 2px solid #ebcb8b; border-radius: 5px; font-weight: bold; }")
            else:
                self.inspector_box.setStyleSheet(
                    "QGroupBox { border: 2px solid #5e81ac; border-radius: 5px; font-weight: bold; }")

    # ====== ESTADÍSTICAS ======

    def update_stats(self):
        stats = self.analyzer.get_stats()
        alert = self.analyzer.detect_anomaly()

        text = f"Protocolos: {stats['protocolos']} | Top IP Emisor: {stats['ip_top'][0]} ({stats['ip_top'][1]})"
        if alert:
            text += f" | {alert}"

        self.lbl_stats.setText(text)