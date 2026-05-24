from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
import threading

from parser import parse_packet
from capture import Sniffer
from analyzer import Analyzer
from exporter import export_csv


class GUI(QMainWindow):

    packet_signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sniffer")
        self.setGeometry(100, 100, 1200, 700)

        self.packets = []
        self.analyzer = Analyzer()

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

        # Árbol detalles
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Detalles del paquete")

        # Estadísticas
        self.stats = QLabel("Estadísticas")

        # Botones
        self.start_btn = QPushButton("▶ Iniciar")
        self.start_btn.clicked.connect(self.start)

        self.stop_btn = QPushButton("⏹ Detener")
        self.stop_btn.clicked.connect(self.stop)

        self.export_btn = QPushButton("💾 Exportar CSV")
        self.export_btn.clicked.connect(self.export)

        # ====== LAYOUT PROFESIONAL ======

        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()
        btn_layout = QHBoxLayout()

        # Izquierda
        left_layout.addWidget(self.filter)
        left_layout.addWidget(self.table)

        # Botones
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)

        # Derecha
        right_layout.addWidget(self.tree)
        right_layout.addWidget(self.stats)
        right_layout.addLayout(btn_layout)

        # Unión
        main_layout.addLayout(left_layout, 2)
        main_layout.addLayout(right_layout, 1)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # ====== ESTILO MINIMALISTA ======

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                font-family: Segoe UI;
                font-size: 13px;
            }

            QLineEdit {
                background-color: #2a2a2a;
                border: 1px solid #3a3a3a;
                border-radius: 10px;
                padding: 6px;
            }

            QTableWidget {
                background-color: #252525;
                border: none;
                gridline-color: #333;
                border-radius: 10px;
            }

            QHeaderView::section {
                background-color: #2f2f2f;
                padding: 5px;
                border: none;
            }

            QTreeWidget {
                background-color: #252525;
                border-radius: 10px;
                padding: 5px;
            }

            QPushButton {
                background-color: #2f2f2f;
                border-radius: 10px;
                padding: 6px 12px;
            }

            QPushButton:hover {
                background-color: #3a3a3a;
            }

            QLabel {
                color: #aaa;
            }
        """)

        # Sniffer
        self.sniffer = Sniffer(self.add_packet)

    # ====== CONTROL ======

    def start(self):
        threading.Thread(target=self.sniffer.start, daemon=True).start()

    def stop(self):
        self.sniffer.stop()

    # ====== THREAD SAFE ======

    def add_packet(self, packet):
        self.packet_signal.emit(packet)

    def process_packet_gui(self, packet):
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

        # Filtro
        self.check_row_visibility(row, parsed)

        self.update_stats()


    # ======= FILTRO ========

    def apply_filter(self):
        # Se recorre toda la tabla y oculta/muestra filas según el texto introducido
        for row in range(self.table.rowCount()):
            parsed_packet = self.packets[row]
            self.check_row_visibility(row, parsed_packet)

    def check_row_visibility(self, row, parsed_packet):
        # Se compara de forma limpia si el filtro coincide con Origen, Destino o Protocolo
        query = self.filter.text().lower().strip()

        if not query:
            # Si el filtro está vacío, mostramos la fila siempre
            self.table.setRowHidden(row, False)
            return

        ip = parsed_packet.get("ip", {})
        tr = parsed_packet.get("transport", {})

        origen = ip.get("Origen", "-").lower()
        destino = ip.get("Destino", "-").lower()
        proto = tr.get("Tipo", "OTRO").lower()

        # Si la búsqueda está incluida en cualquiera de los tres campos visibles importantes
        if query in origen or query in destino or query in proto:
            self.table.setRowHidden(row, False)  # Se mantiene visible
        else:
            self.table.setRowHidden(row, True)  # Se oculta


    # ====== DETALLES ======

    def show_details(self, row, col):
        self.tree.clear()
        packet = self.packets[row]

        for layer, fields in packet.items():
            parent = QTreeWidgetItem([layer.upper()])
            self.tree.addTopLevelItem(parent)

            for k, v in fields.items():
                child = QTreeWidgetItem([f"{k}: {v}"])
                parent.addChild(child)

            self.tree.expandItem(parent)

        self.tree.expandAll()

    # ====== STATS ======

    def update_stats(self):
        stats = self.analyzer.get_stats()
        alert = self.analyzer.detect_anomaly()

        text = f"Protocolos: {stats['protocolos']} | IP Top: {stats['ip_top']}"
        if alert:
            text += "\n" + alert

        self.stats.setText(text)

    # ====== EXPORT ======

    def export(self):
        export_csv(self.packets)
