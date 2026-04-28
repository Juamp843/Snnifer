from scapy.all import sniff

class Sniffer:
    def __init__(self, callback):
        self.callback = callback
        self.running = False

    def start(self):
        self.running = True
        sniff(prn=self.handle, store=False)

    def handle(self, packet):
        if self.running:
            self.callback(packet)

    def stop(self):
        self.running = False