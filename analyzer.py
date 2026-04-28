from collections import Counter

class Analyzer:
    def __init__(self):
        self.proto_counter = Counter()
        self.ip_counter = Counter()

    def process(self, parsed):
        ip = parsed.get("ip", {})
        transport = parsed.get("transport", {})

        proto = transport.get("Tipo", "OTRO")
        self.proto_counter[proto] += 1

        src = ip.get("Origen")
        if src:
            self.ip_counter[src] += 1

    def get_stats(self):
        top_ip = self.ip_counter.most_common(1)
        return {
            "protocolos": dict(self.proto_counter),
            "ip_top": top_ip[0] if top_ip else ("-", 0)
        }

    def detect_anomaly(self):
        for ip, count in self.ip_counter.items():
            if count > 50:
                return f"⚠ Posible tráfico sospechoso desde {ip}"
        return None