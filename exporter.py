import csv

def export_csv(packets):
    with open("captura.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Origen", "Destino", "Protocolo"])

        for p in packets:
            ip = p.get("ip", {})
            t = p.get("transport", {})

            writer.writerow([
                ip.get("Origen"),
                ip.get("Destino"),
                t.get("Tipo")
            ])