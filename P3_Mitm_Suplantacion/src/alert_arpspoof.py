"""
alert_arpspoof.py
=================
Detección de ARP Spoofing mediante monitorización de anomalías
Práctica 3: MITM y Suplantación
Técnicas de Hacking — Universidad Europea de Madrid
"""

from __future__ import annotations
import logging
from collections import defaultdict
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# Tabla ARP legítima: {ip: mac}
arp_table: dict[str, str] = {}

# Contador de anomalías por IP
anomaly_count: dict[str, int] = defaultdict(int)


def alert_arpspoof(pkt) -> None:
    """
    Callback para sniff() — analiza cada paquete ARP recibido.

    Detecta dos tipos de anomalías:
    1. Gratuitous ARP: respuesta ARP no solicitada (op=2, dst=broadcast)
    2. Conflicto IP-MAC: una IP conocida aparece con una MAC diferente
    """
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]

    # Solo analizamos respuestas ARP (op=2 is-at)
    if arp.op != 2:
        return

    ip_src  = arp.psrc   # IP anunciada
    mac_src = arp.hwsrc  # MAC anunciada
    mac_dst = arp.hwdst  # MAC destino

    # ── Anomalía 1: Gratuitous ARP ────────────────────────
    # Una respuesta ARP dirigida a broadcast sin ser solicitada
    # es una técnica clásica de envenenamiento
    if mac_dst in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        anomaly_count[ip_src] += 1
        log.warning(
            "⚠️  GRATUITOUS ARP detectado | IP: %s → MAC: %s | "
            "Posible ARP Spoofing (anomalías acumuladas: %d)",
            ip_src, mac_src, anomaly_count[ip_src],
        )

    # ── Anomalía 2: Conflicto IP-MAC ──────────────────────
    # Si ya conocemos la MAC legítima para esta IP y ahora
    # aparece una diferente, alguien está suplantando
    if ip_src in arp_table:
        mac_legitima = arp_table[ip_src]
        if mac_legitima != mac_src:
            anomaly_count[ip_src] += 1
            log.warning(
                "🚨 CONFLICTO ARP detectado | IP: %s | "
                "MAC legítima: %s → MAC sospechosa: %s | "
                "Anomalías acumuladas: %d",
                ip_src, mac_legitima, mac_src, anomaly_count[ip_src],
            )
    else:
        # Primera vez que vemos esta IP — registramos como legítima
        arp_table[ip_src] = mac_src
        log.info("✔  ARP registrado | IP: %s → MAC: %s", ip_src, mac_src)


def monitor(iface: str = "eth0", count: int = 0) -> None:
    """
    Inicia la monitorización ARP en la interfaz indicada.

    Parámetros
    ----------
    iface : str
        Interfaz de red a monitorizar (default: eth0)
    count : int
        Número de paquetes a capturar (0 = infinito)
    """
    log.info("Iniciando monitorización ARP en interfaz %s…", iface)
    log.info("Presiona Ctrl+C para detener.")
    sniff(
        iface=iface,
        filter="arp",
        prn=alert_arpspoof,
        count=count,
        store=False,
    )


if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    monitor(iface=iface)