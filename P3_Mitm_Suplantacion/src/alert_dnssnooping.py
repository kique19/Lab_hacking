"""
alert_dnssnooping.py
====================
Detección de DNS Snooping / Ataque de Kaminsky
Práctica 3: MITM y Suplantación
Técnicas de Hacking — Universidad Europea de Madrid

Firma: Detección por volumen (Threshold) de peticiones
a subdominios inexistentes desde una misma IP origen.
"""

from __future__ import annotations
import logging
from collections import defaultdict
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sniff

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Configuración de la firma ─────────────────────────────
THRESHOLD = 5        # número de consultas sospechosas para alertar
WINDOW_SIZE = 10     # segundos de ventana temporal (informativo)
DNS_PORT = 53

# Contador de consultas por IP origen
query_count: dict[str, int] = defaultdict(int)

# Subdominios conocidos como legítimos
LEGIT_DOMAINS = {"www.test.local.", "ns1.test.local.", "test.local."}


def alert_dnssnooping(pkt) -> None:
    """
    Callback para sniff() — analiza cada paquete DNS recibido.

    Detecta ráfagas de consultas a subdominios inexistentes
    desde una misma IP origen (firma de Kaminsky / DNS Snooping).
    """
    # Solo paquetes UDP al puerto 53 con capa DNS
    if not (pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return

    dns = pkt[DNS]

    # Solo consultas (qr=0), no respuestas
    if dns.qr != 0:
        return

    # Solo paquetes con al menos una pregunta
    if dns.qdcount == 0 or not pkt.haslayer(DNSQR):
        return

    ip_src = pkt[IP].src
    qname  = pkt[DNSQR].qname.decode(errors="ignore").lower()

    log.debug("Consulta DNS: %s → %s", ip_src, qname)

    # ── Firma: subdominio no legítimo ─────────────────────
    if qname not in LEGIT_DOMAINS:
        query_count[ip_src] += 1
        count = query_count[ip_src]

        if count == 1:
            log.info(
                "DNS sospechosa: %s consulta subdominio desconocido '%s' (1/%d)",
                ip_src, qname, THRESHOLD,
            )

        if count >= THRESHOLD:
            log.warning(
                "🚨 ALERTA DNS SNOOPING | IP: %s | "
                "Consultas a subdominios inexistentes: %d (umbral: %d) | "
                "Último dominio: %s",
                ip_src, count, THRESHOLD, qname,
            )


def monitor_dns(iface: str = "eth0", count: int = 0) -> None:
    """
    Inicia la monitorización DNS en la interfaz indicada.

    Parámetros
    ----------
    iface : str
        Interfaz de red a monitorizar (default: eth0)
    count : int
        Número de paquetes a capturar (0 = infinito)
    """
    log.info("Iniciando monitorización DNS en interfaz %s…", iface)
    log.info("Threshold configurado: %d consultas sospechosas", THRESHOLD)
    log.info("Presiona Ctrl+C para detener.")
    sniff(
        iface=iface,
        filter=f"udp port {DNS_PORT}",
        prn=alert_dnssnooping,
        count=count,
        store=False,
    )


if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    monitor_dns(iface=iface)