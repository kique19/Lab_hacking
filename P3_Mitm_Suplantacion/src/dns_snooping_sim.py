"""
dns_snooping_sim.py
===================
Simulación de DNS Snooping / Ataque de Kaminsky
Práctica 3: MITM y Suplantación
Técnicas de Hacking — Universidad Europea de Madrid

Genera una ráfaga de consultas DNS a subdominios inexistentes
para validar la firma de detección alert_dnssnooping.
"""

from __future__ import annotations
import time
import random
import string
import logging
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import send

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Configuración del escenario ───────────────────────────
DNS_SERVER  = "172.21.0.10"   # IP del servidor DNS
DNS_PORT    = 53
BASE_DOMAIN = "test.local"


def random_subdomain(length: int = 8) -> str:
    """Genera un subdominio aleatorio inexistente."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def send_dns_query(subdomain: str, iface: str = "eth0") -> None:
    """Envía una consulta DNS para subdomain.BASE_DOMAIN."""
    qname = f"{subdomain}.{BASE_DOMAIN}"
    pkt = (
        IP(dst=DNS_SERVER)
        / UDP(dport=DNS_PORT, sport=random.randint(1024, 65535))
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    send(pkt, iface=iface, verbose=False)
    log.info("Consulta enviada: %s → %s", DNS_SERVER, qname)


def run_attack(
    rounds: int = 15,
    interval: float = 0.5,
    iface: str = "eth0",
) -> None:
    """
    Ejecuta la ráfaga de consultas DNS a subdominios inexistentes.

    Parámetros
    ----------
    rounds   : número de consultas a enviar
    interval : segundos entre consultas
    iface    : interfaz de red
    """
    log.info("Iniciando simulación DNS Snooping (%d consultas)…", rounds)
    for i in range(rounds):
        subdomain = random_subdomain()
        log.info("Ronda %d/%d — subdominio: %s.%s", i + 1, rounds, subdomain, BASE_DOMAIN)
        send_dns_query(subdomain, iface=iface)
        time.sleep(interval)
    log.info("Simulación completada.")


if __name__ == "__main__":
    run_attack(rounds=15, interval=0.5)
    