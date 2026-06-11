"""
craft_discovery_pkts.py
=======================
Host Discovery via Scapy — Práctica 2: Reconocimiento Activo
Técnicas de Hacking — Universidad Europea de Madrid
"""

from __future__ import annotations
import logging
from typing import Union
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

SUPPORTED = {"udp", "tcp", "icmp"}


def _build_udp(ip_dst: str, port: int, count: int) -> list[Packet]:
    """Craft paquetes UDP hacia ip_dst:port."""
    return [IP(dst=ip_dst) / UDP(dport=port) for _ in range(count)]


def _build_tcp_ack(ip_dst: str, port: int, count: int) -> list[Packet]:
    """Craft paquetes TCP-ACK hacia ip_dst:port."""
    return [IP(dst=ip_dst) / TCP(dport=port, flags="A") for _ in range(count)]


def _build_icmp_timestamp(ip_dst: str, count: int) -> list[Packet]:
    """Craft paquetes ICMP Timestamp Request hacia ip_dst."""
    return [IP(dst=ip_dst) / ICMP(type=13, code=0) for _ in range(count)]


def craft_discovery_pkts(
    protocols: Union[list[str], str],
    ip_range: Union[list[str], str],
    pkt_count: dict[str, int] | None = None,
    port: int = 80,
) -> dict[str, list[Packet]]:
    """
    Construye paquetes de descubrimiento de hosts.

    Parámetros
    ----------
    protocols : str o lista de hasta 3 strings — obligatorio
        Protocolos a usar: 'udp', 'tcp', 'icmp'
    ip_range : str o lista de strings — obligatorio
        IP o rango de IPs destino
    pkt_count : dict opcional
        Número de paquetes por protocolo (por defecto 1)
    port : int opcional
        Puerto destino para TCP y UDP (por defecto 80)
    """
    # Normalizar protocols
    if isinstance(protocols, str):
        protocols = [protocols]
    elif not isinstance(protocols, list):
        raise TypeError("`protocols` debe ser str o list.")

    if len(protocols) > 3:
        raise ValueError("Máximo 3 protocolos.")

    protocols_norm = []
    for p in protocols:
        p_lower = p.lower()
        if p_lower not in SUPPORTED:
            raise ValueError(f"Protocolo '{p}' no soportado. Usa: {SUPPORTED}")
        protocols_norm.append(p_lower)

    # Normalizar ip_range
    if isinstance(ip_range, str):
        ip_range = [ip_range]
    elif not isinstance(ip_range, list):
        raise TypeError("`ip_range` debe ser str o list.")

    if pkt_count is None:
        pkt_count = {}

    # Construir paquetes
    result: dict[str, list[Packet]] = {p: [] for p in protocols_norm}

    for ip_dst in ip_range:
        for proto in protocols_norm:
            n = pkt_count.get(proto, 1)

            if proto == "udp":
                pkts = _build_udp(ip_dst, port, n)
            elif proto == "tcp":
                pkts = _build_tcp_ack(ip_dst, port, n)
            elif proto == "icmp":
                pkts = _build_icmp_timestamp(ip_dst, n)

            result[proto].extend(pkts)
            log.info("Crafted %d %s paquete(s) → %s", n, proto.upper(), ip_dst)

    return result


def discover_hosts(
    protocols: Union[list[str], str],
    ip_range: Union[list[str], str],
    pkt_count: dict[str, int] | None = None,
    port: int = 80,
    timeout: float = 2.0,
    verbose: bool = False,
) -> list[str]:
    """Envía las sondas y devuelve lista de IPs activas."""
    pkts_by_proto = craft_discovery_pkts(protocols, ip_range, pkt_count, port)

    all_pkts: list[Packet] = []
    for pkts in pkts_by_proto.values():
        all_pkts.extend(pkts)

    if not all_pkts:
        log.warning("No hay paquetes que enviar.")
        return []

    log.info("Enviando %d sonda(s)…", len(all_pkts))
    answered, unanswered = sr(all_pkts, timeout=timeout, verbose=verbose)

    active: set[str] = set()
    for sent, received in answered:
        active.add(received[IP].src)

    log.info("%d host(s) activo(s), %d sin respuesta.", len(active), len(unanswered))
    return sorted(active)