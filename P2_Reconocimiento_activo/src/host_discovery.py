"""
host_discovery.py
=================
Script de descubrimiento de hosts — Práctica 2
Técnicas de Hacking — Universidad Europea de Madrid
"""

from __future__ import annotations
import sys
from craft_discovery_pkts import craft_discovery_pkts, discover_hosts

# ── Ajusta estas IPs a tu entorno virtualizado ──
ACTIVE_HOST   = "10.0.2.2"    # gateway VMware — activo
INACTIVE_HOST = "10.0.2.100"  # IP libre — inactivo
SUBNET_RANGE  = "10.0.2.0/24" # subred completa


def banner(title: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def scenario_active_host() -> None:
    banner("Escenario 1: Host activo — UDP + TCP-ACK + ICMP-Timestamp")
    pkts = craft_discovery_pkts(
        protocols=["udp", "tcp", "icmp"],
        ip_range=ACTIVE_HOST,
        pkt_count={"udp": 2, "tcp": 1, "icmp": 1},
        port=80,
    )
    for proto, pkt_list in pkts.items():
        print(f"\n  [{proto.upper()}] {len(pkt_list)} paquete(s):")
        for p in pkt_list:
            print(f"    {p.summary()}")

    print(f"\n  >>> Enviando probes a {ACTIVE_HOST}…")
    active = discover_hosts(
        protocols=["udp", "tcp", "icmp"],
        ip_range=ACTIVE_HOST,
        pkt_count={"udp": 2, "tcp": 1, "icmp": 1},
        port=80,
        timeout=2.0,
    )
    _print_result(active)


def scenario_inactive_host() -> None:
    banner("Escenario 2: IP sin host activo — ICMP-Timestamp")
    pkts = craft_discovery_pkts(protocols="icmp", ip_range=INACTIVE_HOST)
    print(f"  [ICMP] {len(pkts['icmp'])} paquete(s):")
    for p in pkts["icmp"]:
        print(f"    {p.summary()}")

    print(f"\n  >>> Enviando probe a {INACTIVE_HOST}…")
    active = discover_hosts(protocols="icmp", ip_range=INACTIVE_HOST, timeout=2.0)
    _print_result(active)


def scenario_subnet_scan() -> None:
    banner(f"Escenario 3: Escaneo de subred {SUBNET_RANGE} — TCP-ACK")
    print(f"  >>> Escaneando {SUBNET_RANGE}…")
    active = discover_hosts(protocols="tcp", ip_range=SUBNET_RANGE, timeout=3.0)
    _print_result(active)


def _print_result(active: list[str]) -> None:
    if active:
        print("\n  ✔  Hosts activos:")
        for ip in active:
            print(f"       {ip}")
    else:
        print("\n  ✘  No se detectaron hosts activos.")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        print("[DEMO — sin envío de paquetes]\n")
        pkts = craft_discovery_pkts(
            protocols=["udp", "tcp", "icmp"],
            ip_range=[ACTIVE_HOST, INACTIVE_HOST],
            pkt_count={"udp": 2, "tcp": 2, "icmp": 2},
            port=80,
        )
        for proto, pkt_list in pkts.items():
            print(f"[{proto.upper()}] {len(pkt_list)} paquetes:")
            for p in pkt_list:
                print(f"  {p.summary()}")
        sys.exit(0)

    scenario_active_host()
    scenario_inactive_host()
    scenario_subnet_scan()