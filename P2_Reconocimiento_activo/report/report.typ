#set document(
  title: "Práctica 2: Reconocimiento Activo",
  author: "Pablo",
  date: datetime(year: 2026, month: 4, day: 20),
)

#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 3cm, right: 3cm),
  numbering: "1",
)

#set text(size: 11pt, lang: "es")
#set par(justify: true)
#set heading(numbering: "1.1.")
#set bibliography(style: "ieee")

// ── Portada ──────────────────────────────────────────────
#align(center)[
  #v(2cm)
  #text(size: 14pt, weight: "bold")[TÉCNICAS DE HACKING]
  #v(0.5cm)
  #text(size: 22pt, weight: "bold")[Práctica 2: Reconocimiento Activo]
  #v(0.8cm)
  #text(size: 12pt)[Pablo --- Universidad Europea de Madrid]
  #v(0.3cm)
  #text(size: 11pt)[Curso 2025--2026 | Abril 2026]
  #v(1cm)
  #line(length: 70%, stroke: 1pt)
]

#pagebreak()

// ── Resumen ──────────────────────────────────────────────
= Resumen

Este trabajo explora cómo identificar qué dispositivos están activos en una red
local enviando pequeños mensajes de prueba y analizando sus respuestas.
Se implementa una herramienta en Python capaz de generar tres tipos distintos
de mensajes: UDP, TCP-ACK e ICMP Timestamp. Si un dispositivo responde,
se considera activo; si no lo hace, se asume inactivo o inaccesible.

Adicionalmente, se estudia el comportamiento por defecto de Nmap, una herramienta
estándar en auditorías de seguridad, analizando cuántos mensajes envía,
a qué puertos y cómo clasifica su estado. Todo el trabajo se realiza
en un entorno virtualizado con VMware Workstation.

#pagebreak()

// ── Índice ───────────────────────────────────────────────
#outline(title: "Índice", indent: 1.5em)

#pagebreak()

// ── 1. Introducción ──────────────────────────────────────
= Introducción

El reconocimiento activo es la primera fase operativa de una auditoría de seguridad.
A diferencia del reconocimiento pasivo, implica enviar tráfico al objetivo para
obtener información sobre su topología y servicios expuestos @mcnab2007.
Dado que este tráfico puede quedar registrado, su uso fuera de entornos
autorizados es ilegal.

Esta práctica aborda dos objetivos complementarios:

+ *Descubrimiento de hosts*: implementar en Python con Scapy @scapy2024 una función
  que detecte dispositivos activos usando los protocolos UDP @rfc768,
  TCP-ACK @rfc793 e ICMP Timestamp @rfc792.

+ *Comportamiento de Nmap*: analizar qué hace Nmap @nmap2009 por defecto,
  cuántos paquetes envía y cómo determina el estado de cada puerto,
  evidenciándolo con capturas de tráfico @wireshark2024.

El entorno de pruebas consiste en una máquina virtual Kali Linux sobre
VMware Workstation @docker2024, usando el gateway virtual `10.0.2.2` como
host activo y `10.0.2.100` como IP sin host asignado.

// ── 2. Desarrollo ────────────────────────────────────────
= Desarrollo

== Entorno de laboratorio

Las pruebas se realizan sobre una máquina virtual Kali Linux (kernel 6.19.14)
corriendo sobre VMware Workstation. La gestión de dependencias Python se realiza
con uv @uv2024, registrando Scapy en `pyproject.toml` mediante `uv add scapy`.
El editor utilizado es VSCodium @vscodium2024 y el informe se redacta con
Typst @typst2024.

#figure(
  table(
    columns: (auto, auto),
    align: (left, left),
    table.header[*Componente*][*Detalle*],
    [Sistema operativo], [Kali Linux 6.19.14],
    [IP atacante],       [`10.0.2.15`],
    [Host activo],       [`10.0.2.2` (gateway VMware)],
    [Host inactivo],     [`10.0.2.100` (IP libre)],
    [Python],            [3.13.12],
    [Scapy],             [2.7.0],
    [Nmap],              [7.99],
  ),
  caption: [Configuración del entorno de laboratorio.]
)

== Parte 1 --- Descubrimiento de hosts con Scapy

=== Fundamento teórico

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, left, left),
    table.header[*Protocolo*][*Sonda enviada*][*Respuesta → host activo*],
    [UDP @rfc768],
    [Datagrama UDP vacío al puerto 80],
    [ICMP Port Unreachable (type 3)],

    [TCP-ACK @rfc793],
    [Segmento TCP flag ACK al puerto 80],
    [RST — host activo independientemente del estado del puerto],

    [ICMP Timestamp @rfc792],
    [ICMP type 13 (Timestamp Request)],
    [ICMP type 14 (Timestamp Reply)],
  ),
  caption: [Estímulos y respuestas de los protocolos de descubrimiento.]
)

*UDP*: un datagrama a un puerto cerrado provoca un ICMP Port Unreachable,
confirmando que el host existe. Si el puerto está filtrado no hay respuesta @rfc768.

*TCP-ACK*: un ACK fuera de contexto siempre genera RST en el destino,
independientemente de si el puerto está abierto o cerrado @rfc793.
Esto lo hace útil para saltarse algunos firewalls orientados a conexiones nuevas.

*ICMP Timestamp*: solicita la hora del sistema al destino.
Aunque muchos firewalls modernos lo bloquean, es muy efectivo en redes internas @rfc792.

=== Implementación

La función `craft_discovery_pkts` se define en `src/craft_discovery_pkts.py`
con la siguiente signatura:

```python
def craft_discovery_pkts(
    protocols: list[str] | str,        # obligatorio: hasta 3 protocolos
    ip_range:  list[str] | str,        # obligatorio: IP o lista de IPs
    pkt_count: dict[str, int] | None,  # opcional: nº paquetes por proto (def. 1)
    port: int = 80,                    # opcional: puerto TCP/UDP (def. 80)
) -> dict[str, list[Packet]]:
```

Decisiones de diseño destacadas:

- Validación temprana de protocolos antes de construir ningún paquete.
- Builders privados por protocolo (`_build_udp`, `_build_tcp_ack`,
  `_build_icmp_timestamp`) para facilitar mantenimiento y extensión.
- Logging estructurado con el módulo estándar `logging`.
- Función complementaria `discover_hosts` que llama a `craft_discovery_pkts`,
  envía los paquetes con `sr()` y extrae las IPs que respondieron.

=== Resultados del descubrimiento

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: (left, left, center, left),
    table.header[*IP destino*][*Protocolo*][*Respuesta*][*Conclusión*],
    [`10.0.2.2`],   [UDP],      [ICMP Port Unreachable], [Host activo ✔],
    [`10.0.2.2`],   [TCP-ACK],  [RST],                   [Host activo ✔],
    [`10.0.2.2`],   [ICMP TS],  [Timestamp Reply],       [Host activo ✔],
    [`10.0.2.100`], [ICMP TS],  [Sin respuesta],         [Host inactivo ✘],
  ),
  caption: [Resultados del descubrimiento de hosts.]
)
#figure(
  image("../evidencias/captura_script.png", width: 100%),
  caption: [Ejecución del script de descubrimiento. Se observa cómo 10.0.2.2 es detectado como activo y 10.0.2.100 no genera respuesta.]
)

== Parte 2 --- Comportamiento por defecto de Nmap

=== Estado de puerto

El estado de un puerto describe cómo responde un servicio al recibir una sonda @nmap2009:

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, left, left),
    table.header[*Estado*][*Sonda enviada*][*Respuesta*],
    [Abierto],   [TCP SYN], [SYN/ACK — hay servicio escuchando],
    [Cerrado],   [TCP SYN], [RST/ACK — host activo, sin servicio],
    [Filtrado],  [TCP SYN], [Sin respuesta o ICMP Unreachable],
  ),
  caption: [Estados de puerto y sus indicadores de tráfico.]
)

=== Comportamiento por defecto

Al ejecutar `nmap <objetivo>` sin opciones, Nmap realiza un
*TCP SYN Stealth Scan* (`-sS`) sobre los *1000 puertos más comunes*
según su base de datos `nmap-services` @nmapmanpage.

Evidencia obtenida con `nmap -v 10.0.2.2`:

#figure(
  table(
    columns: (auto, auto),
    align: (left, left),
    table.header[*Métrica*][*Valor*],
    [Tipo de escaneo],       [SYN Stealth Scan],
    [Puertos analizados],    [1000],
    [Paquetes enviados],     [1997 (1000 SYN + retransmisiones)],
    [Paquetes recibidos],    [629],
    [Puertos abiertos],      [6],
    [Puertos filtrados],     [994],
    [Tiempo total],          [5.03 segundos],
  ),
  caption: [Métricas del escaneo Nmap por defecto sobre `10.0.2.2`.]
)
#figure(
  image("../evidencias/captura_nmap_terminal.png", width: 100%),
  caption: [Salida de nmap -v mostrando el SYN Stealth Scan sobre 10.0.2.2.]
)

=== Servicios descubiertos

#figure(
  table(
    columns: (auto, auto, auto),
    align: (center, center, left),
    table.header[*Puerto*][*Estado*][*Servicio*],
    [135/tcp],  [Abierto], [msrpc],
    [445/tcp],  [Abierto], [microsoft-ds (SMB)],
    [902/tcp],  [Abierto], [iss-realsecure (VMware)],
    [912/tcp],  [Abierto], [apex-mesh (VMware)],
    [3306/tcp], [Abierto], [mysql],
    [5357/tcp], [Abierto], [wsdapi],
    [otros 994],[Filtrado],[Sin respuesta del gateway],
  ),
  caption: [Puertos descubiertos por Nmap en `10.0.2.2`.]
)
#figure(
  image("../evidencias/captura_wireshark.png", width: 100%),
  caption: [Captura Wireshark con filtro tcp.flags.syn == 1 and tcp.flags.ack == 0 mostrando los paquetes SYN enviados por Nmap.]
)

La presencia de los puertos 902 y 912 es característica del hipervisor VMware,
que expone estos servicios en el gateway virtual @nmap2009.

// ── 3. Resultados ────────────────────────────────────────
= Resultados

La implementación de `craft_discovery_pkts` construye y envía correctamente
paquetes UDP, TCP-ACK e ICMP Timestamp, detectando hosts activos mediante
el análisis de respuestas con `scapy.sendrecv.sr()`.

El gateway `10.0.2.2` respondió a los tres tipos de sonda, confirmando su
actividad. La IP `10.0.2.100` no generó respuesta alguna en el timeout
configurado (2 segundos), clasificándose como inactiva.

Nmap, en su configuración por defecto, realiza un SYN Stealth Scan sobre
1000 puertos, enviando en este caso 1997 paquetes en 5 segundos.
Descubrió 6 servicios activos, todos correspondientes al gateway VMware
del host Windows subyacente.

// ── 4. Conclusiones ──────────────────────────────────────
= Conclusiones
- La función `craft_discovery_pkts` implementa correctamente el descubrimiento
  multi-protocolo con todos los argumentos obligatorios y opcionales requeridos.

- Cada protocolo aporta una perspectiva diferente: ICMP Timestamp es el más
  directo pero frecuentemente bloqueado; TCP-ACK evita ciertos filtros de
  firewall; UDP provoca respuestas ICMP en hosts sin filtrado estricto.

- Nmap realiza por defecto un TCP SYN Stealth Scan sobre 1000 puertos,
  con un coste aproximado de 2000 paquetes. Conocer este comportamiento
  es esencial para interpretar resultados y ajustar la discreción del escaneo.

- Todas las pruebas se realizaron en entorno virtualizado, cumpliendo
  con las restricciones legales y éticas de la práctica.

// ── Bibliografía ─────────────────────────────────────────
#pagebreak()
= Bibliografía

#bibliography("references.bib")