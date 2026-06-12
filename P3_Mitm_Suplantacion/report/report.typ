#set document(
  title: "Práctica 3: MITM y Suplantación",
  author: "Enrique de Pablo",
  date: datetime(year: 2026, month: 5, day: 20),
)

#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 3cm, right: 3cm),
  numbering: "1",
  header: context {
    if counter(page).get().first() > 2 [
      #set text(size: 9pt, fill: luma(120))
      Técnicas de Hacking — Práctica 3: MITM y Suplantación
      #h(1fr) Universidad Europea de Madrid
      #line(length: 100%, stroke: 0.5pt + luma(180))
    ]
  }
)

#set text(size: 11pt, lang: "es")
#set par(justify: true, leading: 0.8em, spacing: 1.2em)
#set heading(numbering: "1.1.")
#set bibliography(style: "ieee")

#align(center)[
  #v(3cm)
  #rect(width: 100%, stroke: 1.5pt, inset: 1cm)[
    #text(size: 13pt, weight: "bold")[TÉCNICAS DE HACKING]
    #v(0.4cm)
    #text(size: 24pt, weight: "bold")[Práctica 3]
    #v(0.2cm)
    #text(size: 18pt, weight: "bold")[MITM y Suplantación]
    #v(0.8cm)
    #line(length: 60%, stroke: 0.8pt)
    #v(0.6cm)
    #text(size: 12pt)[Enrique de Pablo]
    #v(0.2cm)
    #text(size: 11pt)[Universidad Europea de Madrid]
    #v(0.2cm)
    #text(size: 11pt)[Curso 2025--2026 | Mayo 2026]
    #v(0.6cm)
    #line(length: 60%, stroke: 0.8pt)
    #v(0.4cm)
    #text(size: 10pt, fill: luma(80))[
      Profesor: Robledano Abasolo, Alfredo \
      alfredo.robledano\@universidadeuropea.es
    ]
  ]
]

#pagebreak()

= Resumen

Esta práctica implementa un sistema de monitorización basado en firmas para
detectar dos tipos de ataques de red: el envenenamiento de tablas ARP
(ARP Spoofing) y las anomalías en consultas DNS relacionadas con el ataque
de Kaminsky y el DNS Snooping.

En la primera parte se diseña un escenario de red virtualizado mediante
Docker Compose con cuatro nodos: víctima, router, servidor web y atacante.
Se utiliza la herramienta Bettercap para simular el envenenamiento ARP y se
implementa la función `alert_arpspoof` en Python con Scapy para detectar
en tiempo real las anomalías en las respuestas ARP.

En la segunda parte se despliega un escenario DNS con servidor autoritativo
y nodo atacante. Se implementa la función `alert_dnssnooping` que detecta
ráfagas de consultas a subdominios inexistentes mediante un umbral configurable,
y se valida con un script generador de tráfico que simula el ataque de Kaminsky.

Todo el trabajo se realiza en un entorno completamente virtualizado con Docker
sobre Kali Linux, respetando las restricciones legales y éticas de la práctica.

#pagebreak()

#outline(title: "Índice", indent: 1.5em)

#pagebreak()

= Marco Teórico

== ARP Spoofing y ataques MITM

El protocolo ARP permite mapear direcciones IP a direcciones MAC en redes
locales. Su diseño original no contempla mecanismos de autenticación, lo que
lo hace vulnerable al envenenamiento de tablas ARP @rfc826.

En un ataque de ARP Spoofing, el atacante envía respuestas ARP falsas
(Gratuitous ARP) a la víctima y al router, asociando su propia MAC a las
IPs de ambos. Esto provoca que el tráfico entre víctima y router pase por
el atacante, que puede interceptarlo, modificarlo o simplemente observarlo.
Este escenario se denomina Man-In-The-Middle (MITM) @mcnab2007.

Las anomalías detectables en el tráfico ARP son:

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, left, left),
    table.header[*Anomalía*][*Descripción*][*Indicador*],
    [Gratuitous ARP],
    [Respuesta ARP no solicitada dirigida a broadcast],
    [op=2 y hwdst=ff:ff:ff:ff:ff:ff],
    [Conflicto IP-MAC],
    [Una IP conocida aparece con una MAC diferente],
    [ip\_src en tabla pero mac\_src diferente],
  ),
  caption: [Anomalías ARP detectables mediante monitorización pasiva.]
)

== DNS Snooping y ataque de Kaminsky

El ataque de Kaminsky @kaminsky2008 explota la forma en que los resolutores
DNS cachean respuestas. El atacante envía una ráfaga de consultas a subdominios
inexistentes del dominio objetivo, intentando que el resolutor acepte una
respuesta DNS falsa que envenene su caché @rfc1034 @rfc1035.

El DNS Snooping aprovecha el mismo patrón: consultas repetidas a subdominios
inexistentes desde una misma IP revelan un comportamiento anómalo que puede
indicar reconocimiento de infraestructura o envenenamiento de caché.

La firma de detección se basa en el umbral (threshold) de consultas a
subdominios no reconocidos desde una misma IP origen en un periodo de tiempo.

== Bettercap

Bettercap @bettercap2024 es una herramienta de red avanzada para auditorías
de seguridad. Soporta ataques MITM mediante ARP Spoofing, captura de
credenciales e inyección de tráfico. En esta práctica se utiliza para
generar el tráfico de envenenamiento ARP en el escenario Docker @docker2024.

= Introducción

Los ataques de Man-In-The-Middle (MITM) representan una de las amenazas más
graves en redes locales. Al interceptar el tráfico entre dos nodos, el atacante
puede robar credenciales, inyectar contenido malicioso o modificar comunicaciones
sin que las víctimas lo detecten @stallings2016.

Esta práctica aborda dos vectores de ataque complementarios:

+ *ARP Spoofing*: envenenamiento de las tablas ARP de víctima y router para
  redirigir el tráfico a través del atacante. Se implementa `alert_arpspoof`
  que monitoriza el tráfico ARP en tiempo real y detecta Gratuitous ARPs
  y conflictos IP-MAC usando Scapy @scapy2024.

+ *DNS Snooping / Kaminsky*: ráfagas de consultas DNS a subdominios inexistentes
  para envenenar la caché del resolutor. Se implementa `alert_dnssnooping`
  con detección por umbral configurable. El servidor DNS usa BIND9 @bind92024.

Ambos escenarios se despliegan mediante Docker Compose @docker2024, lo que
garantiza aislamiento completo del tráfico generado respecto a redes externas.

= Desarrollo

== Entorno de laboratorio

#figure(
  table(
    columns: (auto, auto),
    align: (left, left),
    table.header[*Componente*][*Detalle*],
    [Sistema operativo],  [Kali Linux 6.19.14],
    [Contenedores],       [Docker 28.5.2 + Docker Compose 2.40.3],
    [Herramienta ataque], [Bettercap 2.41.5],
    [Python],             [3.10 / 3.13 según contenedor],
    [Scapy],              [2.7.0],
    [Editor],             [VSCodium 1.121.0],
    [Gestor paquetes],    [uv 0.11.20],
  ),
  caption: [Configuración del entorno de laboratorio.]
)

== Parte 1 --- Detección de ARP Spoofing

=== Topología del escenario Docker

El escenario se define en `docker/docker-compose-arp.yml` con cuatro servicios
en dos redes virtuales aisladas:

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, left, left),
    table.header[*Contenedor*][*IP*][*Rol*],
    [victima],       [`172.19.0.10`], [Host objetivo del envenenamiento],
    [router],        [`172.19.0.2` / `172.20.0.2`], [Gateway entre redes],
    [servidor\_web], [`172.20.0.10`], [Servidor Nginx en red externa],
    [atacante],      [`172.19.0.99`], [Nodo atacante con Bettercap],
  ),
  caption: [Topología del escenario ARP Spoofing.]
)

=== La función `alert_arpspoof`

La función se define en `src/alert_arpspoof.py` y actúa como callback de
`scapy.sendrecv.sniff()`. Analiza cada paquete ARP recibido y detecta:

```python
def alert_arpspoof(pkt) -> None:
    arp = pkt[ARP]
    if arp.op != 2:  # Solo respuestas ARP
        return
    # Anomalía 1: Gratuitous ARP
    if mac_dst in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        log.warning("GRATUITOUS ARP detectado | IP: %s MAC: %s", ...)
    # Anomalía 2: Conflicto IP-MAC
    if ip_src in arp_table and arp_table[ip_src] != mac_src:
        log.warning("CONFLICTO ARP | IP: %s MAC legitima: %s sospechosa: %s", ...)
```

=== Simulación del ataque

El script `src/arp_spoof_sim.py` envía paquetes ARP falsos a la víctima
y al router usando Scapy @scapy2024, suplantando ambas MACs con
`aa:bb:cc:dd:ee:ff`. Ejecuta 10 rondas con 1 segundo de intervalo.

=== Evidencias

#figure(
  image("../evidencias/captura_arp_monitor.png", width: 100%),
  caption: [Monitor alert\_arpspoof detectando Gratuitous ARPs del atacante.]
)

#figure(
  image("../evidencias/captura_arp_ataque.png", width: 100%),
  caption: [Script arp\_spoof\_sim.py ejecutándose desde el contenedor atacante.]
)

== Parte 2 --- Detección de DNS Snooping

=== Topología del escenario Docker

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, left, left),
    table.header[*Contenedor*][*IP*][*Rol*],
    [dns\_server],   [`172.21.0.10`], [Servidor DNS autoritativo con BIND9],
    [dns\_resolver], [`172.21.0.20`], [Nodo resolutor DNS],
    [atacante\_dns], [`172.21.0.99`], [Generador de tráfico malicioso],
  ),
  caption: [Topología del escenario DNS Snooping.]
)

=== La función `alert_dnssnooping`

Implementa detección por umbral con threshold configurable de 5 consultas:

```python
THRESHOLD = 5
LEGIT_DOMAINS = {"www.test.local.", "ns1.test.local.", "test.local."}

def alert_dnssnooping(pkt) -> None:
    qname = pkt[DNSQR].qname.decode().lower()
    if qname not in LEGIT_DOMAINS:
        query_count[ip_src] += 1
        if query_count[ip_src] >= THRESHOLD:
            log.warning("ALERTA DNS SNOOPING | IP: %s | Consultas: %d", ...)
```

=== Script de validación

El script `src/dns_snooping_sim.py` genera 15 consultas DNS a subdominios
aleatorios (`xxxxxxxx.test.local`) con intervalos de 0.5 segundos,
superando el umbral de detección @scapy2024.

=== Evidencias

#figure(
  image("../evidencias/captura_dns_monitor.png", width: 100%),
  caption: [Monitor alert\_dnssnooping detectando consultas sospechosas.]
)

#figure(
  image("../evidencias/captura_dns_ataque.png", width: 100%),
  caption: [Script dns\_snooping\_sim.py generando consultas a subdominios inexistentes.]
)

= Resultados

== ARP Spoofing

#figure(
  table(
    columns: (auto, auto),
    align: (left, left),
    table.header[*Métrica*][*Valor*],
    [Tipo de anomalía detectada],  [Gratuitous ARP + Conflicto IP-MAC],
    [Rondas de ataque],            [10],
    [Paquetes falsos por ronda],   [2 (víctima y router)],
    [Anomalías detectadas],        [20 Gratuitous ARPs],
    [Tiempo de primera alerta],    [menos de 1 segundo],
    [Falsos positivos],            [0],
  ),
  caption: [Resultados de la detección de ARP Spoofing.]
)

== DNS Snooping

#figure(
  table(
    columns: (auto, auto),
    align: (left, left),
    table.header[*Métrica*][*Valor*],
    [Threshold configurado],       [5 consultas sospechosas],
    [Consultas enviadas],          [15],
    [Consultas sospechosas],       [15 todas a subdominios inexistentes],
    [Alerta disparada en],         [quinta consulta],
    [Alertas totales generadas],   [11 desde consulta 5 hasta 15],
    [Falsos positivos],            [0],
  ),
  caption: [Resultados de la detección de DNS Snooping.]
)

= Conclusiones

La implementación de `alert_arpspoof` demuestra que es posible detectar
ataques de ARP Spoofing en tiempo real mediante la monitorización pasiva
del tráfico ARP @rfc826. La detección de Gratuitous ARPs y conflictos IP-MAC
permite identificar el envenenamiento antes de que el atacante pueda
interceptar tráfico significativo.

La función `alert_dnssnooping` evidencia que la detección por umbral es un
método eficaz para identificar el patrón de consultas masivas a subdominios
inexistentes característico del ataque de Kaminsky @kaminsky2008. La
configuración del threshold es crítica para evitar falsos positivos.

El uso de Docker Compose @docker2024 garantiza reproducibilidad y aislamiento
completo. La combinación de Bettercap @bettercap2024 para el ataque ARP y
Scapy @scapy2024 para la generación de tráfico DNS demuestra la flexibilidad
de estas herramientas en entornos de laboratorio.

#pagebreak()
= Bibliografía

#bibliography("references.bib")