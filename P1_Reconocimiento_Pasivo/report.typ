// --- Configuración General del Estilo Académico ---
#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 3cm),
  numbering: "1",
)

#set text(
  font: "New Computer Modern", 
  size: 11pt,
  lang: "es",
  style: "normal", // Forzamos estilo normal por defecto
)

#set heading(numbering: "1.1.")
#show heading: set block(above: 1.4em, below: 1em)

// --- Portada ---
#align(center + horizon)[
  // 1. Imagen ARRIBA del título
  #image("imagenes/logouniversidad.png", width: 30%) 
  #v(1cm) // Espacio entre imagen y título

  #text(12pt, weight: "semibold")[UNIVERSIDAD EUROPEA] \
  #v(0.5cm)
  
  #text(20pt, weight: "bold")[Reporte de Investigación OSINT] \
  
  #text(14pt)[Practica 1: Recogida de Informacion Pasiva]
  
  // 2. Imagen ABAJO del subtítulo
  #v(1cm) // Espacio entre subtítulo e imagen
  #image("imagenes/inditex.png", width: 50%)

  #v(2cm)
  *Presentado por:* \
  Enrique De Pablo Garcia
  
  #v(1cm)
  *Fecha:* \
  #datetime.today().display("[day] de [month repr:long], [year]")

]

#pagebreak()
// --- Resumen (No técnico) ---
#heading(numbering: none)[RESUMEN]
// Se eliminó la regla de set text(style: "italic") que afectaba a este bloque
Este reporte presenta los hallazgos derivados de una investigación de inteligencia de fuentes abiertas (OSINT). En términos sencillos, se ha recopilado y analizado información disponible públicamente en internet para [objetivo de la investigación, ej: identificar la huella digital de una entidad]. No se han utilizado métodos intrusivos, centrándose exclusivamente en la correlación de datos expuestos para extraer conclusiones accionables.




#pagebreak()

// --- Índice ---
#outline(title: "Índice de Contenidos", indent: auto)


#pagebreak()

// --- Introducción ---

== INTRODUCCION
En esta práctica voy a trabajar la fase inicial de una auditoría de ciberseguridad: el reconocimiento pasivo. El objetivo es aprender a recopilar información sobre una empresa sin interactuar directamente con sus sistemas, usando solo técnicas OSINT (inteligencia de fuentes abiertas). De esta forma, la práctica se mantiene dentro de lo legal y ético.

El trabajo se divide en dos partes. Primero, investigo los registros DNS, que son una fuente muy importante de información. Voy a describir qué función tienen registros como A, AAAA, MX, TXT, CNAME, NS, SOA y PTR, y también voy a explicar cuándo consultarlos es reconocimiento pasivo y cuándo se considera activo.

En la segunda parte, hago un análisis OSINT de una empresa del IBEX 35 (Inditex). Elijo una compañía y recojo toda la información pública que pueda encontrar sobre ella: su modelo de negocio, los servicios que ofrece, su infraestructura tecnológica, subdominios, proveedores, presencia en redes sociales y su huella geográfica. También incluyo tres ejemplos de dorking con buscadores.

Es importante tener en cuenta que no puedo usar técnicas activas como escanear puertos con nmap o hacer fuerza bruta. Si lo hiciera, no solo suspendería la asignatura, sino que podría tener problemas legales. Por eso, me voy a limitar a buscar información que ya esté disponible públicamente.




#pagebreak()

== DESARROLLLO
*PARTE 1: INVESTIGACION DE REGISTROS DNS*

*1.1. Descripción de Registros DNS*

- A (Address): Es el registro más básico; vincula un nombre de dominio con una dirección IPv4 (de 32 bits).

- AAAA (IPv6 Address): Cumple la misma función que el registro A, pero vincula el dominio con una dirección IPv6 (de 128 bits).

- MX (Mail Exchange): Especifica los servidores de correo encargados de aceptar mensajes en nombre del dominio, habitualmente ordenados por prioridad.

- TXT (Text): Permite a los administradores insertar texto legible por máquina en el DNS; se usa comúnmente para verificación de propiedad y políticas de seguridad como SPF o DKIM.

- CNAME (Canonical Name): Se utiliza para crear alias, redirigiendo un nombre de dominio o subdominio al nombre "canónico" de otro dominio.

- NS (Name Server): Indica qué servidores de nombres son la autoridad para el dominio, es decir, quién contiene los registros oficiales.

- SOA (Start of Authority): Contiene información administrativa crítica sobre la zona DNS, incluyendo el servidor maestro, el correo del administrador y números de serie para la sincronización.

- PTR (Pointer): Es el inverso del registro A; apunta una dirección IP a un nombre de dominio, utilizándose en las zonas de búsqueda inversa.

#v(1cm)

¿Bajo que condiciones y herramientas la consulta de estos registros se considera reconocimiento pasivo y cuando se convierte en reconocimiento activo?

*Reconocimiento pasivo*

Se considera reconocimiento pasivo cuando la consulta se realiza sin enviar peticiones directas a los servidores DNS de la organización objetivo. Esto se consigue con herramientas online como DNSlytics, SecurityTrails, MXToolbox o ViewDNS.info, que almacenan en sus propias bases de datos registros históricos y actuales sin necesidad de consultar en tiempo real a los servidores autoritativos.

Bajo estas condiciones, la consulta es completamente pasiva porque el analista accede a información ya recopilada por terceros, sin dejar rastro en la infraestructura del objetivo.

#pagebreak()

*Reconocimiento Activo*

La consulta se convierte en reconocimiento activo cuando el analista realiza peticiones directas a los servidores DNS autoritativos del dominio objetivo. En este caso, se genera tráfico que puede quedar registrado en los logs del servidor, alertando potencialmente al propietario del dominio.

Esto ocurre al utilizar herramientas como:

- nslookup o dig desde la terminal, si se consulta directamente a los servidores NS del dominio.

- dnsrecon, theHarvester o fierce en modo activo, cuando realizan consultas en tiempo real a los servidores oficiales.

- Cualquier consulta DNS manual o automatizada que se dirija a los servidores de nombres autoritativos del objetivo.

En resumen, la diferencia clave está en el origen de la información: si se accede a datos ya almacenados por terceros, es pasivo; si se interroga directamente a los servidores del objetivo, se convierte en activo y puede dejar rastro.
#v(0.5cm)
*PARTE 2: AUDITORIA OSINT SOBRE LA EMPRESA IBEX 35*

*2.1 MODELO DE NEGOCIO*

*Modelo de negocio*: 

Inditex desarrolla su actividad en el diseño, fabricación y distribución de moda y accesorios. Cuenta con un modelo integrado verticalmente que le permite controlar toda la cadena de valor, desde el diseño hasta la venta al cliente final. Destaca por su producción en proximidad, con más del 50% de la fabricación concentrada en países cercanos a sus principales mercados (España, Portugal, Marruecos y Turquía). La compañía opera con 5.692 tiendas físicas y presencia online en 22 países. Su estrategia se basa en la renovación constante de colecciones, logrando plazos de entrega de 24 a 48 horas en Europa.




*Clientes:*	

Inditex segmenta su público objetivo a través de sus diferentes marcas:

- Zara: público amplio con posicionamiento mid-market.

- Massimo Dutti: público adulto con poder adquisitivo medio-alto.

- Bershka y Stradivarius: público joven con precios de entrada.

- Lefties: público de bajo coste, compitiendo con Shein y Primark.

La distribución geográfica de sus ventas se estructura de la siguiente manera:

- Europa: 53,5%

- España: 16,1%

- América: 18,2%

- Resto del mundo: 12,2%

#pagebreak()

*Proveedores:*	

Inditex mantiene una red de más de 1.400 proveedores, de los cuales más del 50% se encuentran en zonas de proximidad (España, Portugal, Marruecos y Turquía). La compañía establece relaciones a largo plazo con sus proveedores y exige el cumplimiento de un código de conducta obligatorio. Desde 1998, utiliza una extranet privada para gestionar las comunicaciones y la coordinación con su cadena de suministro.




*Servicios que ofrece:*

Inditex comercializa los siguientes productos:

- Ropa, calzado y accesorios.

- Lencería (Oysho).

- Artículos para el hogar (Zara Home y Lefties Home).

La venta se realiza a través de dos canales:

- Tiendas físicas: presencia global con más de 5.600 establecimientos.

- Canal online: disponible en 22 países, con servicios omnicanal como la compra online y devolución en tienda física.

*2.2 INVESTIGACION DE PRESENCIA DIGITAL*

*1. Servicios y Tecnologías expuestos*

*Analytics y Tracking*

Para realizar la busqueda de informacion de este apartado he utilizado una herramienta llamada *builtwith* (no he encontrado bibliografia para esta herramienta)

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [Brevo (antiguo Sendinblue)], [Email marketing, automatización y CRM],
  [Cloudflare Rocket Loader], [Optimización de carga de recursos],
  [Google Analytics], [Análisis de audiencia y tráfico],
  [Google Analytics 4], [Versión moderna de Google Analytics],
  [Global Site Tag], [Etiqueta principal de Google para medición y conversión],
)

*Widgets y herramientas*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [OneTrust], [Gestión de consentimiento de cookies],
  [Optanon], [Sistema de transparencia de cookies (OneTrust)],
  [Nagich], [Accesibilidad web (proveedor israelí)],
  [WebEx], [Widget para programación de reuniones online],
  [Airtable], [Base de datos y gestión de proyectos],
  [MongoDB], [Base de datos NoSQL],
  [OpenAI], [Uso de GPT y SSO con OpenAI],
  [Slack], [Mensajería para equipos],
)

*Frameworks y librerías*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [Next.js], [Framework React para aplicaciones estáticas],
  [React], [Librería JavaScript para interfaces de usuario],
  [jQuery], [Manipulación de HTML y eventos],
  [GSAP], [Animaciones HTML5 de alto rendimiento],
  [Slick JS], [Carrusel responsive],
  [ASP.NET Ajax], [Framework para experiencias web interactivas],
  [Java EE], [Framework para aplicaciones server-side],
  [Adobe Enterprise Cloud], [Plataforma de contenido y comercio],
)

*CDN y hosting*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [Akamai], [CDN global y hosting],
  [Akamai Edge], [Red de distribución de contenido],
  [Amazon AWS], [Hosting en la nube de Amazon],
  [GStatic Google Static Content], [Contenido estático de Google],
)

*Servidores web*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [Apache], [Servidor web HTTP],
  [nginx], [Servidor HTTP y proxy de correo],
)

*Seguridad y SSL*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [SSL by Default], [Redirección HTTPS por defecto],
  [HSTS], [Forza comunicación solo por HTTPS],
  [DigiCert SSL], [Certificado SSL de DigiCert],
  [GeoTrust SSL], [Certificado SSL de GeoTrust],
  [GlobalSign Domain Verification], [Verificación de dominio para SSL],
)

*Gestión de correo*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [Proofpoint], [Seguridad de correo electrónico],
  [DMARC Reject], [Política DMARC de rechazo],
  [SPF], [Sender Policy Framework para evitar spoofing],
  [Apple iCloud Mail], [Servicio de correo web de Apple],
)

*Registro del dominio*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [ComLaude], [Empresa de gestión de nombres de dominio y protección de marca],
)

*2. Infraestructura y Proveedores*

Para este apartado he utilizado una herramienta llamada dnslytics @bhardwaj2025practical y whois @liu2015learning


*Registro del dominio*

#table(
  columns: 2,
  [*Concepto*], [*Información*],
  [Dominio], [inditex.com],
  [Registrar], [NOM-IQ Ltd dba Com Laude],
  [Fecha de creación], [15 de enero de 1997],
  [Fecha de expiración], [14 de enero de 2034],
  [Estado del dominio], [ACTIVE],
  [Propietario], [Industria de Diseño Textil, S.A. (INDITEX, S.A.)],
  [País del propietario], [España (A Coruña)],
  [Protección de privacidad], [Datos de contacto anonimizados],
)

*Name Servers (Servidores DNS)*

Inditex utiliza los servidores DNS de Akamai, todos ellos con el dominio `akam.net`:

#table(
  columns: 3,
  [*Name Server*], [*IP*], [*Proveedor*],
  [a1-253.akam.net], [193.108.91.253], [Akamai International B.V.],
  [a11-64.akam.net], [84.53.139.64], [Akamai International B.V.],
  [a18-67.akam.net], [95.101.36.67], [Akamai International B.V.],
  [a4-65.akam.net], [72.246.46.65], [Akamai International B.V.],
  [a5-64.akam.net], [95.100.168.64], [Akamai International B.V.],
  [a8-66.akam.net], [2.16.40.66], [Akamai International B.V.],
)

Todos los Name Servers pertenecen a *Akamai International B.V.* (ASN 21342).

*Registros A (Direcciones IP)*

#table(
  columns: 3,
  [*IP*], [*Ubicación geográfica*], [*Proveedor*],
  [23.200.24.104], [Alemania (DE)], [Akamai International B.V.],
  [23.200.24.109], [Alemania (DE)], [Akamai International B.V.],
  [104.97.14.178], [Países Bajos (NL)], [Akamai International B.V.],
)
#pagebreak()
*Servidores de correo (MX)*

#table(
  columns: 4,
  [*Pref.*], [*Hostname*], [*IP*], [*Proveedor*],
  [10], [mxa-005d4502.gslb.pphosted.com], [185.183.31.43 (EE.UU.)], [Proofpoint, Inc.],
  [20], [mxb-005d4502.gslb.pphosted.com], [205.220.184.36 (Alemania)], [Proofpoint, Inc.],
)

El proveedor de seguridad de correo electrónico es *Proofpoint, Inc.* (ASN 52129).

*SPF (Sender Policy Framework)*

`v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all`

La política SPF utiliza `-all`, lo que indica que cualquier correo que no provenga de los servidores autorizados debe ser rechazado (fail).

*Proveedores principales*

#table(
  columns: 2,
  [*Categoría*], [*Proveedor*],
  [Registrar del dominio], [Com Laude (NOM-IQ Ltd)],
  [DNS (Name Servers)], [Akamai International B.V.],
  [CDN y hosting], [Akamai (red global de servidores)],
  [Seguridad de correo], [Proofpoint, Inc.],
  [Infraestructura cloud], [Amazon AWS],
)
* Dominios relacionados*

Inditex protege su marca registrando el dominio en múltiples extensiones geográficas y genéricas. Se han identificado más de 50 dominios relacionados, incluyendo:

#table(
  columns: 4,
  [inditex.es], [inditex.nl], [inditex.mx], [inditex.com.ar],
  [inditex.co.uk], [inditex.fr], [inditex.de], [inditex.pt],
  [inditex.cl], [inditex.cloud], [inditex.it], [inditex.org],
)

La mayoría de estos dominios comparten la misma infraestructura DNS de Akamai, lo que indica una gestión centralizada y corporativa de la marca.

*Resumen de infraestructura*

La infraestructura digital de Inditex se apoya en proveedores de primer nivel:

- *Com Laude* como gestor estratégico de su portfolio de dominios.
- *Akamai* como proveedor de DNS, CDN y hosting a nivel global.
- *Proofpoint* como solución de seguridad para el correo electrónico.
- *Amazon AWS* complementando la infraestructura en la nube.

#pagebreak()

*3. Huella Digital Geografica*

Para este apartado apartir de los resultados del apartado anterior (IPs),he utilizado una herramienta llamada IPinfo @deshoullieres2004ipinfo

*Geolocalización de servidores*

Las direcciones IP asociadas al dominio inditex.com se encuentran distribuidas en centros de datos de Akamai en Europa. A continuación se detalla la geolocalización de cada IP:

#table(
  columns: 5,
  [*IP*], [*País*], [*Ciudad*], [*Coordenadas*], [*Proveedor*],
  [23.200.24.104], [Alemania], [Berlín], [52.5244 N, 13.4105 E], [Akamai International B.V.],
  [23.200.24.109], [Alemania], [Berlín], [52.5244 N, 13.4105 E], [Akamai International B.V.],
  [104.97.14.178], [Países Bajos], [Ámsterdam], [52.374 N, 4.8897 E], [Akamai International B.V.],
)

*Detalles por IP*

*IP 23.200.24.104*

- *Hostname*: a23-200-24-104.deploy.static.akamaitechnologies.com
- *ASN*: AS20940 (Akamai International B.V.)
- *Rango*: 23.200.24.0/24
- *Ubicación*: Berlín, Estado de Berlín, Alemania
- *Código postal*: 10119
- *Zona horaria*: Europe/Berlin
- *Tipo de red*: Hosting
- *Anycast*: No

*IP 23.200.24.109*

- *Hostname*: a23-200-24-109.deploy.static.akamaitechnologies.com
- *ASN*: AS20940 (Akamai International B.V.)
- *Rango*: 23.200.24.0/24
- *Ubicación*: Berlín, Estado de Berlín, Alemania
- *Código postal*: 10119
- *Zona horaria*: Europe/Berlin
- *Tipo de red*: Hosting

*IP 104.97.14.178*

- *Hostname*: a104-97-14-178.deploy.static.akamaitechnologies.com
- *ASN*: AS20940 (Akamai International B.V.)
- *Rango*: 104.97.14.0/23
- *Ubicación*: Ámsterdam, Holanda Septentrional, Países Bajos
- *Código postal*: 1012
- *Zona horaria*: Europe/Amsterdam
- *Tipo de red*: Hosting

#pagebreak()

Análisis geográfico

Todos los servidores analizados pertenecen a *Akamai International B.V.* (AS20940), uno de los principales proveedores de CDN (Content Delivery Network) a nivel mundial.

La distribución geográfica se concentra en Europa Central y Occidental:
- *Berlín, Alemania*: dos servidores ubicados en la capital alemana.
- *Ámsterdam, Países Bajos*: un servidor ubicado en un importante centro de interconexión europeo.

Esta estrategia de distribución permite a Inditex ofrecer bajos tiempos de latencia a sus usuarios en Europa, especialmente en países como España, donde se concentra gran parte de su mercado. La proximidad de los servidores a los centros logísticos de la compañía en España, Portugal y Marruecos también facilita la rápida renovación de colecciones y los plazos de entrega de 24-48 horas que caracterizan su modelo de negocio.

Contacto de abuso

Para todos los servidores analizados, el contacto de abuso es el mismo:

- *Correo electrónico*: abuse akamai.com
- *Teléfono*: +1-617-444-2535
- *Dirección*: 8 Cambridge Center, Mailstop 926-G, Cambridge, MA 02142, EE.UU.


*4. Exposición de activos*

*Subdominios identificados*

El análisis realizado con las herramientas DNSdumpster y Censys ha permitido identificar un gran número de subdominios asociados a inditex.com. A continuación se presentan los más relevantes, agrupados por categorías:

*Autenticación y seguridad*

#table(
  columns: 3,
  [*Subdominio*], [*IP / Proveedor*], [*Descripción*],
  [adfs.inditex.com], [195.77.161.140 (Telefónica, España)], [Active Directory Federation Services],
  [certauth.adfs.inditex.com], [195.77.161.140], [Autoridad de certificación para ADFS],
  [adfspre.inditex.com], [195.77.161.141], [Entorno de pre-producción de ADFS],
  [auth.inditex.com], [Akamai], [Servicio de autenticación],
  [workspace.inditex.com], [Citrix Netscaler], [Portal de acceso para empleados (Citrix Workspace)],
  [itxvpro.inditex.com], [195.77.161.137], [Intel Endpoint Management Assistant],
)
#pagebreak()
*Correo electrónico*

#table(
  columns: 3,
  [*Subdominio*], [*IP / Proveedor*], [*Descripción*],
  [autodiscover.inditex.com], [195.77.161.26], [Descubrimiento automático de correo (Outlook)],
)

*Comercio electrónico y servicios*

#table(
  columns: 3,
  [*Subdominio*], [*IP / Proveedor*], [*Descripción*],
  [commerce.inditex.com], [Akamai], [Plataforma de comercio electrónico],
  [zara-resell.pro.awscl.inditex.com], [Amazon AWS (Irlanda)], [Plataforma de reventa Zara Resell (producción)],
  [mobilevsp.inditex.com], [195.77.161.104], [Servicios móviles],
)

*APIs y microservicios*

#table(
  columns: 3,
  [*Subdominio*], [*IP / Proveedor*], [*Descripción*],
  [api.purchaseweuocp1.paas01weu.iopcompclo.azcl.inditex.com], [Microsoft Azure (Países Bajos)], [API de compras en plataforma IOP],
  [api.idpcloudpre1.idpcloud-pre.paas.azcl.inditex.com], [Microsoft Azure (España)], [API de Identity Platform (pre-producción)],
  [api.financepro1.finance.paas.azcl.inditex.com], [Microsoft Azure (España)], [API de servicios financieros (producción)],
)

*Entornos de desarrollo y pruebas*

#table(
  columns: 3,
  [*Subdominio*], [*IP / Proveedor*], [*Descripción*],
  [dev-alejandria.azcl.inditex.com], [Microsoft Azure (Países Bajos)], [Entorno de desarrollo "Alejandria"],
  [datagravity-047.azcl.inditex.com], [Microsoft Azure (Países Bajos)], [Servicio Data Gravity en Azure],
  [*.pre.awscl.inditex.com*], [Amazon AWS], [Subdominios en entorno de pre-producción],
  [*.dev.awscl.inditex.com*], [Amazon AWS], [Subdominios en entorno de desarrollo],
)

*Comunicación y contenido*

#table(
  columns: 3,
  [*Subdominio*], [*IP / Proveedor*], [*Descripción*],
  [blogs.inditex.com], [Akamai], [Blog corporativo de Inditex],
  [annualreport2023.inditex.com], [Amazon AWS (EE.UU.)], [Informe anual 2023],
)
#pagebreak()
*Certificados SSL identificados*

El análisis en Censys revela múltiples certificados SSL asociados a los subdominios de Inditex:

#table(
  columns: 3,
  [*Certificado*], [*Subdominios asociados*], [*Emisor*],
  [*.inditex.com*], [inditex.com, auth.inditex.com, commerce.inditex.com], [INDUSTRIA DE DISEÑO TEXTIL SA],
  [blogs.inditex.com], [blogs.inditex.com], [INDUSTRIA DE DISEÑO TEXTIL SA],
  [commerce.inditex.com], [commerce.inditex.com], [INDUSTRIA DE DISEÑO TEXTIL SA],
  [*.cloud.inditex.com*], [datagravity-047.azcl.inditex.com, dev-alejandria.azcl.inditex.com], [Industria de Diseño Textil, S.A.],
  [*.docs.inditex.com*], [subdominios de documentación], [Industria de Diseño Textil, S.A.],
  [workspace.inditex.com], [workspace.inditex.com, receiver.ar.inditex.com], [INDUSTRIA DE DISEÑO TEXTIL SA],
  [itxvpro.inditex.com], [itxvpro.inditex.com], [INDUSTRIA DE DISEÑO TEXTIL SA],
  [mobilevsp.inditex.com], [mobilevsp.inditex.com], [INDUSTRIA DE DISEÑO TEXTIL SA],
)

*Dispositivos expuestos y tecnologías*

El escaneo pasivo de las direcciones IP asociadas a inditex.com ha permitido identificar los siguientes servicios expuestos:

#table(
  columns: 3,
  [*IP*], [*Servicio / Puerto*], [*Tecnología detectada*],
  [195.77.161.140], [HTTPS (443)], [ADFS (Active Directory Federation Services)],
  [195.77.161.137], [HTTPS (443)], [Intel Endpoint Management Assistant],
  [195.77.161.104], [HTTPS (7443)], [Servicios móviles (mobilevsp)],
  [20.187.182.105], [HTTPS (443)], [Citrix Netscaler Gateway],
  [4.207.34.36], [HTTPS (443)], [Azure Application Gateway],
  [51.105.110.81], [HTTPS (443)], [Azure Application Gateway],
  [54.217.109.123], [HTTPS (443)], [Varnish Cache],
  [23.200.24.104], [HTTPS (443)], [Akamai App and API Protector + Akamai Ghost],
  [23.200.24.109], [HTTPS (443)], [Akamai App and API Protector + Akamai Ghost],
)

*Tecnologías de seguridad detectadas*

#table(
  columns: 2,
  [*Tecnología*], [*Función*],
  [Akamai App and API Protector], [WAF (Web Application Firewall)],
  [Akamai Ghost], [CDN y red de distribución de contenido],
  [Azure Application Gateway], [Balanceador de carga y WAF en Azure],
  [Citrix Netscaler], [Balanceador de carga y portal de acceso remoto],
  [Varnish Cache], [Proxy inverso y caché HTTP],
  [SSL by Default], [Redirección automática a HTTPS],
  [HSTS], [Forzado de comunicación segura],
)

*Resumen de activos expuestos por categoría*

#table(
  columns: 2,
  [*Categoría*], [*Subdominios / Activos*],
  [Autenticación], [adfs.inditex.com, auth.inditex.com, workspace.inditex.com],
  [Correo electrónico], [autodiscover.inditex.com],
  [Comercio electrónico], [commerce.inditex.com, zara-resell.pro.awscl.inditex.com],
  [APIs], [api.purchaseweuocp1..., api.idpcloudpre1..., api.financepro1...],
  [Desarrollo y pruebas], [*.pre.awscl.inditex.com, *.dev.awscl.inditex.com, dev-alejandria.azcl.inditex.com],
  [Entornos cloud], [AWS (Irlanda, Alemania, EE.UU.), Azure (Países Bajos, España)],
  [Comunicación], [blogs.inditex.com, annualreport2023.inditex.com],
  [Infraestructura interna], [itxvpro.inditex.com, mobilevsp.inditex.com],
)

*5. Presencia en Redes Sociales*
*Presencia en redes sociales*

Inditex mantiene una presencia activa en las principales redes sociales, enfocada principalmente en comunicación corporativa, atracción de talento y difusión de sus resultados. A continuación se detallan los perfiles oficiales identificados.

*LinkedIn*

- *Perfil oficial*: https://www.linkedin.com/company/inditex
- *Seguidores*: más de 1.747.000

La página corporativa de Inditex en LinkedIn es el canal principal para la difusión de contenidos institucionales. Entre las publicaciones más destacadas se encuentran:

- Resultados financieros anuales y trimestrales
- Vídeos corporativos sobre cultura de empresa
- Iniciativas de sostenibilidad e inclusión (programa for&from, programa INCLUYE)
- Reconocimientos como el certificado Top Employer, obtenido por tercer año consecutivo en países como España, Alemania, Francia, Italia, México, China y Australia
- Ofertas de empleo y desarrollo profesional

La compañía destaca que el *80% de las vacantes* se cubren mediante promoción interna, con más de 9.100 profesionales ascendidos.

*X (anteriormente Twitter)*

- *Perfil oficial*: https://x.com/InditexSpain
- *Fecha de creación*: septiembre de 2013


Este perfil está orientado al público español. Actualmente no presenta actividad reciente de publicaciones, aunque se mantiene como canal oficial verificado de la compañía.

*YouTube*

- *Perfil oficial*: https://www.youtube.com/@InditexCareersOfficial
- *Vídeos publicados*: 53

El canal de YouTube está orientado a *Inditex Careers* (talento y empleo). Los contenidos incluyen:

- Testimonios de empleados
- Cultura corporativa y valores
- Procesos de selección
- Experiencias de inclusión laboral (programa INCLUYE)

El canal promociona la web `inditexcareers.com` para la búsqueda de ofertas de empleo en las marcas del grupo.

*Instagram*

- *Perfil oficial*: https://www.instagram.com/inditexcareers

Perfil enfocado en la atracción de talento, con contenido visual sobre oportunidades laborales, vida en la compañía y eventos corporativos.

*Perfiles de las marcas del grupo*

Además de los perfiles corporativos, Inditex gestiona perfiles independientes para cada una de sus marcas, orientados a producto, marketing y atención al cliente:

| Marca | Plataformas principales |
|-------|------------------------|
| Zara | Instagram, TikTok, X, YouTube, Facebook |
| Pull&Bear | Instagram, TikTok, X, YouTube, Facebook |
| Massimo Dutti | Instagram, X, YouTube, Facebook |
| Bershka | Instagram, TikTok, X, YouTube, Facebook |
| Stradivarius | Instagram, TikTok, X, YouTube, Facebook |
| Oysho | Instagram, X, YouTube, Facebook |
| Zara Home | Instagram, X, YouTube, Facebook |
| Lefties | Instagram, Facebook |

*Resumen de presencia en redes sociales*

#table(
  columns: 3,
  [*Red social*], [*Perfil oficial*], [*Enfoque principal*],
  [LinkedIn], [inditex], [Corporativo, resultados, talento, sostenibilidad],
  [X], [InditexSpain], [Corporativo España],
  [YouTube], [InditexCareersOfficial], [Talento y empleo],
  [Instagram], [inditexcareers], [Atracción de talento y cultura de empresa],


)
#pagebreak()
*6. 3 Ejemplos de Dorking*

*Dorking*

El dorking consiste en el uso de operadores de búsqueda avanzada en motores como Google para localizar información sensible o no destinada a ser pública, sin interactuar directamente con los sistemas objetivo. A continuación se presentan tres ejemplos originales y avanzados que simulan consultas realistas en una auditoría OSINT.

*Ejemplo 1 – Credenciales y configuraciones expuestas en repositorios públicos*

`site:github.com "inditex" ("password" | "secret" | "token" | "api_key" | "client_secret") -"example"`

*Explicación*: Busca en repositorios públicos de GitHub que contengan la palabra "inditex" junto con términos asociados a credenciales sensibles. Excluye "example" para evitar falsos positivos de documentación de ejemplo. Un atacante buscaría aquí claves API, tokens de acceso o contraseñas en texto plano que puedan haber sido subidas accidentalmente por desarrolladores.

*Ejemplo 2 – Panel de administración o backend expuesto sin autenticación*

`site:inditex.com inurl:("admin" | "login" | "panel" | "dashboard" | "backoffice" | "console") -"login?returnUrl" -"login/error"`

*Explicación*: Busca URLs que contengan palabras clave típicas de paneles de administración dentro del dominio inditex.com. Filtra resultados comunes como páginas de error de login para reducir ruido. Un atacante buscaría accesos a interfaces de gestión que podrían estar mal protegidas o tener credenciales por defecto.

*Ejemplo 3 – Archivos de respaldo, logs o datos sensibles indexados*

`site:inditex.com ext:(sql | bak | log | conf | env | json | yaml) -"example" -"sample"`

*Explicación*: Busca archivos con extensiones peligrosas que suelen contener información sensible: volcados de bases de datos (.sql), copias de seguridad (.bak), registros de depuración (.log), archivos de configuración (.conf), variables de entorno (.env) y archivos de configuración en formato JSON o YAML. Un atacante buscaría archivos que nunca deberían estar accesibles públicamente, como backups olvidados en servidores mal configurados.
#pagebreak()

#bibliography("references.bib", style: "apa")
