# Proyecto: Mapeo de Infraestructura de Red para Colegio Multisede

## 1. Contexto

El colegio cuenta con varias sedes y requiere realizar un levantamiento de su infraestructura de red actual.

El objetivo inicial no es implementar una plataforma compleja de monitoreo ni una arquitectura distribuida, sino obtener una fotografía técnica de cómo está organizada actualmente la red en cada sede para posteriormente analizar oportunidades de mejora.

La solución debe permitir descubrir equipos conectados a la red, registrar su información técnica y representar visualmente la topología de red mediante una interfaz web.

---

## 2. Objetivo general

Construir una aplicación monolítica y liviana que permita:

- Detectar dispositivos conectados a la red.
- Identificar información básica de cada equipo.
- Clasificar los dispositivos encontrados.
- Obtener información adicional de routers, switches y access points cuando sea posible.
- Identificar relaciones entre dispositivos.
- Construir un mapa visual de la infraestructura de red.
- Permitir completar manualmente información que no pueda descubrirse automáticamente.
- Utilizar la información obtenida como base para analizar mejoras en la infraestructura del colegio.

---

## 3. Objetivo de la primera versión

La primera versión debe responder principalmente a las siguientes preguntas:

1. ¿Qué equipos existen actualmente en la red?
2. ¿Qué IP y MAC tiene cada equipo?
3. ¿Qué fabricante corresponde a cada dispositivo?
4. ¿Qué tipo de dispositivo es?
5. ¿Cuáles son routers, switches, access points, servidores, impresoras, cámaras y PCs?
6. ¿Cómo están conectados entre sí los equipos principales?
7. ¿Qué equipos pertenecen a cada sede?
8. ¿Qué información debe completarse manualmente?
9. ¿Qué problemas o puntos de mejora pueden observarse en la infraestructura actual?

---

## 4. Alcance inicial

La aplicación estará enfocada en el levantamiento y visualización de infraestructura.

### Incluido

- Descubrimiento de red.
- Detección de IP.
- Detección de MAC.
- Resolución de hostname.
- Identificación aproximada del fabricante.
- Identificación básica del tipo de equipo.
- Detección de gateway.
- Detección de rango de red.
- Escaneo mediante Nmap.
- Consulta SNMP cuando exista acceso.
- Consulta LLDP/CDP cuando exista soporte y acceso.
- Registro de switches.
- Registro de routers/firewalls.
- Registro de access points.
- Registro de servidores.
- Registro de impresoras.
- Registro de PCs.
- Registro de cámaras u otros dispositivos.
- Registro de interfaces.
- Registro de conexiones.
- Registro de VLAN cuando pueda obtenerse.
- Mapa visual de la red.
- Inventario en formato tabla.
- Edición manual de dispositivos.
- Clasificación por sede.
- Guardado local de la información.
- Visualización web.

### Fuera del alcance inicial

Por ahora no se requiere:

- Microservicios.
- Agentes distribuidos.
- Kubernetes.
- Cloud Run.
- Alta disponibilidad.
- Alertas en tiempo real.
- Monitoreo 24/7.
- Histórico complejo de métricas.
- Sistema de tickets.
- Gestión automática de configuración.
- Corrección automática de configuraciones.
- Integración con Active Directory.
- Integración con sistemas académicos.
- Aplicación móvil.
- SIEM.
- IDS/IPS.
- Automatización de cambios de red.

Estas funciones podrían evaluarse posteriormente.

---

# 5. Arquitectura propuesta

La solución inicial será un monolito.

```text
┌─────────────────────────────────────┐
│             PYTHON APP              │
│                                     │
│  Flask                              │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ Descubrimiento de red         │  │
│  │                               │  │
│  │ ARP                           │  │
│  │ ICMP / Ping                   │  │
│  │ Nmap                          │  │
│  │ SNMP                          │  │
│  │ LLDP/CDP                      │  │
│  │ DNS / Hostname                │  │
│  └───────────────┬───────────────┘  │
│                  │                  │
│  ┌───────────────▼───────────────┐  │
│  │ Procesamiento                 │  │
│  │                               │  │
│  │ Clasificación                 │  │
│  │ Identificación                │  │
│  │ Relaciones                   │  │
│  │ Topología                    │  │
│  └───────────────┬───────────────┘  │
│                  │                  │
│  ┌───────────────▼───────────────┐  │
│  │ SQLite                        │  │
│  │                               │  │
│  │ Dispositivos                  │  │
│  │ Interfaces                    │  │
│  │ Conexiones                    │  │
│  │ Sedes                         │  │
│  │ VLAN                          │  │
│  └───────────────┬───────────────┘  │
└──────────────────┼──────────────────┘
                   │
                   ▼
          HTML + CSS + JavaScript
                   │
          Bootstrap / CSS
                   │
             Cytoscape.js
                   │
                   ▼
               MAPA DE RED
```

---

# 6. Stack tecnológico

## Backend

### Python

Será el lenguaje principal.

Responsabilidades:

- Detectar interfaces de red.
- Obtener IP local.
- Obtener máscara.
- Obtener gateway.
- Determinar la subred.
- Ejecutar descubrimiento.
- Ejecutar Nmap.
- Consultar SNMP.
- Procesar resultados.
- Clasificar dispositivos.
- Construir relaciones.
- Persistir información.
- Exponer información al frontend.

---

## Framework web

### Flask

Para la primera versión se recomienda Flask por ser simple y suficiente para el proyecto.

Ejemplo de ejecución:

```bash
python app.py
```

Aplicación:

```text
http://localhost:5000
```

FastAPI también es una alternativa válida, pero Flask simplifica la primera implementación.

---

## Base de datos

### SQLite

Para el MVP no es necesario PostgreSQL.

Ventajas:

- No requiere instalar un servidor de base de datos.
- Archivo local.
- Fácil respaldo.
- Fácil portabilidad.
- Suficiente para inventario y topología.
- Ideal para ejecutar la aplicación desde una laptop.

Archivo sugerido:

```text
network.db
```

Más adelante podría migrarse a PostgreSQL.

---

## Frontend

Se utilizará:

- HTML.
- CSS.
- JavaScript.
- Bootstrap opcional.
- Cytoscape.js.

No será necesario Angular para la primera versión.

---

# 7. Librerías y herramientas

## Herramientas del sistema

### Nmap

Utilizado para descubrimiento y análisis de hosts.

Ejemplo:

```bash
nmap -sn 192.168.1.0/24
```

También puede utilizarse para detectar puertos y servicios.

---

## Librerías Python

### Standard Library

```text
subprocess
socket
ipaddress
platform
json
sqlite3
```

---

### python-nmap

Para ejecutar y procesar resultados de Nmap desde Python.

```text
python-nmap
```

---

### pysnmp

Para consultar dispositivos mediante SNMP.

```text
pysnmp
```

---

### netaddr

Puede utilizarse para manejo de direcciones MAC/IP.

```text
netaddr
```

---

### psutil

Útil para obtener interfaces de red locales.

```text
psutil
```

---

# 8. Estructura propuesta del proyecto

```text
network-mapper/
│
├── app.py
│
├── requirements.txt
│
├── network.db
│
├── config.py
│
├── scanner/
│   │
│   ├── __init__.py
│   ├── network.py
│   ├── arp.py
│   ├── ping.py
│   ├── nmap_scanner.py
│   ├── snmp.py
│   ├── lldp.py
│   ├── vendor.py
│   ├── classifier.py
│   └── topology.py
│
├── services/
│   │
│   ├── discovery_service.py
│   ├── device_service.py
│   └── topology_service.py
│
├── repositories/
│   │
│   ├── device_repository.py
│   ├── site_repository.py
│   └── topology_repository.py
│
├── templates/
│   │
│   ├── index.html
│   ├── devices.html
│   ├── device_detail.html
│   ├── topology.html
│   └── sites.html
│
└── static/
    │
    ├── css/
    │   └── style.css
    │
    └── js/
        ├── app.js
        └── topology.js
```

---

# 9. Flujo general

```text
Usuario abre navegador
          │
          ▼
http://localhost:5000
          │
          ▼
Selecciona sede
          │
          ▼
[ ESCANEAR RED ]
          │
          ▼
Python obtiene:
IP local
Máscara
Gateway
          │
          ▼
Calcula rango de red
Ejemplo:
192.168.10.0/24
          │
          ▼
Descubre dispositivos
          │
          ▼
ARP / Ping / Nmap
          │
          ▼
Obtiene:
IP
MAC
Hostname
Fabricante
Puertos
          │
          ▼
Intenta clasificar dispositivo
          │
          ▼
SNMP / LLDP si está disponible
          │
          ▼
Construye relaciones
          │
          ▼
Guarda resultados en SQLite
          │
          ▼
Genera JSON de topología
          │
          ▼
Cytoscape.js
          │
          ▼
Mapa visual
```

---

# 10. Detección inicial de red

La aplicación debe obtener automáticamente:

- IP local.
- Interfaz activa.
- Máscara.
- Gateway.
- Red.
- CIDR.
- DNS.

Ejemplo:

```text
IP:
10.10.20.53

Máscara:
255.255.255.0

Gateway:
10.10.20.1

Red:
10.10.20.0/24
```

La aplicación debería mostrar esta información antes del escaneo.

---

# 11. Descubrimiento de dispositivos

El primer nivel será encontrar los dispositivos activos.

Ejemplo:

```text
192.168.10.1
192.168.10.2
192.168.10.3
192.168.10.15
192.168.10.20
192.168.10.30
```

Para cada dispositivo se intentará obtener:

```text
IP
MAC
Hostname
Fabricante
Estado
Latencia
Puertos abiertos
Servicios
```

---

# 12. Identificación del fabricante

La dirección MAC permite identificar aproximadamente el fabricante mediante el prefijo OUI.

Ejemplo:

```text
MAC:
FC:EC:DA:XX:XX:XX

Fabricante:
Ubiquiti Networks
```

Esto ayudará a clasificar dispositivos.

Ejemplos de fabricantes que podrían aparecer:

- Cisco.
- Fortinet.
- Ubiquiti.
- TP-Link.
- MikroTik.
- HP.
- Aruba.
- Dell.
- Lenovo.
- Hikvision.
- Dahua.
- Epson.
- Brother.
- Huawei.

---

# 13. Clasificación de dispositivos

La aplicación intentará determinar el tipo de dispositivo.

Tipos iniciales:

```text
ROUTER
FIREWALL
SWITCH
ACCESS_POINT
SERVER
PC
LAPTOP
PRINTER
CAMERA
NVR
UPS
PHONE
CONTROLLER
UNKNOWN
```

La clasificación puede utilizar:

- Fabricante.
- Puertos abiertos.
- Servicios.
- SNMP.
- Hostname.
- Información LLDP.
- Reglas internas.

Ejemplo:

```text
192.168.1.1
Marca: Fortinet
Puertos: 80, 443
SNMP: Fortigate 60F

Tipo:
FIREWALL
```

---

# 14. SNMP

SNMP será una pieza importante para obtener información detallada.

Se recomienda utilizar SNMP solamente con autorización y credenciales proporcionadas por el responsable de TI.

Preferencia:

```text
SNMPv3
```

Información que puede obtenerse:

- Fabricante.
- Modelo.
- Serial.
- Uptime.
- Interfaces.
- Estado de interfaces.
- Velocidad.
- Descripción de puertos.
- VLAN.
- Tabla MAC.
- Tabla ARP.
- Puertos activos.
- Puertos inactivos.

Ejemplo:

```text
SW-CORE

Modelo:
Cisco CBS350

Puerto 1:
UP

Puerto 2:
UP

Puerto 3:
DOWN

Puerto 24:
UP
```

---

# 15. LLDP y CDP

LLDP/CDP permitirá identificar conexiones reales entre equipos de infraestructura.

Ejemplo:

```text
SWITCH-A
Puerto Gi0/24

Vecino:
SWITCH-CORE

Puerto remoto:
Gi0/5
```

Esto permite construir:

```text
SWITCH-A Gi0/24
        │
        │
        ▼
SWITCH-CORE Gi0/5
```

LLDP será especialmente útil para:

- Switch → Switch.
- Switch → Router.
- Switch → Firewall.
- Switch → Access Point.

CDP puede utilizarse principalmente en infraestructura Cisco.

---

# 16. Tabla MAC de switches

Cuando sea posible acceder mediante SNMP, la tabla MAC permitirá identificar qué dispositivos están detrás de qué puertos.

Ejemplo:

```text
SW-01

Port 1
AA:BB:CC:11:22:33

Port 2
AA:BB:CC:44:55:66

Port 24
SW-CORE
```

Esto permitirá mejorar la construcción automática del mapa.

---

# 17. Access Points

Los access points deben identificarse como equipos separados.

Información deseada:

- IP.
- MAC.
- Hostname.
- Marca.
- Modelo.
- Estado.
- Switch al que están conectados.
- Puerto del switch.
- SSID cuando sea posible.
- VLAN cuando sea posible.

Dependiendo de la marca pueden existir controladores:

- UniFi Controller.
- Omada Controller.
- Aruba Controller.
- Cisco Controller.
- Fortinet/FortiAP.
- Ruckus.

En una primera versión no es obligatorio consumir las APIs de estos controladores.

---

# 18. Topología

El objetivo es representar visualmente relaciones.

Ejemplo:

```text
                       INTERNET
                          │
                     FIREWALL
                          │
                       SW-CORE
                ┌─────────┼─────────┐
                │         │         │
             SERVER    SW-PISO1  SW-PISO2
                           │         │
                        AP-01     AP-02
                          │          │
                     ┌────┴───┐  ┌──┴────┐
                     PC      PC  PC      PC
```

---

# 19. Cytoscape.js

Cytoscape.js será utilizado para representar la topología.

Python entregará datos similares a:

```json
{
  "nodes": [
    {
      "id": "firewall01",
      "label": "Firewall",
      "type": "firewall",
      "ip": "192.168.1.1"
    },
    {
      "id": "sw-core",
      "label": "Core Switch",
      "type": "switch",
      "ip": "192.168.1.2"
    },
    {
      "id": "ap01",
      "label": "AP-01",
      "type": "access_point",
      "ip": "192.168.1.20"
    }
  ],
  "edges": [
    {
      "source": "firewall01",
      "target": "sw-core"
    },
    {
      "source": "sw-core",
      "target": "ap01"
    }
  ]
}
```

El frontend podrá generar automáticamente el mapa.

---

# 20. Modelo de datos inicial

## Tabla: sites

```text
id
name
description
address_reference
created_at
updated_at
```

Ejemplo:

```text
Sede Central
Sede Primaria
Sede Secundaria
Sede Inicial
```

---

## Tabla: networks

```text
id
site_id
name
cidr
gateway
vlan_id
description
```

---

## Tabla: devices

```text
id
site_id
network_id
ip
mac
hostname
vendor
model
serial_number
device_type
location
status
description
last_seen
created_at
updated_at
```

---

## Tabla: interfaces

```text
id
device_id
name
mac
ip
speed
status
description
vlan_id
```

---

## Tabla: connections

```text
id
source_device_id
source_interface_id
target_device_id
target_interface_id
connection_type
discovery_method
confidence
created_at
updated_at
```

---

## Tabla: vlans

```text
id
site_id
vlan_id
name
description
subnet
```

---

# 21. Métodos de descubrimiento

Cada relación encontrada debe registrar su fuente.

Valores posibles:

```text
MANUAL
ARP
NMAP
SNMP
LLDP
CDP
CONTROLLER_API
MAC_TABLE
```

También puede guardarse un nivel de confianza:

```text
HIGH
MEDIUM
LOW
```

Ejemplo:

```text
SW-CORE → SW-PISO2

Método:
LLDP

Confianza:
HIGH
```

---

# 22. Edición manual

La aplicación debe permitir completar información manualmente.

Esto es importante porque el descubrimiento automático no podrá obtener necesariamente toda la información.

Ejemplo:

```text
IP:
192.168.1.2

Hostname:
SWITCH-001

Nombre:
SW-CORE-SEDE-CENTRAL

Tipo:
SWITCH

Ubicación:
Datacenter principal

Rack:
Rack 01

Piso:
1

Marca:
Cisco

Modelo:
CBS350-48T
```

La información manual no debe perderse durante nuevos escaneos.

---

# 23. Pantalla principal

Propuesta:

```text
┌────────────────────────────────────────────────┐
│ Infraestructura de Red - Colegio               │
│                                                │
│ Sede: [ Sede Central ▼ ]                       │
│                                                │
│ Red detectada: 192.168.10.0/24                 │
│ Gateway:       192.168.10.1                    │
│                                                │
│ [ ESCANEAR RED ]                               │
├────────────────────────────────────────────────┤
│                                                │
│                INTERNET                        │
│                   │                            │
│              FIREWALL                          │
│                   │                            │
│               CORE-SW                          │
│           ┌───────┼───────┐                    │
│         SW-01   SW-02   SERVER                 │
│         /  \      │                            │
│      AP-01 AP-02 AP-03                         │
│                                                │
├────────────────────────────────────────────────┤
│ Equipos: 43                                    │
│ Switches: 5                                    │
│ AP: 8                                          │
│ Servidores: 3                                  │
│ PCs: 22                                        │
└────────────────────────────────────────────────┘
```

---

# 24. Pantalla de inventario

Tabla:

```text
Equipo
IP
MAC
Hostname
Tipo
Fabricante
Modelo
Estado
Sede
Ubicación
```

Ejemplo:

```text
SW-CORE
192.168.10.2
AA:BB:CC:DD:EE:FF
SW-CORE
Switch
Cisco
CBS350
Online
Sede Central
Datacenter
```

---

# 25. Detalle de dispositivo

Ejemplo:

```text
SW-CORE

IP:
192.168.10.2

MAC:
AA:BB:CC:DD:EE:FF

Fabricante:
Cisco

Modelo:
CBS350-24T

Sede:
Sede Central

Ubicación:
Datacenter

Estado:
Online

Uptime:
125 días
```

Interfaces:

```text
Puerto 1  → Firewall
Puerto 2  → Servidor
Puerto 3  → AP-01
Puerto 4  → AP-02
Puerto 20 → SW-PISO1
Puerto 24 → SW-PISO2
```

---

# 26. Escaneo

El botón:

```text
ESCANEAR RED
```

debe realizar el descubrimiento.

Flujo:

```text
Detectar interfaz activa
        ↓
Obtener IP local
        ↓
Obtener máscara
        ↓
Obtener gateway
        ↓
Calcular subnet
        ↓
Ejecutar descubrimiento
        ↓
Identificar hosts
        ↓
Procesar MAC
        ↓
Resolver hostname
        ↓
Detectar fabricante
        ↓
Ejecutar Nmap
        ↓
Intentar SNMP
        ↓
Intentar LLDP
        ↓
Guardar resultados
        ↓
Actualizar mapa
```

---

# 27. Progreso del escaneo

La interfaz podría mostrar:

```text
Escaneando red 192.168.10.0/24

[✓] Gateway detectado
[✓] 54 hosts encontrados
[✓] Direcciones MAC procesadas
[✓] Fabricantes identificados
[ ] Consultando servicios
[ ] Consultando SNMP
[ ] Construyendo topología
```

Al finalizar:

```text
Escaneo completado.

54 dispositivos encontrados.

Routers / Firewall: 2
Switches: 7
Access Points: 10
Servidores: 4
Impresoras: 6
Computadoras: 19
Otros: 6
```

---

# 28. Varias sedes

La aplicación debe manejar cada sede de forma independiente.

Ejemplo:

```text
COLEGIO
│
├── SEDE CENTRAL
│
├── SEDE PRIMARIA
│
├── SEDE SECUNDARIA
│
└── SEDE INICIAL
```

El levantamiento se realizará físicamente desde una computadora conectada a la red de cada sede.

Ejemplo:

```text
Laptop
   │
   ├── Sede Central → Escaneo
   │
   ├── Sede Primaria → Escaneo
   │
   ├── Sede Secundaria → Escaneo
   │
   └── Sede Inicial → Escaneo
```

Los resultados se almacenan identificados por sede.

---

# 29. Limitaciones del descubrimiento

Un escaneo desde una PC no garantiza descubrir el 100 % de la infraestructura.

Factores:

- VLAN.
- ACL.
- Firewall.
- Redes aisladas.
- Wi-Fi invitados.
- Equipos que no responden ICMP.
- Equipos sin SNMP.
- Switches no administrables.
- Dispositivos detrás de NAT.
- Redes independientes.
- Equipos apagados.
- Configuración de seguridad.

---

# 30. Diferencia entre descubrir dispositivos y descubrir topología

Encontrar:

```text
192.168.1.1
192.168.1.2
192.168.1.10
192.168.1.20
```

no significa conocer automáticamente:

```text
Router
  │
Switch Core
  │
Switch Piso 2
  │
AP Aula 204
```

El mapa físico requiere información adicional.

Principalmente:

- SNMP.
- LLDP.
- CDP.
- Tabla MAC.
- Información del controlador Wi-Fi.
- Información manual.

---

# 31. Estrategia de implementación

## Fase 1 — Descubrimiento básico

Objetivo:

Identificar todos los dispositivos visibles.

Implementar:

- IP local.
- Máscara.
- Gateway.
- Subnet.
- Ping.
- ARP.
- Nmap Ping Scan.
- IP.
- MAC.
- Hostname.
- Fabricante.
- Estado.

Resultado:

Inventario inicial.

---

## Fase 2 — Clasificación

Implementar clasificación:

- Router.
- Firewall.
- Switch.
- Access Point.
- Servidor.
- PC.
- Impresora.
- Cámara.
- Otros.

Usar:

- Vendor.
- Hostname.
- Puertos.
- Servicios.
- Reglas internas.

---

## Fase 3 — SNMP

Agregar:

- Modelo.
- Serial.
- Uptime.
- Interfaces.
- Estado de puertos.
- Velocidad.
- Tabla MAC.
- VLAN.

---

## Fase 4 — Topología

Agregar:

- LLDP.
- CDP.
- Tabla MAC.
- Relación switch-switch.
- Relación switch-router.
- Relación switch-AP.

Construir:

```text
nodes
edges
```

---

## Fase 5 — Visualización

Implementar Cytoscape.js.

Características:

- Zoom.
- Mover nodos.
- Seleccionar nodos.
- Mostrar detalle.
- Filtrar por tipo.
- Filtrar por sede.
- Diferenciar equipos por icono o estilo.
- Mostrar relaciones.

---

## Fase 6 — Información manual

Agregar posibilidad de:

- Renombrar dispositivos.
- Definir ubicación.
- Definir rack.
- Definir piso.
- Corregir tipo.
- Crear conexión manual.
- Agregar dispositivo no descubierto.
- Agregar observaciones.

---

# 32. Qué no debe hacer el sistema

La primera versión será principalmente de lectura.

No debe:

- Cambiar configuración del router.
- Cambiar VLAN.
- Reiniciar switches.
- Modificar configuraciones.
- Reiniciar AP.
- Cambiar contraseñas.
- Ejecutar comandos destructivos.
- Modificar firewalls.
- Eliminar configuraciones.

El sistema debe utilizarse únicamente en redes donde se cuente con autorización del colegio y del responsable de TI.

---

# 33. Objetivo del análisis posterior

Después de obtener el inventario y el mapa se podrá analizar:

## Arquitectura

- Switches en cascada.
- Topología desordenada.
- Puntos únicos de falla.
- Falta de redundancia.
- Mala distribución de equipos.

## Switching

- Switches antiguos.
- Puertos Fast Ethernet.
- Equipos no administrables.
- Saturación de uplinks.
- Puertos sin uso.
- Mala ubicación de switches.

## VLAN

- Red plana.
- Falta de segmentación.
- VLAN administrativa.
- VLAN estudiantes.
- VLAN docentes.
- VLAN cámaras.
- VLAN servidores.
- VLAN invitados.
- VLAN voz.

## Wi-Fi

- Cantidad de AP.
- Distribución.
- Cobertura.
- AP antiguos.
- Exceso de usuarios por AP.
- Canales.
- SSID.
- VLAN asociadas.
- AP domésticos.

## Seguridad

- Segmentación.
- Firewall.
- Gestión de dispositivos.
- Protocolos inseguros.
- SNMPv1/v2.
- Equipos con firmware antiguo.
- Equipos accesibles desde redes que no deberían.

## Datacenter

- Core switch.
- Firewall.
- Servidores.
- UPS.
- Rack.
- Patch panels.
- Redundancia.
- Organización.

---

# 34. Resultado esperado

Al terminar el levantamiento, cada sede debería tener:

1. Inventario de dispositivos.
2. Rango o rangos de red.
3. Gateway.
4. Routers.
5. Firewalls.
6. Switches.
7. Access Points.
8. Servidores.
9. Impresoras.
10. Cámaras.
11. PCs importantes.
12. VLAN conocidas.
13. Interfaces relevantes.
14. Relaciones entre dispositivos.
15. Topología visual.
16. Observaciones.
17. Información faltante.
18. Recomendaciones posteriores.

---

# 35. Ejemplo de resultado final

```text
COLEGIO
│
├── SEDE CENTRAL
│   │
│   ├── INTERNET
│   │      │
│   │   FIREWALL
│   │      │
│   │   CORE-SW
│   │      │
│   │      ├── SW-ADMIN
│   │      │      ├── AP-ADMIN
│   │      │      ├── PC-01
│   │      │      └── PRINTER-01
│   │      │
│   │      ├── SW-AULAS-01
│   │      │      ├── AP-AULA-101
│   │      │      └── AP-AULA-102
│   │      │
│   │      └── SERVER
│   │
│   └── VLAN
│          ├── VLAN 10 Administración
│          ├── VLAN 20 Docentes
│          ├── VLAN 30 Alumnos
│          ├── VLAN 40 Cámaras
│          └── VLAN 50 Servidores
│
├── SEDE PRIMARIA
│
├── SEDE SECUNDARIA
│
└── SEDE INICIAL
```

---

# 36. MVP recomendado

Para comenzar:

```text
Python
+
Flask
+
SQLite
+
Nmap
+
HTML
+
CSS
+
JavaScript
+
Cytoscape.js
```

Posteriormente:

```text
+ SNMP
+ LLDP
+ CDP
+ APIs de controladores Wi-Fi
```

---

# 37. Primer entregable técnico

La primera versión funcional debería permitir:

### Pantalla Inicio

- Seleccionar sede.
- Ver interfaz de red actual.
- Ver IP.
- Ver gateway.
- Ver subnet.
- Botón Escanear.

### Pantalla Inventario

- Lista de equipos.
- IP.
- MAC.
- Hostname.
- Vendor.
- Tipo.
- Estado.

### Pantalla Mapa

- Nodos.
- Relaciones.
- Zoom.
- Selección.
- Detalle de dispositivo.

### Pantalla Dispositivo

- Información técnica.
- Campos editables.
- Interfaces.
- Conexiones.
- Observaciones.

---

# 38. Criterio principal del proyecto

La prioridad no es desarrollar un sistema complejo.

La prioridad es:

> Obtener una representación suficientemente confiable de la infraestructura actual del colegio para poder entender cómo está organizada y posteriormente proponer mejoras.

El descubrimiento automático debe reducir el trabajo manual, pero el sistema debe permitir complementar y corregir información.

---

# 39. Enfoque recomendado

Primero probar en una sola sede.

```text
SEDE PILOTO
    │
    ▼
Detectar red
    │
    ▼
Descubrir dispositivos
    │
    ▼
Validar inventario
    │
    ▼
Clasificar equipos
    │
    ▼
Agregar SNMP
    │
    ▼
Construir topología
    │
    ▼
Validar físicamente
```

Cuando la metodología funcione correctamente:

```text
Sede Central
Sede Primaria
Sede Secundaria
Sede Inicial
```

---

# 40. Posibles mejoras futuras

Una vez terminado el levantamiento inicial podrían agregarse:

- PostgreSQL.
- Servidor central.
- Escaneo programado.
- Historial.
- Alertas.
- Monitorización.
- Dashboard.
- Métricas de disponibilidad.
- Integración con controladores Wi-Fi.
- Integración con UniFi.
- Integración con Omada.
- Integración con Fortinet.
- Exportación PDF.
- Exportación Excel.
- Comparación entre sedes.
- Detección de cambios.
- Inventario automático periódico.
- Diagramas por VLAN.
- Diagramas por piso.
- Diagramas por rack.
- Monitoreo de disponibilidad.
- Monitoreo de tráfico.
- Recomendaciones automáticas.

---

# 41. Resumen de arquitectura

```text
               USUARIO
                  │
                  ▼
             NAVEGADOR
                  │
                  ▼
          Flask + Python
          Aplicación única
                  │
        ┌─────────┼─────────┐
        │         │         │
        ▼         ▼         ▼
      Nmap       SNMP     LLDP/CDP
        │         │         │
        └─────────┼─────────┘
                  │
                  ▼
              Procesamiento
                  │
                  ▼
                SQLite
                  │
          ┌───────┴───────┐
          │               │
          ▼               ▼
      Inventario        Topología
                            │
                            ▼
                      Cytoscape.js
                            │
                            ▼
                        MAPA WEB
```

---

# 42. Decisión técnica actual

Se utilizará inicialmente:

- Arquitectura monolítica.
- Python.
- Flask.
- SQLite.
- HTML.
- CSS.
- JavaScript.
- Cytoscape.js.
- Nmap.
- SNMP posteriormente.
- LLDP/CDP posteriormente.

No se utilizará inicialmente:

- Angular.
- Spring Boot.
- PostgreSQL.
- Microservicios.
- Agentes por sede.
- Infraestructura cloud.

La aplicación podrá ejecutarse directamente desde una laptop autorizada conectada a la red de la sede que se desea analizar.

---

# 43. Próximo paso sugerido

Implementar el MVP de descubrimiento básico.

Orden recomendado:

```text
1. Crear proyecto Flask.
2. Detectar interfaz activa.
3. Obtener IP/máscara/gateway.
4. Calcular subnet.
5. Integrar Nmap.
6. Detectar hosts.
7. Obtener MAC.
8. Resolver hostname.
9. Obtener fabricante.
10. Guardar dispositivos en SQLite.
11. Mostrar inventario en HTML.
12. Crear página de topología.
13. Integrar Cytoscape.js.
14. Agregar edición manual.
15. Agregar SNMP.
16. Agregar LLDP/CDP.
```

Este será el punto de partida para realizar el levantamiento real de la infraestructura del colegio.
