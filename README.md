# NetMap Escolar

Inventario y exploración de la red de una sede. Cada instalación usa su propia base SQLite (`network.db`); la interfaz muestra una sola sede. Las bases existentes conservan sus registros al iniciar la versión nueva. Si una base anterior contiene varias sedes, la interfaz muestra la primera y conserva las demás para una futura versión multisede.

## Preparación

Requiere Python 3.10 o posterior. Desde la carpeta del proyecto:

```powershell
python -m pip install -r requirements.txt
python app.py
```

La aplicación abre en `http://localhost:5000`. Si Nmap está instalado, se usa para revisar puertos TCP; en caso contrario se usa el sondeo TCP integrado. Para obtener interfaces, VLAN, tabla MAC y vecinos LLDP/CDP se necesitan equipos administrables y credenciales SNMP con permiso de lectura. El formulario acepta SNMPv3 y SNMPv2c; las credenciales se usan en ese escaneo y no se guardan en SQLite.

`MAX_SCAN_HOSTS` controla el máximo de direcciones por escaneo (predeterminado: 16384) y `SCAN_HOST_WORKERS` la concurrencia de inspección (predeterminado: 12). El rango se valida y su tamaño se muestra antes de iniciar. Los equipos que no respondan dentro del rango escaneado permanecen en inventario como `OFFLINE`; el filtro «Solo conectados» los oculta.

## Cómo leer el mapa

- **Física:** enlaces LLDP/CDP observados y enlaces manuales. Un equipo sin enlace confirmado sigue visible.
- **Lógica:** subred, gateway configurado y equipos asociados; también muestra VLAN observadas por SNMP. Las líneas al gateway representan la salida configurada para la subred, no prueban un cable directo ni la ruta predeterminada de cada equipo.
- **Inventario:** todos los equipos agrupados por tipo, con filtro de estado.

Selecciona un nodo o enlace para ver su detalle y origen. Los vecinos no resueltos aparecen al lado del mapa. La ficha del equipo incluye interfaces, estados, velocidad, VLAN, enlaces y direcciones MAC aprendidas cuando el dispositivo expone esos datos.

En redes grandes, la vista física abre un resumen por switch y por punto de acceso (AP). Haz clic en un grupo para ver hasta 60 equipos por página y usa **Volver al resumen** para navegar a otro switch o AP. Los equipos sin enlace se agrupan por subred y se pueden expandir de la misma forma. Los switches, routers y puntos de acceso permanecen visibles. La búsqueda y los filtros muestran directamente los equipos coincidentes.

Cuando un switch informa una MAC en un puerto único, el mapa puede usarla para asociar visualmente el equipo a ese switch. Cuando un AP informa MAC en una interfaz de radio identificable, el mapa puede agrupar sus clientes bajo ese AP; varias MAC pueden compartir la misma radio. Se usa la observación más reciente de las últimas 24 horas y no se asignan clientes si varios AP informan la misma MAC al mismo tiempo. El inspector indica la interfaz y la evidencia. Estas asociaciones no representan un enlace físico ni confirman la asociación Wi-Fi actual; las líneas LLDP/CDP y los enlaces manuales mantienen su significado propio. Para identificar puntos de acceso se usan nombres y modelos concretos obtenidos por hostname, SNMP o la interfaz web. Una marca compartida con switches y routers no basta por sí sola.

La detección también lee títulos de administración HTTPS en los puertos 443 y 8443, incluso cuando el equipo usa un certificado local. El fabricante HPE, Aruba, Cisco o Ubiquiti por sí solo no determina si el equipo es AP, switch o router. Una MAC privada o aleatoria tampoco demuestra que sea un teléfono; estos casos quedan sin identificar hasta reunir otra señal o registrar el tipo manualmente. Los cambios de clasificación se aplican en el siguiente escaneo; las correcciones manuales se conservan.

Si un AP no publica las MAC de sus radios por SNMP, puedes registrar la relación desde la ficha del cliente con **Wi-Fi / asociación con AP**. El mapa agrupará ese cliente bajo el AP indicado.

Los nodos muestran un icono según el tipo de equipo y la leyenda indica cuáles están presentes en la vista. Los equipos desconectados aparecen en gris al activar su filtro; la forma y el icono siguen indicando el tipo.

El borde azul discontinuo identifica Wi-Fi y el borde verde identifica cable. Para el equipo donde corre la aplicación, el medio proviene del adaptador de red local. En otros equipos, «Cable observado» requiere un enlace LLDP/CDP; si no hay una señal fiable, el mapa indica «No identificado». El inspector explica la evidencia disponible.

El resumen muestra las subredes registradas y los tipos de equipos inventariados. En **Inventario**, el menú **Columnas** permite elegir los datos visibles; la selección se conserva en el navegador. El inventario y el mapa muestran solo equipos conectados al abrirse, con un filtro para incluir los desconectados.

La exportación CSV conserva sus columnas anteriores y añade señales para revisar la detección: puertos TCP, tipo y modelo detectados en el último escaneo antes de una corrección manual, origen de la clasificación, nombres DNS/NetBIOS, TTL, respuesta e identidad SNMP, cantidad de interfaces y vecinos, título y puerto web, advertencia SNMP y resultados de las sondas web en JSON (estado HTTP, servidor, redirección o error). Los equipos registrados antes de esta versión tendrán esas señales vacías hasta su próximo escaneo. No se exportan credenciales SNMP.

El mapa físico representa solo relaciones respaldadas por LLDP/CDP o registradas manualmente. Las tablas MAC ayudan a investigar puertos, pero por sí solas no prueban un cable directo. Algunos equipos y redes aisladas pueden no ser visibles desde la computadora de escaneo.

## Asociaciones cliente–AP desde CSV

En **Mapa de red**, usa **Descargar plantilla** e **Importar asociaciones**. El CSV debe tener una fila por cliente, con `client_mac,ap_ip`. Admite coma o punto y coma como separador y UTF-8. También se aceptan los encabezados `MAC address,Access Point` y `macaddr,associated_device`. La referencia del AP puede ser su IP, nombre o serial, siempre que identifique un solo dispositivo del inventario de la sede. Si el AP aún figuraba como desconocido, una referencia válida lo identifica como punto de acceso sin asignarle un modelo supuesto.

```csv
client_mac,ap_ip
AA:BB:CC:DD:EE:01,192.168.50.55
```

La importación reemplaza la captura anterior de esa sede. Informa cuántas filas se importaron, cuántas no encontraron AP, cuántas son inválidas y cuántas MAC aparecen asociadas a AP distintos. Si ninguna fila es válida, conserva la captura anterior. Un archivo que solo contiene los encabezados borra la captura. El mapa muestra estas asociaciones durante 24 horas desde la importación y da prioridad a esta fuente sobre una MAC aprendida en una interfaz de radio. No crea enlaces físicos. El CSV de inventario exporta el AP asociado, la fuente y la fecha, además de `sysObjectID` y los detalles LLDP disponibles.

En switches y otros equipos que respondan SNMP, la lectura ahora prioriza el modelo y serial del chasis; también recoge la descripción, capacidad, identificador y dirección de administración que anuncien los vecinos LLDP. Una identidad LLDP que coincide de forma única con un equipo existente puede clasificarlo, pero no se crean dispositivos a partir de anuncios no resueltos. El puerto Aruba 4343 no confirma por sí solo si la administración usa Instant o ArubaOS 8.

Referencias: [Aruba Instant REST](https://www.arubanetworks.com/techdocs/Aruba-Instant-8.x-Books/8111/Aruba-Instant-8.11.1.0-REST-API-Guide.pdf), [ArubaOS 8 REST](https://developer.arubanetworks.com/aos8/docs/getting-started-aos8-restapi), [Aruba 2530 LLDP](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Management%20and%20Configuration%20Guide%20for%20ArubaOS-Switch%2016.10.pdf), [SNMP sysObjectID](https://datatracker.ietf.org/doc/html/rfc3418) y [ENTITY-MIB](https://datatracker.ietf.org/doc/rfc4133/).

## Pruebas

```powershell
python -m pytest -q
node --test tests/map_overview.test.js
```
