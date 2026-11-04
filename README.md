# NetMap Escolar

Inventario y exploración de la red de una sede. Cada instalación usa su propia base SQLite (`network.db`); la interfaz muestra una sola sede. Las bases existentes conservan sus registros al iniciar la versión nueva. Si una base anterior contiene varias sedes, la interfaz muestra la primera y conserva las demás para una futura versión multisede.

## Preparación

Requiere Python 3.10 o posterior. Desde la carpeta del proyecto:

```powershell
python -m pip install -r requirements.txt
python app.py
```

La aplicación abre en `http://localhost:5000`. Si Nmap está instalado, se usa para revisar puertos TCP; en caso contrario se usa el sondeo TCP integrado. Para obtener interfaces, VLAN, tabla MAC y vecinos LLDP/CDP se necesitan equipos administrables y credenciales SNMP con permiso de lectura. El formulario acepta SNMPv3 y SNMPv2c; las credenciales se usan en ese escaneo y no se guardan en SQLite.

El escaneo consulta por SNMP la tabla de vecinos IPv4 del gateway y usa sus MAC cuando faltan en la tabla local. En switches, usa la tabla MAC por VLAN y recurre a BRIDGE-MIB cuando no está disponible. La ficha del equipo muestra el origen de la MAC y los servicios identificados por Nmap en equipos sin clasificar. En Windows, **Diagnóstico de red → Ver ruta IP** ejecuta un seguimiento desde el servidor.

Si la sede usa Windows DHCP, configura la variable de entorno `SCAN_DHCP_SERVER` con el nombre o IP del servidor antes de iniciar la aplicación. La cuenta que ejecuta la aplicación necesita acceso de lectura al servidor DHCP y el módulo PowerShell `DhcpServer`. Las concesiones enriquecen los equipos encontrados en el escaneo.


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

El mapa físico distingue los enlaces LLDP/CDP o manuales de las relaciones por canal entre un grabador y sus cámaras. Las tablas MAC ayudan a investigar puertos, pero por sí solas no prueban un cable directo. Algunos equipos y redes aisladas pueden no ser visibles desde la computadora de escaneo.

## Asociaciones cliente–AP desde CSV

En **Mapa de red**, usa **Descargar plantilla** e **Importar asociaciones**. El CSV debe tener una fila por cliente, con `client_mac,ap_ip`. Admite coma o punto y coma como separador y UTF-8. También se aceptan los encabezados `MAC address,Access Point` y `macaddr,associated_device`. La referencia del AP puede ser su IP, nombre o serial, siempre que identifique un solo dispositivo del inventario de la sede. Si el AP aún figuraba como desconocido, una referencia válida lo identifica como punto de acceso sin asignarle un modelo supuesto.

```csv
client_mac,ap_ip
AA:BB:CC:DD:EE:01,192.168.50.55
```

La importación reemplaza la captura anterior de esa sede. Informa cuántas filas se importaron, cuántas no encontraron AP, cuántas son inválidas y cuántas MAC aparecen asociadas a AP distintos. Si ninguna fila es válida, conserva la captura anterior. Un archivo que solo contiene los encabezados borra la captura. El mapa muestra estas asociaciones durante 24 horas desde la importación y da prioridad a esta fuente sobre una MAC aprendida en una interfaz de radio. No crea enlaces físicos. El CSV de inventario exporta el AP asociado, la fuente y la fecha, además de `sysObjectID` y los detalles LLDP disponibles.

En switches y otros equipos que respondan SNMP, la lectura ahora prioriza el modelo y serial del chasis; también recoge la descripción, capacidad, identificador y dirección de administración que anuncien los vecinos LLDP. Una identidad LLDP que coincide de forma única con un equipo existente puede clasificarlo, pero no se crean dispositivos a partir de anuncios no resueltos. El puerto Aruba 4343 no confirma por sí solo si la administración usa Instant o ArubaOS 8.

Referencias: [Aruba Instant REST](https://www.arubanetworks.com/techdocs/Aruba-Instant-8.x-Books/8111/Aruba-Instant-8.11.1.0-REST-API-Guide.pdf), [ArubaOS 8 REST](https://developer.arubanetworks.com/aos8/docs/getting-started-aos8-restapi), [Aruba 2530 LLDP](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/Aruba%202530%20Management%20and%20Configuration%20Guide%20for%20ArubaOS-Switch%2016.10.pdf), [SNMP sysObjectID](https://datatracker.ietf.org/doc/html/rfc3418) y [ENTITY-MIB](https://datatracker.ietf.org/doc/rfc4133/).

## Identificación de equipos: drivers, plugins y retroalimentación

Cada equipo se identifica combinando **evidencias con peso** (fingerprint, `sysObjectID`,
nombre de host, categoría del fabricante, respuestas de protocolos y tus correcciones).
Gana el tipo con mayor puntaje; el resultado guarda confianza (alta/media/baja) y las
fuentes, y se ve en el inspector del mapa. Por debajo del umbral el equipo queda
`UNKNOWN` y se reporta, nunca se adivina.

| Fuente | Qué aporta | Requiere |
|---|---|---|
| `sysobjectid` | Fabricante y línea de producto | SNMP |
| `printer-mib` | Modelo, serie y contadores de impresoras | SNMP |
| `aruba-instant-snmp` | APs del cluster y tabla de clientes (nombre y SO) | SNMP en el Virtual Controller |
| `hikvision-sadp`, `ubiquiti-discovery`, `mikrotik-mndp`, `upnp` | Modelo, serie y firmware sin credenciales | Estar en el mismo segmento (broadcast/multicast) |
| `mdns` | Nombre de iPhone, Mac, Chromecast | Respuesta unicast del equipo |

Las tablas de columnas de Aruba son una suposición validada en ejecución: cada
volcado crudo queda en `driver_debug/aruba_<ip>.json` para corregirlas con tu firmware.

### Equipos sin identificar

Cada escaneo escribe `unidentified_devices.csv` (junto a la base de datos, o en
`IDENTITY_DATA_DIR`). También puedes descargarlo desde **Mapa de red → Descargar reporte**.
Completa `manual_type` (ej. `Impresora`, `Cámara`, `AP`, o el código `PRINTER`) y,
opcionalmente, `manual_vendor`, `manual_model` y `apply_to_oui` (`si` aplica la regla a
todo el fabricante). Súbelo en la misma pantalla o déjalo en la carpeta: se guarda en
`identity_overrides.csv` con máxima prioridad y se aplica a los próximos escaneos.
Los equipos marcados manualmente en la ficha no se modifican.

`identity_overrides.csv` también se puede editar a mano. Tipos de coincidencia:
`mac`, `oui`, `ip`, `hostname_prefix`, `sysobjectid_prefix`.

### Mantenimiento del inventario

En **Mapa de red**:

- **Reclasificar sin escanear** vuelve a aplicar las reglas actuales (fabricante, nombre,
  Telnet, tus overrides) a los equipos `UNKNOWN` ya guardados, sin tocar la red. Los
  equipos marcados manualmente no se modifican.
- **Depurar** elimina los equipos desconectados con MAC aleatoria que no se ven hace N
  días (pide confirmación y muestra cuántos son antes de borrar). Los manuales y los
  de MAC real se conservan. Un teléfono que reaparece se vuelve a registrar en el
  siguiente escaneo.

Los fabricantes que la base de OUI no conoce se completan en `scanner/vendor.py`.

### Plugins

Coloca en `plugins/` (variable `PLUGIN_DIR`):

- **Python** (`mi_driver.py`): define `DRIVERS = [MiDriver()]` o `register(registry)`;
  hereda de `scanner.drivers.base.Driver` (`matches` sin I/O, `probe` con I/O).
- **DLL / .so**: carpeta con `plugin.json` y la biblioteca; exporta
  `int netmap_identify(const char *request_json, char *response_json, int size)`.
  El formato completo está en `scanner/drivers/native.py`. Las credenciales se leen
  solo de variables de entorno. Una DLL ejecuta código nativo con tus permisos:
  instala solo plugins de confianza y con la misma arquitectura (32/64 bits) que Python.

Un plugin que falla se registra en el log y no interrumpe el escaneo.

### Variables

`IDENTITY_ENABLED`, `IDENTITY_DATA_DIR`, `PLUGIN_DIR`, `IDENTITY_BROADCAST`
(barridos SSDP/SADP/Ubiquiti/MNDP), `IDENTITY_MDNS`, `IDENTITY_SWEEP_SECONDS`.
Los barridos de difusión solo alcanzan el segmento donde corre la aplicación.

## Pruebas

```powershell
python -m pytest -q
node --test tests/map_overview.test.js
```


### Switches administrables

En **Switches**, registra la IP de administración y un perfil SNMP de lectura (v2c o v3). El perfil completo se cifra con la misma clave local del NVR, `nvr_secret.key`, junto a la base SQLite. Conserva esa clave al mover o respaldar la base. Los secretos se introducen de nuevo para reemplazar un perfil y no se muestran en pantalla ni en diagnósticos.

**Probar tablas SNMP** consulta interfaces, VLAN, tabla MAC y vecinos LLDP/CDP. Un resultado vacío puede indicar falta de datos, soporte o permisos. La IP registrada se consulta automáticamente en cada escaneo de la sede, aunque esté fuera del rango o no responda a ping. El PC debe tener acceso a su red de administración. Registrar una IP existente corrige su tipo a SWITCH y conserva la corrección manual.


## Generar el instalador de Windows

La distribución de Windows incluye Python, las dependencias y los archivos de la interfaz. Cada instalación comienza con una base nueva y conserva sus datos en `%LOCALAPPDATA%\NetMapEscolar`. La ventana de escritorio abre el navegador y permite cerrar el servidor local. Nmap sigue siendo opcional.

### Requisitos de la computadora que compila

- Windows 10 u 11 de 64 bits.
- Git y Python 3.13 de 64 bits, que es la versión usada para validar este paquete.
- [Inno Setup 7](https://jrsoftware.org/isdl.php), con su compilador `ISCC.exe`.
- Acceso a Internet para descargar las dependencias durante la preparación.

Las computadoras de las sedes solo necesitan ejecutar el instalador.

### Clonar y preparar el entorno

Abre PowerShell y ejecuta estos comandos desde la carpeta donde quieras clonar el proyecto.

```powershell
git clone https://github.com/Azgaf012/mapeo-redes.git
cd mapeo-redes

py -3.13 -m venv .venv-build
.\.venv-build\Scripts\python.exe -m pip install --upgrade pip
.\.venv-build\Scripts\python.exe -m pip install -r packaging/requirements-build.txt
```

Agrega el entorno de compilación y el compilador de Inno Setup al PATH de esta sesión. Ajusta `$innoDir` a la carpeta donde instalaste Inno Setup.

```powershell
$innoDir = 'C:\Program Files\Inno Setup 7'
$buildPythonDir = Join-Path (Get-Location) '.venv-build\Scripts'
$env:Path = "$buildPythonDir;$innoDir;$env:Path"

python --version
Get-Command ISCC.exe
```

Ambas comprobaciones deben funcionar antes de compilar.

### Compilar

Desde la raíz del proyecto, ejecuta el script.

```powershell
.\packaging\build-windows.ps1
```

El script usa PyInstaller para empaquetar la aplicación y después ejecuta Inno Setup para crear el instalador. Si PowerShell bloquea archivos `.ps1`, puedes ejecutar esas dos operaciones directamente.

```powershell
.\.venv-build\Scripts\python.exe -m PyInstaller packaging/NetMapEscolar.spec --noconfirm
if ($LASTEXITCODE -ne 0) { throw 'Falló PyInstaller.' }

& "$innoDir\ISCC.exe" packaging/windows-installer.iss
if ($LASTEXITCODE -ne 0) { throw 'Falló Inno Setup.' }
```

El resultado de la versión actual queda en estos archivos y carpetas.

- `dist/NetMapEscolar-Instalador-1.0.0-Windows-x64.exe` es el archivo único que se entrega a las sedes.
- `dist/NetMapEscolar/` contiene la aplicación empaquetada. Para ejecutarla directamente, conserva toda la carpeta junto a `NetMapEscolar.exe`.
- `build/` contiene archivos intermedios. Tanto `build/` como `dist/` están excluidos de Git.

### Validar antes de distribuir

Comprueba el ejecutable empaquetado con una carpeta de datos de prueba independiente.

```powershell
$testDataDir = Join-Path (Get-Location) '.tools\prueba-instalador'
$packagedExe = Join-Path (Get-Location) 'dist\NetMapEscolar\NetMapEscolar.exe'

$testProcess = Start-Process -FilePath $packagedExe -ArgumentList @(
    '--smoke-test',
    '--data-dir',
    ('"' + $testDataDir + '"')
) -WindowStyle Hidden -PassThru -Wait

if ($testProcess.ExitCode -ne 0) {
    throw "Falló la validación. Revisa $testDataDir\aplicacion.log"
}
Get-Content (Join-Path $testDataDir 'smoke-test.json')
```

La prueba comprueba las pantallas principales, los recursos de la interfaz, la generación de un archivo Packet Tracer y el cifrado de un perfil SNMP de prueba. Después instala el `.exe` en una computadora de prueba, abre el acceso directo y comprueba el escaneo en su red.

### Generar una actualización

1. Actualiza el código y vuelve a instalar `packaging/requirements-build.txt` si cambiaron las dependencias.
2. Cambia `AppVersion` en `packaging/windows-installer.iss`. El nombre del instalador usa esa versión.
3. Conserva el mismo `AppId` para que Inno Setup reconozca la instalación existente.
4. Compila y valida nuevamente antes de entregar el archivo.

Los datos y las claves se guardan fuera de la carpeta del programa. La actualización y la desinstalación conservan la carpeta de datos del usuario. Las instrucciones de uso y respaldo para las sedes se incluyen en [packaging/LEEME.txt](packaging/LEEME.txt).

Se empaquetan las plantillas, los recursos estáticos y el esquema SQLite. Los inventarios y las claves locales quedan fuera de la distribución. Los archivos de compilación y los recursos de `static/vendor/` deben estar incluidos en el repositorio para poder generar el instalador desde una clonación nueva. El instalador generado actualmente carece de firma digital.
