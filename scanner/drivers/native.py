"""Native (DLL / .so) plugin driver.

Lets a manufacturer SDK or a compiled helper take part in identification without
touching the application. A plugin is a folder under ``plugins/`` with a
``plugin.json`` manifest and the library next to it::

    {
      "name": "hikvision-sdk",
      "dll": "hik_identify.dll",
      "entry": "netmap_identify",
      "calling_convention": "cdecl",          // or "stdcall"
      "match": {"vendors": ["hikvision"], "ports": [8000], "sys_object_id_prefix": [], "ouis": []},
      "weight": 90,
      "timeout_s": 5,
      "thread_safe": false,
      "credentials_env": {"username": "HIK_USER", "password": "HIK_PASS"}
    }

The library must export ``int entry(const char *request_json, char *response_json,
int response_size)`` returning 0 on success. ``request_json`` describes the host
(see ``HostFacts.to_request``); ``response_json`` must be a JSON object with any of
``device_type, vendor, model, serial, firmware, hostname, detail, weight``.
Credentials are passed only from the environment variables named in the manifest,
never stored. The library is loaded only from inside its plugin folder.
"""

import ctypes
import json
import logging
import os
import platform
import threading

from scanner.drivers.base import Driver, DriverResult

log = logging.getLogger("netmap.identity")

RESPONSE_SIZE = 8192


class NativePluginError(Exception):
    pass


class NativePluginDriver(Driver):
    priority = 70

    def __init__(self, folder, manifest):
        self.folder = os.path.realpath(folder)
        self.manifest = manifest
        self.name = f"native:{manifest.get('name') or os.path.basename(self.folder)}"
        self.weight = int(manifest.get("weight", 85))
        self.timeout = float(manifest.get("timeout_s", 5))
        self.match = manifest.get("match") or {}
        self._lock = None if manifest.get("thread_safe") else threading.Lock()
        self._function = self._load()

    def _load(self):
        library_name = self.manifest.get("dll")
        if not library_name:
            raise NativePluginError("plugin.json no define 'dll'")
        path = os.path.realpath(os.path.join(self.folder, library_name))
        if os.path.commonpath([self.folder, path]) != self.folder:
            raise NativePluginError("la biblioteca debe estar dentro de la carpeta del plugin")
        if not os.path.isfile(path):
            raise NativePluginError(f"no existe {library_name}")
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(self.folder)
        try:
            stdcall = self.manifest.get("calling_convention", "cdecl").lower() == "stdcall"
            library = (ctypes.WinDLL if stdcall and platform.system() == "Windows" else ctypes.CDLL)(path)
        except OSError as exc:
            bits = platform.architecture()[0]
            raise NativePluginError(
                f"no se pudo cargar {library_name} ({exc}). Python es de {bits}: la biblioteca "
                "debe tener la misma arquitectura y sus dependencias deben estar en la carpeta.") from exc
        try:
            function = getattr(library, self.manifest.get("entry", "netmap_identify"))
        except AttributeError as exc:
            raise NativePluginError(f"no exporta la función '{self.manifest.get('entry', 'netmap_identify')}'") from exc
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        function.restype = ctypes.c_int
        return function

    def matches(self, facts):
        rules = self.match
        if rules.get("always"):
            return True
        vendor = (facts.vendor or "").lower()
        if any(item.lower() in vendor for item in rules.get("vendors", [])):
            return True
        if set(rules.get("ports", [])) & set(facts.open_ports or []):
            return True
        oid = (facts.snmp.get("sys_object_id") or "").lstrip(".")
        if any(oid.startswith(prefix.lstrip(".")) for prefix in rules.get("sys_object_id_prefix", [])):
            return True
        mac = "".join(char for char in (facts.mac or "").upper() if char.isalnum())
        return any(mac.startswith("".join(c for c in oui.upper() if c.isalnum()))
                   for oui in rules.get("ouis", []))

    def _request(self, facts):
        request = facts.to_request()
        credentials = {key: os.environ.get(variable, "")
                       for key, variable in (self.manifest.get("credentials_env") or {}).items()}
        if credentials:
            request["credentials"] = credentials
        return json.dumps(request).encode("utf-8")

    def _call(self, request):
        buffer = ctypes.create_string_buffer(RESPONSE_SIZE)
        outcome = {}

        def run():
            outcome["code"] = self._function(request, buffer, RESPONSE_SIZE)

        if self._lock:
            self._lock.acquire()
        try:
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            worker.join(self.timeout)
        finally:
            if self._lock:
                self._lock.release()
        if worker.is_alive():
            raise TimeoutError(f"{self.name} excedió {self.timeout:g}s")
        return outcome.get("code"), buffer.value

    def probe(self, facts):
        code, raw = self._call(self._request(facts))
        if code != 0 or not raw:
            return None
        data = json.loads(raw.decode("utf-8", errors="ignore"))
        if not isinstance(data, dict):
            return None
        return DriverResult(
            device_type=data.get("device_type") or None,
            weight=int(data.get("weight", self.weight)) if data.get("device_type") else int(data.get("weight", 0)),
            vendor=str(data.get("vendor", ""))[:80], model=str(data.get("model", ""))[:80],
            serial=str(data.get("serial", ""))[:60], firmware=str(data.get("firmware", ""))[:60],
            hostname=str(data.get("hostname", ""))[:120],
            detail=str(data.get("detail", self.name))[:200])


def load_native_plugin(folder):
    with open(os.path.join(folder, "plugin.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    return NativePluginDriver(folder, manifest)
