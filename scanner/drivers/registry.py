"""Driver registry: built-in drivers + Python plugins + native (DLL) plugins."""

import importlib.util
import logging
import os
import time

from scanner.drivers.builtin import builtin_drivers
from scanner.drivers.native import load_native_plugin

log = logging.getLogger("netmap.identity")


class DriverRegistry:
    def __init__(self):
        self.drivers = []
        self.load_errors = []
        self.plugins = []

    # -- registration -------------------------------------------------------
    def register(self, driver, origin="builtin"):
        self.drivers.append(driver)
        self.drivers.sort(key=lambda item: getattr(item, "priority", 100))
        if origin != "builtin":
            self.plugins.append({"name": driver.name, "origin": origin})

    def load_builtin(self, mdns_enabled=True):
        for driver in builtin_drivers(mdns_enabled=mdns_enabled):
            self.register(driver)

    def load_plugins(self, plugin_dir):
        """Load ``plugins/*.py`` (``register(registry)`` or ``DRIVERS``) and plugin folders."""
        if not plugin_dir or not os.path.isdir(plugin_dir):
            return
        for entry in sorted(os.listdir(plugin_dir)):
            path = os.path.join(plugin_dir, entry)
            try:
                if os.path.isfile(path) and entry.endswith(".py") and not entry.startswith("_"):
                    self._load_python(path)
                elif os.path.isdir(path) and os.path.isfile(os.path.join(path, "plugin.json")):
                    self.register(load_native_plugin(path), origin=f"dll:{entry}")
                    log.info("Plugin nativo cargado: %s", entry)
            except Exception as exc:
                message = f"{entry}: {exc}"
                self.load_errors.append(message)
                log.error("No se pudo cargar el plugin %s", message)

    def _load_python(self, path):
        spec = importlib.util.spec_from_file_location(
            f"netmap_plugin_{os.path.splitext(os.path.basename(path))[0]}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        declared = list(getattr(module, "DRIVERS", []))
        if not hasattr(module, "register") and not declared:
            raise ValueError("el archivo no define register(registry) ni DRIVERS")
        known = {id(driver) for driver in self.drivers}
        if hasattr(module, "register"):
            module.register(self)
        for driver in declared:
            if id(driver) not in known and driver not in self.drivers:
                self.register(driver)
        origin = f"py:{os.path.basename(path)}"
        for driver in self.drivers:
            if id(driver) not in known:
                self.plugins.append({"name": driver.name, "origin": origin})
        log.info("Plugin Python cargado: %s", os.path.basename(path))

    def set_debug_dir(self, directory):
        for driver in self.drivers:
            driver.debug_dir = directory

    # -- execution ----------------------------------------------------------
    def begin_scan(self):
        for driver in self.drivers:
            try:
                driver.begin_scan()
            except Exception as exc:
                log.warning("%s.begin_scan falló: %s", driver.name, exc)

    def run(self, facts):
        """Run every matching driver; a failing driver never aborts the scan."""
        results = []
        for driver in self.drivers:
            try:
                if not driver.matches(facts):
                    continue
                started = time.monotonic()
                result = driver.probe(facts)
                log.debug("%s %s -> %s (%.2fs)", driver.name, facts.ip,
                          getattr(result, "device_type", None), time.monotonic() - started)
                if result is not None:
                    results.append((driver, result))
            except Exception as exc:
                log.warning("Driver %s falló en %s: %s: %s", driver.name, facts.ip,
                            exc.__class__.__name__, exc)
        return results

    def describe(self):
        return {"drivers": [{"name": driver.name, "priority": driver.priority}
                            for driver in self.drivers],
                "plugins": self.plugins, "errors": self.load_errors}
