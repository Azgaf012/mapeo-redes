"""Desktop entry point used by the Windows installer."""
import argparse
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import secrets
import sys
import threading
import webbrowser


def configure_runtime(data_dir):
    data_dir.mkdir(parents=True, exist_ok=True)
    secret_file = data_dir / "session_secret.key"
    try:
        with secret_file.open("x", encoding="ascii") as handle:
            handle.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    os.environ["DATABASE_PATH"] = str(data_dir / "network.db")
    os.environ["IDENTITY_DATA_DIR"] = str(data_dir)
    os.environ["PLUGIN_DIR"] = str(data_dir / "plugins")
    os.environ["SECRET_KEY"] = secret_file.read_text(encoding="ascii").strip()
    os.environ["FLASK_DEBUG"] = "false"
    handler = RotatingFileHandler(data_dir / "aplicacion.log", maxBytes=2_000_000,
                                  backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)


def smoke_test(data_dir):
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    results = {}
    with app.test_client() as client:
        for route in ("/", "/topology", "/devices", "/nvr", "/switches", "/api/topology/data",
                      "/static/vendor/bootstrap/bootstrap.min.css",
                      "/static/vendor/cytoscape/cytoscape.min.js"):
            response = client.get(route)
            if response.status_code != 200:
                raise RuntimeError(f"{route}: HTTP {response.status_code}")
            results[route] = response.status_code
        # Exercise bundled package assets and encryption without touching a real network.
        from services.packet_tracer_export import build_packet_tracer
        pkt = build_packet_tracer([
            {"group": "nodes", "data": {"kind": "device", "id": "1",
             "device_type": "SWITCH", "ip": "192.0.2.1"}},
        ])
        results["pkt_bytes"] = len(pkt)
        from repositories.switch_credential_repository import SwitchCredentialRepository
        store = SwitchCredentialRepository(str(data_dir / "network.db"))
        store.save(1, "192.0.2.1", {"version": "2c", "community": "smoke-test-only"})
        assert store.list_by_site(1, True)[0]["credentials"]["community"] == "smoke-test-only"
        store.remove(1, "192.0.2.1")
    (data_dir / "smoke-test.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path,
                        default=Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "NetMapEscolar")
    parser.add_argument("--smoke-test", action="store_true")
    args = parser.parse_args()
    data_dir = args.data_dir.resolve()

    import tkinter as tk
    from tkinter import messagebox
    root = None
    mutex = None
    server = None
    try:
        if not args.smoke_test:
            import ctypes
            mutex_name = "Local\\NetMapEscolar-" + hashlib.sha256(str(data_dir).encode()).hexdigest()[:20]
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateMutexW.restype = ctypes.c_void_p
            kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            mutex = kernel.CreateMutexW(None, False, mutex_name)
            if not mutex:
                raise OSError("No se pudo iniciar la aplicación.")
            already_running = ctypes.get_last_error() == 183
            root = tk.Tk()
            root.withdraw()
            if already_running:
                messagebox.showinfo("NetMap Escolar", "NetMap Escolar ya está abierto. Busca su ventana en la barra de tareas.")
                return
        configure_runtime(data_dir)
        if args.smoke_test:
            smoke_test(data_dir)
            return
        from app import create_app
        from waitress import create_server
        server = create_server(create_app(), host="127.0.0.1", port=0, threads=8)
        url = f"http://127.0.0.1:{server.effective_port}"
        threading.Thread(target=server.run, daemon=True, name="NetMap-web").start()

        root.title("NetMap Escolar")
        root.geometry("440x245")
        root.resizable(False, False)
        tk.Label(root, text="NetMap Escolar", font=("Segoe UI", 18, "bold")).pack(pady=(20, 8))
        tk.Label(root, text="La aplicación está lista. Mantén esta ventana abierta.",
                 font=("Segoe UI", 10)).pack()
        tk.Label(root, text=url, font=("Segoe UI", 10)).pack(pady=8)
        tk.Button(root, text="Abrir aplicación", width=26, command=lambda: webbrowser.open(url)).pack(pady=3)
        tk.Button(root, text="Abrir carpeta de datos", width=26,
                  command=lambda: os.startfile(str(data_dir))).pack(pady=3)
        tk.Button(root, text="Cerrar NetMap", width=26, command=root.destroy).pack(pady=3)
        root.deiconify()
        webbrowser.open(url)
        root.mainloop()
    except Exception:
        logging.exception("Error al iniciar NetMap Escolar")
        if args.smoke_test:
            raise
        messagebox.showerror("NetMap Escolar", f"No se pudo iniciar. Revisa aplicacion.log en\n{data_dir}")
    finally:
        if server is not None:
            server.close()
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass
        if mutex:
            kernel.CloseHandle(mutex)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
