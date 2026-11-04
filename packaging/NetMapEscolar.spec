# Build with: python -m PyInstaller packaging/NetMapEscolar.spec --noconfirm
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

root = Path(SPECPATH).parent
datas = [(str(root / "templates"), "templates"),
         (str(root / "static"), "static"),
         (str(root / "database" / "schema.sql"), "database")]
binaries = []
hiddenimports = collect_submodules("scanner.drivers")
for package in ("pkt_core", "pysnmp"):
    package_datas, package_binaries, package_imports = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_imports
a = Analysis([str(root / "desktop_launcher.py")], pathex=[str(root)],
             binaries=binaries, datas=datas, hiddenimports=hiddenimports,
             excludes=["pytest", "IPython", "matplotlib", "numpy", "pandas", "PyQt5", "PyQt6"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="NetMapEscolar",
          console=False, uac_admin=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="NetMapEscolar")
