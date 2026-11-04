$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    python -m PyInstaller packaging/NetMapEscolar.spec --noconfirm
    if ($LASTEXITCODE -ne 0) { throw 'Error al empaquetar la aplicación.' }
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if (-not $compiler) { throw 'Agrega ISCC.exe de Inno Setup al PATH.' }
    & $compiler.Source packaging/windows-installer.iss
    if ($LASTEXITCODE -ne 0) { throw 'Error al compilar el instalador.' }
} finally { Pop-Location }
