param(
    [string]$OutputDir = "dist\ULPF-Agent-Plugin"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "        ULPF AGENT PLUGIN PACKAGER" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------
# CLEAN OUTPUT
# ---------------------------------------------------------

if (Test-Path $OutputDir) {
    Remove-Item $OutputDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ---------------------------------------------------------
# VALIDATE REQUIRED FILES
# ---------------------------------------------------------

$requiredFiles = @(
    "agent\agent.py",
    "agent\windows_service.py",
    "agent\agent.yaml",
    "agent\discovery.py",
    "scripts\install-ulpf-agent-windows.ps1",
    "installer\Install-ULPF-Agent.cmd",
    "installer\plugin-manifest.json",
    "installer\README.md"
)

foreach ($file in $requiredFiles) {

    if (-not (Test-Path $file)) {
        throw "Required file not found: $file"
    }
}

Write-Host "[ULPF] Required files validated." -ForegroundColor Green

# ---------------------------------------------------------
# COPY AGENT
# ---------------------------------------------------------

Write-Host "[ULPF] Copying agent..." -ForegroundColor Yellow

Copy-Item `
    "agent" `
    "$OutputDir\agent" `
    -Recurse `
    -Force

# ---------------------------------------------------------
# COPY WINDOWS INSTALLER
# ---------------------------------------------------------

Write-Host "[ULPF] Copying Windows installer..." -ForegroundColor Yellow

Copy-Item `
    "scripts\install-ulpf-agent-windows.ps1" `
    "$OutputDir\Install-Agent.ps1" `
    -Force

# ---------------------------------------------------------
# COPY CMD LAUNCHER
# ---------------------------------------------------------

Write-Host "[ULPF] Copying installer launcher..." -ForegroundColor Yellow

Copy-Item `
    "installer\Install-ULPF-Agent.cmd" `
    "$OutputDir\Install-ULPF-Agent.cmd" `
    -Force

# ---------------------------------------------------------
# COPY MANIFEST
# ---------------------------------------------------------

Copy-Item `
    "installer\plugin-manifest.json" `
    "$OutputDir\plugin-manifest.json" `
    -Force

# ---------------------------------------------------------
# COPY README
# ---------------------------------------------------------

Copy-Item `
    "installer\README.md" `
    "$OutputDir\README.md" `
    -Force

# ---------------------------------------------------------
# VERIFY PACKAGED SERVICE HOST
# ---------------------------------------------------------

$packagedServiceHost = Join-Path $OutputDir "agent\windows_service.py"

if (-not (Test-Path $packagedServiceHost)) {
    throw "Packaged Windows service host missing: $packagedServiceHost"
}

Write-Host "[ULPF] Windows service host included." -ForegroundColor Green

# ---------------------------------------------------------
# CREATE ZIP
# ---------------------------------------------------------

$zip = "dist\ULPF-Agent-Plugin.zip"

if (Test-Path $zip) {
    Remove-Item $zip -Force
}

Write-Host "[ULPF] Creating plugin ZIP..." -ForegroundColor Yellow

Compress-Archive `
    -Path "$OutputDir\*" `
    -DestinationPath $zip `
    -Force

# ---------------------------------------------------------
# FINAL VALIDATION
# ---------------------------------------------------------

if (-not (Test-Path $zip)) {
    throw "Plugin ZIP was not created: $zip"
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "       PLUGIN PACKAGE CREATED SUCCESSFULLY" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""
Write-Host "ZIP: $zip" -ForegroundColor Green
Write-Host ""