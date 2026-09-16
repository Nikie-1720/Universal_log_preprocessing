param(
    [string]$OutputDir = "dist\ULPF-Agent-Plugin"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Copy-Item "agent" "$OutputDir\agent" -Recurse -Force
Copy-Item "scripts\install-ulpf-agent-windows.ps1" "$OutputDir\Install-Agent.ps1" -Force
Copy-Item "installer\Install-ULPF-Agent.cmd" "$OutputDir\Install-ULPF-Agent.cmd" -Force
Copy-Item "installer\plugin-manifest.json" "$OutputDir\plugin-manifest.json" -Force
Copy-Item "installer\README.md" "$OutputDir\README.md" -Force

$zip = "dist\ULPF-Agent-Plugin.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$OutputDir\*" -DestinationPath $zip -Force
Write-Host "Plugin bundle created: $zip" -ForegroundColor Green
